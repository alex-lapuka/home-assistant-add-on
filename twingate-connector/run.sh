#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
# ==============================================================================
# Twingate Connector add-on
#
# Checks the add-on options, installs the Twingate Connector from Twingate's
# apt repository and starts it. The Connector takes its settings from
# environment variables. The tokens are never logged and are not written to
# the status file that the Web UI reads.
#
# Runs as the s6 service twingate-connector, which passes the pipe to s6-log
# (the twingate-connector-log service) on file descriptor 3. s6-log copies
# the Connector's output unchanged to the add-on log and keeps a copy for the
# Web UI's log relay.
# ==============================================================================
set -o errexit -o nounset -o pipefail

readonly CONFIG="/etc/twingate/connector.conf"
CONFIG_DIR=$(dirname "${CONFIG}")
readonly CONFIG_DIR
readonly CONNECTOR_BIN="/usr/bin/twingate-connector"
# Prometheus metrics. The Connector listens on all addresses of the add-on
# container; the port is not published on the host (see config.yml).
readonly METRICS_PORT=9999
readonly API_ENDPOINT="/var/run/twingate/connector.sock"
readonly STATUS_DIR="/run/twingate-connector"
readonly STATUS_FILE="${STATUS_DIR}/status.json"

# Packages installed only for the setup, removed before the Connector starts.
TEMPORARY_PACKAGES=()
LOG_LEVEL_NAME=""
CONNECTION_LOGS=false
LOG_RELAY=false

apt_require() {
    local command=$1
    local package=$2

    if ! command -v "${command}" >/dev/null; then
        apt install -yq "${package}"
        TEMPORARY_PACKAGES+=("${package}")
    fi
}

exit_no_changes () {
    echo "Canceling setup and exiting. No changes have been made."
    exit 1
}

# Prints an option, or nothing when it is not set.
read_option() {
    local value
    value=$(bashio::config "$1")
    if [[ "${value}" == "null" ]]; then
        value=""
    fi
    printf '%s' "${value}"
}

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

read_options() {
    local log_level

    TWINGATE_ACCESS_TOKEN=$(read_option 'access_token')
    if [[ -z "${TWINGATE_ACCESS_TOKEN}" ]]; then
        echo "access_token is not set. Please set it in the configuration."
        exit_no_changes
    fi

    TWINGATE_REFRESH_TOKEN=$(read_option 'refresh_token')
    if [[ -z "${TWINGATE_REFRESH_TOKEN}" ]]; then
        echo "refresh_token is not set. Please set it in the configuration."
        exit_no_changes
    fi

    TWINGATE_NETWORK=$(read_option 'network')
    if [[ -z "${TWINGATE_NETWORK}" ]]; then
        echo "network is not set. Please set it in the configuration."
        exit_no_changes
    fi

    # Twingate's levels: 3 errors (the Connector's default), 4 warnings,
    # 5 information, 7 debug.
    log_level=$(read_option 'connector_log_level')
    if [[ -z "${log_level}" ]]; then
        echo "connector_log_level is not set. Using default log level (info)"
        log_level=info
    fi
    case "${log_level}" in
        error) TWINGATE_LOG_LEVEL=3 ;;
        warn) TWINGATE_LOG_LEVEL=4 ;;
        debug) TWINGATE_LOG_LEVEL=7 ;;
        *)
            log_level=info
            TWINGATE_LOG_LEVEL=5
            ;;
    esac
    LOG_LEVEL_NAME="${log_level}"

    # Connection logs name the user and their location, so they are opt-in.
    if bashio::config.true 'connection_logs'; then
        CONNECTION_LOGS=true
    fi
}

# ------------------------------------------------------------------------------
# Installation
# ------------------------------------------------------------------------------

install_connector() {
    local keyring=/usr/share/keyrings/twingate-client-keyring.gpg

    apt update -yq
    apt_require curl curl
    apt_require gpg gpg

    if ! curl -fsSL "https://packages.twingate.com/apt/gpg.key" | gpg --dearmor -o "${keyring}"; then
        echo "Failed to download or process GPG key"
        exit 1
    fi
    echo "deb [signed-by=${keyring}] https://packages.twingate.com/apt/ /" | tee /etc/apt/sources.list.d/twingate.list
    apt update -yq
    apt install -yq twingate-connector

    if ((${#TEMPORARY_PACKAGES[@]} > 0)); then
        apt purge -yq "${TEMPORARY_PACKAGES[@]}" ||
            bashio::log.warning "Could not remove ${TEMPORARY_PACKAGES[*]}; the Connector starts anyway."
    fi
}

# ------------------------------------------------------------------------------
# Status for the Web UI
# ------------------------------------------------------------------------------

# Prints the first line of "twingate-connector --version", or "unknown" when
# the Connector fails, prints nothing or takes longer than 10 seconds. It
# runs with an empty environment, without the tokens.
read_connector_version() {
    local output=""
    local version

    output=$(env -i PATH=/usr/sbin:/usr/bin:/sbin:/bin LANG=C.UTF-8 \
        timeout --kill-after=2 10 "${CONNECTOR_BIN}" --version 2>/dev/null) || output=""
    version=${output%%$'\n'*}
    printf '%s' "${version:-unknown}"
}

# Writes the status file that the Web UI shows: the options without the
# tokens, the Connector version and the process ID that the Connector keeps
# after exec. The file is world-readable because the Web UI runs as an
# unprivileged user. The Web UI is not essential, so this function returns 1
# on any failure instead of stopping the add-on.
write_status() {
    local tmp
    local addon_version
    local connector_version
    local started_at

    started_at=$(date +%s) || return 1
    connector_version=$(read_connector_version)
    # From the add-on's own Supervisor API entry, which needs no extra
    # permission. If the request fails, the Web UI shows it as unknown.
    addon_version=$(bashio::addon.version 2>/dev/null) || addon_version=""

    install -d -m 0755 "${STATUS_DIR}" || return 1
    tmp=$(mktemp "${STATUS_DIR}/.status.XXXXXX") || return 1

    if ! jq --null-input --ascii-output \
        --arg addon_version "${addon_version}" \
        --arg connector_version "${connector_version}" \
        --argjson started_at "${started_at}" \
        --argjson pid "$$" \
        --arg network "${TWINGATE_NETWORK}" \
        --arg log_level "${LOG_LEVEL_NAME}" \
        --arg hostname_label "${TWINGATE_LABEL_HOSTNAME}" \
        --arg deployed_by_label "${TWINGATE_LABEL_DEPLOYED_BY}" \
        --argjson connection_logs "${CONNECTION_LOGS}" \
        --argjson metrics_port "${METRICS_PORT}" \
        --argjson log_relay "${LOG_RELAY}" \
        '{
            schema: 1,
            addon_version: $addon_version,
            connector_version: $connector_version,
            started_at: $started_at,
            pid: $pid,
            network: $network,
            log_level: $log_level,
            hostname_label: $hostname_label,
            deployed_by_label: $deployed_by_label,
            connection_logs: $connection_logs,
            metrics_port: $metrics_port,
            log_relay: $log_relay
          }' >"${tmp}" ||
        ! chmod 0644 "${tmp}" ||
        ! mv -f "${tmp}" "${STATUS_FILE}"; then
        rm -f "${tmp}"
        return 1
    fi
}

# ------------------------------------------------------------------------------
# Main
# ------------------------------------------------------------------------------

# The Web UI shows the Connector as starting until write_status runs.
rm -f "${STATUS_FILE}"

if [[ -f "${CONFIG}" ]]; then
    echo "Config file \"${CONFIG}\" already exists"
    exit_no_changes
fi

read_options
install -d -m 0700 "${CONFIG_DIR}"
install_connector

TWINGATE_LABEL_HOSTNAME=$(hostname)
TWINGATE_LABEL_DEPLOYED_BY="home_assistant"
export TWINGATE_ACCESS_TOKEN TWINGATE_REFRESH_TOKEN TWINGATE_NETWORK TWINGATE_LOG_LEVEL
export TWINGATE_LABEL_HOSTNAME TWINGATE_LABEL_DEPLOYED_BY
export TWINGATE_METRICS_PORT="${METRICS_PORT}"
export TWINGATE_API_ENDPOINT="${API_ENDPOINT}"
if [[ "${CONNECTION_LOGS}" == true ]]; then
    export TWINGATE_LOG_ANALYTICS=v3
else
    unset TWINGATE_LOG_ANALYTICS
fi

{
  echo "TWINGATE_NETWORK=${TWINGATE_NETWORK}"
  echo "TWINGATE_ACCESS_TOKEN=${TWINGATE_ACCESS_TOKEN}"
  echo "TWINGATE_REFRESH_TOKEN=${TWINGATE_REFRESH_TOKEN}"
  echo "TWINGATE_LOG_LEVEL=${TWINGATE_LOG_LEVEL}"
  echo "TWINGATE_LABEL_HOSTNAME=${TWINGATE_LABEL_HOSTNAME}"
  echo "TWINGATE_LABEL_DEPLOYED_BY=${TWINGATE_LABEL_DEPLOYED_BY}"
} > "${CONFIG}"
chmod 0600 "${CONFIG}"

# The Connector's local API socket (used by twingate-connectorctl health).
install -d -m 0755 "$(dirname "${API_ENDPOINT}")"

# s6-log (file descriptor 3) copies the Connector's output to the add-on log
# and keeps a copy from which the log relay gives the Web UI its state,
# warnings and connections. Without it (file descriptor 3 is not open), the
# Connector writes to the add-on log directly as before.
if { true >&3; } 2>/dev/null; then
    LOG_RELAY=true
fi

# write_status reports every failure through its return value.
# shellcheck disable=SC2310
if ! write_status; then
    bashio::log.warning "Could not write the status for the Web UI. The Connector starts anyway; the Web UI shows it as starting."
fi

bashio::log.info "Starting the Twingate Connector for network ${TWINGATE_NETWORK} with log level ${LOG_LEVEL_NAME} (${TWINGATE_LOG_LEVEL})."
bashio::log.info "Metrics: port ${METRICS_PORT} inside the add-on container, not published on the host."
if [[ "${CONNECTION_LOGS}" == true ]]; then
    bashio::log.info "Connection logs are on: the Connector logs every connection with the user's email address and location."
fi

# The Connector does not need access to the Supervisor API.
unset SUPERVISOR_TOKEN HASSIO_TOKEN

# The Connector keeps its crash reports in .sentry-native under its working
# directory: / as before, not the s6 service folder.
cd /

if [[ "${LOG_RELAY}" == true ]]; then
    exec "${CONNECTOR_BIN}" >&3 2>&3 3>&-
fi
exec "${CONNECTOR_BIN}"
