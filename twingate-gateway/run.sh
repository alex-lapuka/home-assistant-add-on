#!/usr/bin/with-contenv bashio
# shellcheck shell=bash
# ==============================================================================
# Twingate Gateway add-on
#
# Validates the add-on options, prepares the CA that the Gateway signs its
# on-demand TLS certificates with, renders the Gateway configuration and starts
# the Gateway. Request header values can hold secrets: they are never logged,
# and the status file for the Web UI holds header names only.
#
# Runs as the s6 service twingate-gateway, which passes the pipe to s6-log
# (the twingate-gateway-log service) on file descriptor 3.
# ==============================================================================
set -o errexit -o nounset -o pipefail
umask 077

readonly GATEWAY_BIN="/usr/local/bin/twingate-gateway"
# Written when the image is built (see the Dockerfile); empty if the version
# could not be found out then.
readonly GATEWAY_VERSION_FILE="/usr/share/twingate-gateway/version"
readonly GATEWAY_PORT=8443
readonly CONFIG_DIR="/etc/twingate-gateway"
readonly CONFIG_FILE="${CONFIG_DIR}/config.yaml"
readonly SSL_DIR="/ssl"
readonly CA_DIR="/data/ca"
readonly ADDON_CA_CERT="${CA_DIR}/ca.crt"
readonly ADDON_CA_KEY="${CA_DIR}/ca.key"
readonly CA_VALIDITY_DAYS=3650
readonly CA_EXPIRY_WARNING_DAYS=30
readonly STATIC_CERT_DIR="/data/tls"
readonly STATIC_CERT="${STATIC_CERT_DIR}/tls.crt"
readonly STATIC_KEY="${STATIC_CERT_DIR}/tls.key"
readonly STATIC_CERT_STATE="${STATIC_CERT_DIR}/issued-for"
readonly STATIC_CERT_VALIDITY_DAYS=825
readonly STATIC_CERT_RENEW_DAYS=30
readonly AUDIT_LOG_FILE="/config/audit.log"
readonly STATUS_DIR="/run/twingate-gateway"
readonly STATUS_FILE="${STATUS_DIR}/status.json"
readonly RELAY_SERVICE="/run/service/twingate-gateway-relay"

# Set by the functions below.
GATEWAY_VERSION=""
NETWORK=""
NETWORK_CHECK="unreachable"
NETWORK_CHECK_STATUS=""
GATEWAY_LOG_LEVEL=""
HEADERS_JSON="{}"
STATIC_IPS=""
AUDIT_LOG="addon_log"
AUDIT_PIPE=false
CA_CERT=""
CA_KEY=""
CA_SOURCE="addon"
RESOLVED_PATH=""

# jq program that prints one line per invalid 'request_headers' entry, or
# nothing when all entries are valid. Entries are identified by position and,
# when it is a valid header name, by name; never by value. An invalid name is
# not shown either, in case a whole "Name: value" line was pasted into it.
read -r -d '' JQ_HEADER_PROBLEMS <<'JQ' || true
def valid_name:
  type == "object" and (.name | type) == "string"
  and (.name | test("^[-!#$%&'*+.^_`|~0-9A-Za-z]+$"));

def entry_title($i):
  "request_headers entry \($i + 1)"
  + (if valid_name then " (\(.name))" else "" end);

(to_entries[]
  | .key as $i
  | .value
  | entry_title($i) as $title
  | if type != "object" then
      "\($title): must have a 'name' and a 'value'"
    elif (.name | type) != "string" or .name == "" then
      "\($title): 'name' is required"
    elif (valid_name | not) then
      "\($title): 'name' must be a valid HTTP header name (letters, digits and !#$%&'*+-.^_`|~ only, no spaces or colons)"
    elif (.value | type) != "string" or (.value | test("\\S") | not) then
      "\($title): 'value' is required"
    elif (.value | test("^[ -~\t]*$") | not) then
      "\($title): 'value' may only contain printable ASCII characters (no line breaks or other control characters)"
    else
      empty
    end),
([.[] | select(valid_name)]
  | group_by(.name | ascii_downcase)[]
  | select(length > 1)
  | "request_headers: header '\(.[0].name)' is set more than once (header names are case-insensitive)")
JQ

# Reads the version of the Gateway binary, recorded when the image was built,
# into GATEWAY_VERSION. It stays empty when the file is missing, empty or
# holds anything other than a version; the Web UI then shows the version from
# the audit log.
read_gateway_version() {
    local version=""

    if [[ -r "${GATEWAY_VERSION_FILE}" ]]; then
        read -r version <"${GATEWAY_VERSION_FILE}" || true
    fi
    if [[ "${version}" =~ ^[0-9A-Za-z.+-]{1,32}$ ]]; then
        GATEWAY_VERSION="${version}"
    fi
}

# ------------------------------------------------------------------------------
# Options
# ------------------------------------------------------------------------------

# Reads the Twingate network name (the <name> in <name>.twingate.com) into
# NETWORK. A pasted URL such as https://<name>.twingate.com/ is accepted.
read_network() {
    local network
    network=$(bashio::config 'network')
    if [[ "${network}" == "null" ]]; then
        network=""
    fi
    network="${network,,}"
    network="${network#https://}"
    network="${network#http://}"
    network="${network%%/*}"
    network="${network%.twingate.com}"

    if [[ ! "${network}" =~ ^[a-z0-9]{1,63}$ ]]; then
        bashio::exit.nok "Option 'network' must be your Twingate network name, the <name> in <name>.twingate.com (1 to 63 lowercase letters and digits)."
    fi

    NETWORK="${network}"
}

# Reads the Gateway system log level into GATEWAY_LOG_LEVEL. It only affects
# the Gateway; the log level of this script stays at info so that the add-on
# options are never dumped to the log.
read_log_level() {
    GATEWAY_LOG_LEVEL=$(bashio::config 'log_level' 'info')

    case "${GATEWAY_LOG_LEVEL}" in
        debug | info | warn | error) ;;
        *) bashio::exit.nok "Option 'log_level' must be one of: debug, info, warn, error." ;;
    esac
}

# Reads 'request_headers' into HEADERS_JSON, a JSON object of header name to
# value template. The value is passed to the Gateway unchanged, so it may be a
# static string or contain one {{placeholder}} supported by the Gateway.
read_request_headers() {
    local raw problems line

    # bashio prints one compact JSON object per list entry, nothing for [].
    raw=$(bashio::config 'request_headers')
    if [[ "${raw}" == "null" ]]; then
        raw=""
    fi

    problems=$(printf '%s' "${raw}" | jq --raw-output --slurp "${JQ_HEADER_PROBLEMS}")
    if [[ -n "${problems}" ]]; then
        while IFS= read -r line; do
            bashio::log.error "${line}"
        done <<<"${problems}"
        bashio::exit.nok "Option 'request_headers' is invalid, see the errors above."
    fi

    HEADERS_JSON=$(printf '%s' "${raw}" | jq --compact-output --slurp 'map({(.name): .value}) | add // {}')
}

# Reads 'certificate_ip_addresses' into STATIC_IPS, a sorted, comma-separated
# list without duplicates. A client that reaches a Resource by IP address sends
# no TLS server name (SNI), so the Gateway cannot issue a certificate for it on
# demand; these addresses get a static certificate instead. Only IPv4 is
# accepted: the Gateway refuses IPv6 Resource addresses (its upstream host must
# match a host name pattern without colons).
read_certificate_ip_addresses() {
    local raw
    local address
    local sorted
    local octet='(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
    local -a addresses=()

    # bashio prints one list entry per line, nothing for [].
    raw=$(bashio::config 'certificate_ip_addresses')
    if [[ "${raw}" == "null" ]]; then
        raw=""
    fi

    while IFS= read -r address; do
        address="${address//[[:space:]]/}"
        if [[ -z "${address}" ]]; then
            continue
        fi
        if [[ "${address}" == *:* ]]; then
            bashio::exit.nok "Option 'certificate_ip_addresses': '${address}' looks like an IPv6 address. Only IPv4 addresses are supported, because the Gateway cannot proxy to IPv6 Resource addresses."
        fi
        if [[ ! "${address}" =~ ^${octet}(\.${octet}){3}$ ]]; then
            bashio::exit.nok "Option 'certificate_ip_addresses': '${address}' is not an IPv4 address (four numbers from 0 to 255 separated by dots, for example 192.168.1.10)."
        fi
        addresses+=("${address}")
    done <<<"${raw}"

    if ((${#addresses[@]} > 0)); then
        sorted=$(printf '%s\n' "${addresses[@]}" | sort -u)
        mapfile -t addresses <<<"${sorted}"
        STATIC_IPS=$(
            IFS=,
            printf '%s' "${addresses[*]}"
        )
    fi
}

# Reads 'audit_log' into AUDIT_LOG. The Gateway's audit log records every
# request with its incoming headers, so it can be sent to a file in the add-on
# configuration folder instead of the add-on log.
read_audit_log() {
    AUDIT_LOG=$(bashio::config 'audit_log' 'addon_log')

    case "${AUDIT_LOG}" in
        addon_log | file) ;;
        *) bashio::exit.nok "Option 'audit_log' must be 'addon_log' or 'file'." ;;
    esac

    # s6-log copies the Gateway's standard output to the add-on log and to
    # the logdir that the audit relay of the Web UI reads. Without the pipe
    # to s6-log (file descriptor 3 is not open), the audit log goes to
    # standard error as before and the Web UI shows no requests.
    if { true >&3; } 2>/dev/null; then
        AUDIT_PIPE=true
    fi
}

# Checks that the Twingate network exists by requesting the signing key URL
# the Gateway uses. Only a 404 stops the add-on; when Twingate cannot be
# reached (for example while the host is still offline at boot) or answers
# anything else, the add-on warns and starts anyway. Redirects are not
# followed and count as found: Twingate redirects networks hosted on a
# regional host, and the Gateway follows that redirect itself.
check_network() {
    local url="https://${NETWORK}.twingate.com/api/v1/jwk/ec"
    local status

    if ! status=$(curl --silent --output /dev/null --write-out '%{http_code}' \
        --connect-timeout 5 --max-time 10 "${url}"); then
        bashio::log.warning "Could not reach ${url} to check the network name. Starting anyway."
        return 0
    fi

    NETWORK_CHECK_STATUS="${status}"
    case "${status}" in
        404)
            bashio::exit.nok "Twingate network '${NETWORK}' not found: ${url} answered 404 Not Found. Set 'network' to the <name> in your Admin Console address <name>.twingate.com."
            ;;
        2?? | 3??)
            NETWORK_CHECK="found"
            bashio::log.info "Twingate network '${NETWORK}' found."
            ;;
        *)
            NETWORK_CHECK="http_error"
            bashio::log.warning "Could not check the network name: ${url} answered HTTP ${status}. Starting anyway."
            ;;
    esac
}

# ------------------------------------------------------------------------------
# Certificate authority
# ------------------------------------------------------------------------------

# Resolves the value of a custom CA option to a readable file inside /ssl and
# stores it in RESOLVED_PATH.
resolve_ssl_file() {
    local option=$1
    local value=$2
    local relative="${value#"${SSL_DIR}"/}"
    local LC_ALL=C

    if [[ ! "${relative}" =~ ^[\ -~]+$ ]]; then
        bashio::exit.nok "Option '${option}' may only contain printable ASCII characters."
    fi
    if [[ "${relative}" == /* ]]; then
        bashio::exit.nok "Option '${option}' must be a file name relative to the Home Assistant ssl folder (${SSL_DIR}), for example 'twingate/ca.crt'."
    fi
    if [[ "/${relative}/" == */../* ]]; then
        bashio::exit.nok "Option '${option}' must not contain '..'."
    fi

    RESOLVED_PATH="${SSL_DIR}/${relative}"
    if [[ ! -f "${RESOLVED_PATH}" || ! -r "${RESOLVED_PATH}" ]]; then
        bashio::exit.nok "Option '${option}': ${RESOLVED_PATH} does not exist or is not a readable file."
    fi
}

# Prints what prevents the Gateway's local issuer from using a CA certificate
# and private key, or nothing when the pair is usable. The Gateway loads the
# pair with Go's tls.LoadX509KeyPair and requires basicConstraints CA:TRUE and,
# when a key usage is present, keyCertSign.
ca_pair_problem() {
    local cert=$1
    local key=$2
    local cert_public_key
    local key_public_key
    local usage

    if ! openssl x509 -in "${cert}" -noout 2>/dev/null; then
        echo "the certificate is missing or not a PEM encoded X.509 certificate"
        return 0
    fi
    if ! openssl pkey -in "${key}" -passin pass: -noout 2>/dev/null; then
        echo "the private key is missing or not an unencrypted PEM private key"
        return 0
    fi
    cert_public_key=$(openssl x509 -in "${cert}" -noout -pubkey)
    key_public_key=$(openssl pkey -in "${key}" -passin pass: -pubout)
    if [[ "${cert_public_key}" != "${key_public_key}" ]]; then
        echo "the private key does not belong to the certificate"
        return 0
    fi
    if ! openssl x509 -in "${cert}" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE'; then
        echo "the certificate is not a CA certificate (basicConstraints CA:TRUE is missing)"
        return 0
    fi
    usage=$(openssl x509 -in "${cert}" -noout -ext keyUsage 2>/dev/null || true)
    if [[ "${usage}" == *"Key Usage"* && "${usage}" != *"Certificate Sign"* ]]; then
        echo "the certificate's key usage does not allow signing certificates (keyCertSign)"
        return 0
    fi
    if ! openssl x509 -in "${cert}" -noout -checkend 0 >/dev/null; then
        echo "the certificate has expired"
        return 0
    fi
}

# Creates an ECDSA P-256 CA in /data/ca, replacing any previous one.
create_ca() {
    local tmp
    local suffix

    install -d -m 0700 "${CA_DIR}"
    tmp=$(mktemp -d "${CA_DIR}/.new.XXXXXX")
    suffix=$(openssl rand -hex 4)

    cat >"${tmp}/openssl.cnf" <<EOF
[req]
prompt = no
distinguished_name = subject
x509_extensions = ca_extensions

[subject]
CN = Twingate Gateway add-on CA ${suffix}

[ca_extensions]
basicConstraints = critical, CA:TRUE, pathlen:0
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
EOF

    if ! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${tmp}/ca.key"; then
        rm -rf "${tmp}"
        bashio::exit.nok "Failed to create the CA private key."
    fi
    if ! openssl req -new -x509 -config "${tmp}/openssl.cnf" -key "${tmp}/ca.key" \
        -sha256 -days "${CA_VALIDITY_DAYS}" -out "${tmp}/ca.crt"; then
        rm -rf "${tmp}"
        bashio::exit.nok "Failed to create the CA certificate."
    fi

    chmod 0600 "${tmp}/ca.key"
    chmod 0644 "${tmp}/ca.crt"
    # Flush the new files before the renames and the renames themselves, so a
    # power loss cannot leave an empty or missing CA key behind.
    sync
    mv -f "${tmp}/ca.key" "${ADDON_CA_KEY}"
    mv -f "${tmp}/ca.crt" "${ADDON_CA_CERT}"
    rm -rf "${tmp}"
    sync
}

# Warns when a private key file is readable by its group or by others. The
# add-on cannot change files in the read-only ssl folder, and the key is
# usable either way, so this is never fatal. The unprivileged processes in
# the add-on (the Web UI runs as nobody, the audit log relay as audit-relay,
# s6-log as audit-log) can read a world-readable key.
warn_if_key_readable() {
    local key=$1
    local mode

    if ! mode=$(stat -L -c '%a' "${key}" 2>/dev/null) || [[ ! "${mode}" =~ ^[0-7]+$ ]]; then
        return 0
    fi
    if (((8#${mode} & 8#044) != 0)); then
        bashio::log.warning "The private key ${key} is readable by its group or by other users (mode ${mode}). Make it readable by its owner only, for example with 'chmod 600', so that unprivileged processes in this add-on cannot read it."
    fi
    return 0
}

# Selects the CA (custom files in /ssl, or the one this add-on creates in
# /data/ca) and stores its paths in CA_CERT and CA_KEY.
prepare_ca() {
    local certfile
    local keyfile
    local problem

    certfile=$(bashio::config 'custom_ca_certfile')
    keyfile=$(bashio::config 'custom_ca_keyfile')
    if [[ "${certfile}" == "null" ]]; then
        certfile=""
    fi
    if [[ "${keyfile}" == "null" ]]; then
        keyfile=""
    fi

    if [[ -n "${certfile}" || -n "${keyfile}" ]]; then
        if [[ -z "${certfile}" || -z "${keyfile}" ]]; then
            bashio::exit.nok "Set both 'custom_ca_certfile' and 'custom_ca_keyfile' to use your own CA, or neither to use the CA created by this add-on."
        fi

        resolve_ssl_file custom_ca_certfile "${certfile}"
        CA_CERT="${RESOLVED_PATH}"
        resolve_ssl_file custom_ca_keyfile "${keyfile}"
        CA_KEY="${RESOLVED_PATH}"

        problem=$(ca_pair_problem "${CA_CERT}" "${CA_KEY}")
        if [[ -n "${problem}" ]]; then
            bashio::exit.nok "The custom CA (${CA_CERT}, ${CA_KEY}) cannot be used: ${problem}."
        fi
        CA_SOURCE="custom"
        bashio::log.info "Using the custom CA certificate ${CA_CERT}."
        warn_if_key_readable "${CA_KEY}"
    else
        CA_CERT="${ADDON_CA_CERT}"
        CA_KEY="${ADDON_CA_KEY}"

        if [[ ! -e "${CA_CERT}" && ! -e "${CA_KEY}" ]]; then
            bashio::log.info "Creating a new CA in ${CA_DIR} (valid for ${CA_VALIDITY_DAYS} days)."
            create_ca
        else
            problem=$(ca_pair_problem "${CA_CERT}" "${CA_KEY}")
            if [[ -n "${problem}" ]]; then
                bashio::log.warning "The CA in ${CA_DIR} cannot be used: ${problem}."
                bashio::log.warning "Creating a new CA. Register the new CA certificate shown below in Twingate; Clients will not trust this Gateway until you do."
                create_ca
            fi
        fi
    fi

    if ! openssl x509 -in "${CA_CERT}" -noout -checkend $((CA_EXPIRY_WARNING_DAYS * 86400)) >/dev/null; then
        bashio::log.warning "The CA certificate expires in less than ${CA_EXPIRY_WARNING_DAYS} days. Replace it and register the new certificate in Twingate before it expires."
    fi
}

# Succeeds when the static certificate in /data/tls was issued by the current
# CA for the configured addresses, matches its key and does not expire soon.
static_certificate_is_current() {
    local issued_for=$1
    local cert_public_key
    local key_public_key

    if [[ ! -f "${STATIC_CERT}" || ! -f "${STATIC_KEY}" || ! -f "${STATIC_CERT_STATE}" ]]; then
        return 1
    fi
    if [[ "$(<"${STATIC_CERT_STATE}")" != "${issued_for}" ]]; then
        return 1
    fi
    if ! openssl verify -partial_chain -CAfile "${CA_CERT}" "${STATIC_CERT}" >/dev/null 2>&1; then
        return 1
    fi
    if ! openssl x509 -in "${STATIC_CERT}" -noout -checkend $((STATIC_CERT_RENEW_DAYS * 86400)) >/dev/null; then
        return 1
    fi
    if ! cert_public_key=$(openssl x509 -in "${STATIC_CERT}" -noout -pubkey 2>/dev/null) ||
        ! key_public_key=$(openssl pkey -in "${STATIC_KEY}" -pubout 2>/dev/null) ||
        [[ "${cert_public_key}" != "${key_public_key}" ]]; then
        return 1
    fi
    return 0
}

# Makes sure /data/tls holds a certificate for the addresses in STATIC_IPS,
# signed by the current CA. It is issued again when the addresses or the CA
# change, or when it expires within STATIC_CERT_RENEW_DAYS days. Without
# addresses, any previous static certificate is removed.
prepare_static_certificate() {
    local ca_fingerprint
    local issued_for
    local tmp
    local serial
    local address
    local subject_alt_names=""
    local -a addresses=()

    if [[ -z "${STATIC_IPS}" ]]; then
        rm -rf "${STATIC_CERT_DIR}"
        return 0
    fi

    ca_fingerprint=$(openssl x509 -in "${CA_CERT}" -noout -fingerprint -sha256)
    issued_for="${STATIC_IPS} ${ca_fingerprint#*=}"

    # The check reports every failure through its return value.
    # shellcheck disable=SC2310
    if static_certificate_is_current "${issued_for}"; then
        bashio::log.info "Using the static certificate for ${STATIC_IPS}."
        return 0
    fi

    bashio::log.info "Issuing a static certificate for ${STATIC_IPS} (valid for ${STATIC_CERT_VALIDITY_DAYS} days)."

    IFS=',' read -r -a addresses <<<"${STATIC_IPS}"
    for address in "${addresses[@]}"; do
        subject_alt_names+="${subject_alt_names:+, }IP:${address}"
    done

    install -d -m 0700 "${STATIC_CERT_DIR}"
    tmp=$(mktemp -d "${STATIC_CERT_DIR}/.new.XXXXXX")
    serial=$(openssl rand -hex 16)

    cat >"${tmp}/extensions.cnf" <<EOF
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
subjectAltName = ${subject_alt_names}
EOF

    # openssl reports progress on stderr; show it only when issuing fails.
    if ! openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -out "${tmp}/tls.key" 2>>"${tmp}/openssl.log" ||
        ! openssl req -new -key "${tmp}/tls.key" -subj "/CN=Twingate Gateway add-on" -out "${tmp}/tls.csr" 2>>"${tmp}/openssl.log" ||
        ! openssl x509 -req -in "${tmp}/tls.csr" -CA "${CA_CERT}" -CAkey "${CA_KEY}" \
            -set_serial "0x${serial}" -days "${STATIC_CERT_VALIDITY_DAYS}" -sha256 \
            -extfile "${tmp}/extensions.cnf" -out "${tmp}/leaf.crt" 2>>"${tmp}/openssl.log"; then
        cat "${tmp}/openssl.log" >&2
        rm -rf "${tmp}"
        bashio::exit.nok "Failed to issue the static certificate for ${STATIC_IPS}."
    fi

    # Serve the CA certificate after the leaf, as the Gateway does for the
    # certificates it issues on demand.
    {
        cat "${tmp}/leaf.crt"
        openssl x509 -in "${CA_CERT}" -outform PEM
    } >"${tmp}/tls.crt"
    printf '%s' "${issued_for}" >"${tmp}/issued-for"

    chmod 0600 "${tmp}/tls.key"
    chmod 0644 "${tmp}/tls.crt"
    sync
    mv -f "${tmp}/tls.key" "${STATIC_KEY}"
    mv -f "${tmp}/tls.crt" "${STATIC_CERT}"
    mv -f "${tmp}/issued-for" "${STATIC_CERT_STATE}"
    rm -rf "${tmp}"
    sync
}

# Prints the CA certificate (never the key) so that it can be registered in
# Twingate.
print_ca() {
    local subject
    local not_after
    local fingerprint

    subject=$(openssl x509 -in "${CA_CERT}" -noout -subject -nameopt RFC2253)
    not_after=$(openssl x509 -in "${CA_CERT}" -noout -enddate)
    fingerprint=$(openssl x509 -in "${CA_CERT}" -noout -fingerprint -sha256)

    bashio::log.info "The Gateway signs its TLS certificates with this CA. Twingate Clients trust the Gateway only if this CA certificate is registered in Twingate as the X.509 certificate authority of the Gateway."
    bashio::log.info "CA subject: ${subject#subject=}"
    bashio::log.info "CA expires: ${not_after#notAfter=}"
    bashio::log.info "CA SHA-256 fingerprint: ${fingerprint#*=}"
    bashio::log.info "CA certificate (PEM, certificate only):"
    openssl x509 -in "${CA_CERT}" -outform PEM
}

# ------------------------------------------------------------------------------
# Gateway configuration
# ------------------------------------------------------------------------------

# Writes the Gateway configuration. The file is JSON, which is valid YAML: jq
# encodes every value as a JSON string, so quotes, colons, braces or any other
# YAML syntax in a header value cannot change the structure of the file. The
# header values reach jq on stdin, not on its command line. --ascii-output
# keeps the file 7-bit clean. With audit_log addon_log, the audit log goes to
# the Gateway's standard output, which s6-log copies to the add-on log.
render_config() {
    local tmp

    install -d -m 0700 "${CONFIG_DIR}"
    tmp=$(mktemp "${CONFIG_DIR}/.config.XXXXXX")

    # Static certificates are tried first and serve handshakes without SNI;
    # any other server name gets a certificate issued on demand by the CA.
    printf '%s' "${HEADERS_JSON}" | jq --ascii-output \
        --arg network "${NETWORK}" \
        --arg level "${GATEWAY_LOG_LEVEL}" \
        --argjson port "${GATEWAY_PORT}" \
        --arg ca_cert "${CA_CERT}" \
        --arg ca_key "${CA_KEY}" \
        --arg static_ips "${STATIC_IPS}" \
        --arg static_cert "${STATIC_CERT}" \
        --arg static_key "${STATIC_KEY}" \
        --arg audit_log "${AUDIT_LOG}" \
        --arg audit_file "${AUDIT_LOG_FILE}" \
        --arg audit_pipe "${AUDIT_PIPE}" \
        '. as $headers
        | {
            twingate: {network: $network},
            port: $port,
            log: {
              system: {level: $level, output: {stderr: {}}},
              audit: {
                output: (
                  if $audit_log == "file" then
                    {file: {path: $audit_file, rotation: {maxSize: "10MiB", maxBackupFiles: 3, compression: "gzip"}}}
                  elif $audit_pipe == "true" then
                    {stdout: {}}
                  else
                    {stderr: {}}
                  end
                )
              }
            },
            tls: (
              (if $static_ips != "" then
                {certificates: {files: [{certificateFile: $static_cert, privateKeyFile: $static_key}]}}
              else
                {}
              end)
              + {automation: {issuer: {local: {certificateFile: $ca_cert, privateKeyFile: $ca_key}}}}
            ),
            webApp: (if ($headers | length) > 0 then {requestHeaders: $headers} else {} end)
          }' >"${tmp}"

    chmod 0600 "${tmp}"
    mv -f "${tmp}" "${CONFIG_FILE}"
}

# Writes the status file that the Web UI shows: the options without secret
# values, the CA certificate (never its key), the Gateway version recorded
# when the image was built and the result of the network check. As in
# render_config, the header values reach jq on stdin; only their names are
# written. The file is world-readable because the Web UI runs as an
# unprivileged user. The Web UI is not essential, so this function returns 1
# on any failure instead of stopping the add-on.
write_status() {
    local tmp
    local addon_version
    local addon_slug
    local host_port=""
    local host_port_state="unknown"
    local audit_stream="none"
    local started_at
    local ca_subject
    local ca_not_after
    local ca_fingerprint
    local ca_pem
    local static_not_after=""

    started_at=$(date +%s) || return 1
    ca_subject=$(openssl x509 -in "${CA_CERT}" -noout -subject -nameopt RFC2253) || return 1
    ca_not_after=$(openssl x509 -in "${CA_CERT}" -noout -enddate -dateopt iso_8601) || return 1
    ca_fingerprint=$(openssl x509 -in "${CA_CERT}" -noout -fingerprint -sha256) || return 1
    ca_pem=$(openssl x509 -in "${CA_CERT}" -outform PEM) || return 1
    if [[ -n "${STATIC_IPS}" ]]; then
        static_not_after=$(openssl x509 -in "${STATIC_CERT}" -noout -enddate -dateopt iso_8601) || return 1
    fi

    if [[ "${AUDIT_LOG}" == "file" ]]; then
        audit_stream="file"
    elif [[ "${AUDIT_PIPE}" == true ]]; then
        # Through s6-log, which keeps the copy that the relay reads.
        audit_stream="relay"
    fi

    # The add-on's version, slug and host port come from its own Supervisor
    # API entry (/addons/self/info), which needs no API permission in
    # config.yaml. If the request fails, the Web UI shows them as unknown. The
    # slug completes the 'ha apps rebuild' command that the Web UI shows when
    # a newer Gateway is available.
    addon_version=$(bashio::app.version) || addon_version=""
    addon_slug=$(bashio::app.slug) || addon_slug=""
    if [[ "${addon_slug}" == "null" || ! "${addon_slug}" =~ ^[a-z0-9][a-z0-9_-]{0,63}$ ]]; then
        addon_slug=""
    fi
    if host_port=$(bashio::app.port "${GATEWAY_PORT}/tcp"); then
        if [[ "${host_port}" =~ ^[0-9]+$ ]]; then
            host_port_state="mapped"
        else
            host_port=""
            host_port_state="not_mapped"
        fi
    else
        host_port=""
    fi

    install -d -m 0755 "${STATUS_DIR}" || return 1
    tmp=$(mktemp "${STATUS_DIR}/.status.XXXXXX") || return 1

    if ! printf '%s' "${HEADERS_JSON}" | jq --ascii-output \
        --arg addon_version "${addon_version}" \
        --arg addon_slug "${addon_slug}" \
        --arg gateway_version "${GATEWAY_VERSION}" \
        --argjson started_at "${started_at}" \
        --arg network "${NETWORK}" \
        --arg network_check "${NETWORK_CHECK}" \
        --arg network_check_status "${NETWORK_CHECK_STATUS}" \
        --arg level "${GATEWAY_LOG_LEVEL}" \
        --arg audit_log "${AUDIT_LOG}" \
        --arg audit_file "${AUDIT_LOG_FILE}" \
        --arg audit_stream "${audit_stream}" \
        --arg static_ips "${STATIC_IPS}" \
        --arg static_not_after "${static_not_after#notAfter=}" \
        --argjson port "${GATEWAY_PORT}" \
        --arg host_port "${host_port}" \
        --arg host_port_state "${host_port_state}" \
        --arg ca_source "${CA_SOURCE}" \
        --arg ca_cert "${CA_CERT}" \
        --arg ca_subject "${ca_subject#subject=}" \
        --arg ca_not_after "${ca_not_after#notAfter=}" \
        --arg ca_fingerprint "${ca_fingerprint#*=}" \
        --arg ca_pem "${ca_pem}" \
        '{
            schema: 1,
            addon_version: $addon_version,
            addon_slug: (if $addon_slug == "" then null else $addon_slug end),
            gateway_version: (if $gateway_version == "" then null else $gateway_version end),
            started_at: $started_at,
            network: $network,
            network_check: {result: $network_check, http_status: $network_check_status},
            log_level: $level,
            audit_log: $audit_log,
            audit_log_file: (if $audit_log == "file" then $audit_file else null end),
            audit_stream: $audit_stream,
            request_header_names: keys,
            certificate_ip_addresses: (if $static_ips == "" then [] else ($static_ips | split(",")) end),
            gateway_port: $port,
            host_port: (if $host_port == "" then null else ($host_port | tonumber) end),
            host_port_state: $host_port_state,
            ca: {
              source: $ca_source,
              certificate_file: $ca_cert,
              subject: $ca_subject,
              not_after: $ca_not_after,
              fingerprint_sha256: $ca_fingerprint,
              pem: ($ca_pem + "\n")
            },
            static_certificate: (if $static_ips == "" then null else {not_after: $static_not_after} end)
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
main() {
    local header_names

    # The Web UI shows the Gateway as starting until write_status runs.
    rm -f "${STATUS_FILE}"

    read_gateway_version
    read_network
    read_log_level
    read_request_headers
    read_certificate_ip_addresses
    read_audit_log
    check_network
    prepare_ca
    prepare_static_certificate
    print_ca
    render_config
    # write_status reports every failure through its return value.
    # shellcheck disable=SC2310
    if ! write_status; then
        bashio::log.warning "Could not write the status for the Web UI. The Gateway starts anyway; the Web UI shows it as starting."
    elif [[ "${AUDIT_LOG}" == "file" ]]; then
        # The relay runs as audit-relay until the status file says audit_log
        # is file; then its run script starts it as root, which can read
        # audit.log. The Gateway does not depend on the relay.
        s6-svc -r "${RELAY_SERVICE}" ||
            bashio::log.warning "Could not restart the audit log relay; the Web UI may show no requests."
    fi

    bashio::log.info "Twingate network: ${NETWORK}"
    header_names=$(jq --raw-output 'keys | join(", ")' <<<"${HEADERS_JSON}")
    if [[ -n "${header_names}" ]]; then
        bashio::log.info "Request headers injected into Web App requests: ${header_names} (values are not logged)."
        bashio::log.warning "These headers are sent to EVERY Web App Resource that uses this Gateway. Assign only the intended Resource (the Home Assistant API) to this Gateway."
    else
        bashio::log.info "No request headers configured; requests are proxied without injected headers."
    fi
    if [[ "${AUDIT_LOG}" == "file" ]]; then
        bashio::log.info "Audit log: ${AUDIT_LOG_FILE} in the add-on configuration folder."
    else
        bashio::log.info "Audit log: add-on log. It records every request with its incoming headers."
    fi
    bashio::log.info "Starting Twingate Gateway${GATEWAY_VERSION:+ ${GATEWAY_VERSION}} on port ${GATEWAY_PORT}/tcp with log level ${GATEWAY_LOG_LEVEL}."

    # The Gateway does not need access to the Supervisor API.
    unset SUPERVISOR_TOKEN HASSIO_TOKEN

    if [[ "${AUDIT_PIPE}" == true ]]; then
        # Standard output, which carries the audit log with addon_log, goes
        # to s6-log.
        exec "${GATEWAY_BIN}" start --config "${CONFIG_FILE}" >&3 3>&-
    fi
    exec "${GATEWAY_BIN}" start --config "${CONFIG_FILE}"
}

main "$@"
