# The base image. The Home Assistant Supervisor always passes BUILD_ARCH
# (aarch64, amd64 or armv7, see config.yml) and, while it reads build.yml,
# BUILD_FROM from there. The default is the same image, so the add-on also
# builds when build.yml is no longer read.
ARG BUILD_ARCH=amd64
ARG BUILD_FROM=ghcr.io/hassio-addons/debian-base/${BUILD_ARCH}:6c7cbab
# hadolint ignore=DL3006
FROM ${BUILD_FROM}

# python3 runs the Web UI and the log relay (standard library only). The
# precompiled standard library (about 13 MiB) is removed; the checks below
# compile only the modules that are used. The Connector itself is still
# installed from Twingate's apt repository at every start (see run.sh).
# hadolint ignore=DL3008
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/* \
    && find /usr/lib/python3* -depth -type d -name __pycache__ -exec rm -rf {} +

# One unprivileged user per service: twingate-log runs s6-log, which copies
# the Connector's output to the add-on log; twingate-relay runs the log relay;
# twingate-ui runs the Web UI. The Web UI's user cannot read the relay's
# files or signal its processes.
RUN for user in twingate-log twingate-relay twingate-ui; do \
        useradd --system --user-group --no-create-home --home-dir /nonexistent \
            --shell /usr/sbin/nologin "${user}" || exit 1; \
    done

# s6-overlay services: the Connector (twingate-connector, started by /run.sh),
# s6-log for its output (twingate-connector-log), the log relay
# (twingate-connector-relay) and the Web UI (twingate-connector-ui). The base
# image's /init starts them; the add-on stops when the Connector exits. The
# Web UI shows the add-on's name and listens on its ingress_port, both from
# config.yml.
COPY rootfs /
COPY icon.png /usr/share/twingate-connector-ui/icon.png
COPY config.yml /usr/share/twingate-connector-ui/config.yml
COPY run.sh /

# The checks test the Web UI and the relay. Run as root, they compile the
# Python modules they import, so that the services start quickly; run again
# as the services' users, they fail the build if a file is not readable.
RUN chmod a+x /run.sh /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/finish \
    && python3 -I -m compileall -q /usr/lib/twingate-connector-ui \
    && python3 -I /usr/lib/twingate-connector-ui/connector_ui.py --check \
    && python3 -I /usr/lib/twingate-connector-ui/log_relay.py --check \
    && chmod -R a+rX /usr/lib/twingate-connector-ui /usr/share/twingate-connector-ui \
    && /command/s6-setuidgid twingate-ui python3 -I /usr/lib/twingate-connector-ui/connector_ui.py --check \
    && /command/s6-setuidgid twingate-relay python3 -I /usr/lib/twingate-connector-ui/log_relay.py --check
