# Twingate Gateway release image (distroless, published for amd64 and arm64).
# The tag `2` follows the newest 2.x release, so each build of the add-on
# takes the Gateway that is current at that moment. The Web UI looks up once a
# day which release this tag points to on Docker Hub and says when a rebuild
# would install a newer one. A new major version is adopted with an add-on
# release, because its configuration, metrics or audit log may differ from
# what run.sh and the Web UI expect.
FROM twingate/gateway:2 AS gateway

# Home Assistant base image (Alpine with s6-overlay v3 and bashio), pinned by
# tag and by the digest of its multi-platform index, so each platform still
# resolves to its own image. The Supervisor builds this Dockerfile directly
# with `docker buildx build --platform ...`, so no build.yaml is needed.
FROM ghcr.io/home-assistant/base:3.24-2026.11.0@sha256:58422480a299b16b6ea376c2167463206d430619ed02b40cd687c8bd6875519e

# openssl creates and checks the CA used for on-demand TLS certificates.
# python3 runs the Web UI and the audit log relay (standard library only);
# '!pyc' leaves out the precompiled standard library (about 11 MiB), the
# checks below compile only the modules that are used.
# bash, bashio, jq and ca-certificates are already part of the base image.
RUN apk add --no-cache openssl python3 '!pyc'

COPY --from=gateway /gateway /usr/local/bin/twingate-gateway
COPY --from=gateway /LICENSE /usr/share/licenses/twingate-gateway/LICENSE

# s6-overlay services: the Gateway (twingate-gateway, started by /run.sh),
# s6-log for its standard output (twingate-gateway-log), which keeps a copy
# of the audit log in /dev/shm, the audit log relay for the Web UI
# (twingate-gateway-relay) and the Web UI (twingate-gateway-ui).
COPY rootfs /
COPY icon.png /usr/share/twingate-gateway-ui/icon.png
COPY run.sh /

# s6-log runs as its own unprivileged user, audit-log, the relay as
# audit-relay and the Web UI as nobody. The checks test the Web UI and the
# relay. Run as root first, they compile the Python modules they import, so
# that they start quickly; run again as the unprivileged users, they fail the
# build if those users cannot read a file the services need.
# Last, gateway_version.py records the version of the Gateway copied above
# for the Web UI: it starts the Gateway as nobody with a configuration that
# cannot start and reads the version from its first log line, without any
# network request. If that fails, the file stays empty, the build goes on
# and the Web UI shows the version from the audit log instead.
RUN addgroup -S audit-relay \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G audit-relay audit-relay \
    && addgroup -S audit-log \
    && adduser -S -D -H -h /nonexistent -s /sbin/nologin -G audit-log audit-log \
    && chmod a+x /run.sh /etc/s6-overlay/s6-rc.d/*/run /etc/s6-overlay/s6-rc.d/*/finish \
    && python3 -I -m compileall -q /usr/lib/twingate-gateway-ui \
    && python3 -I /usr/lib/twingate-gateway-ui/gateway_ui.py --check \
    && python3 -I /usr/lib/twingate-gateway-ui/audit_relay.py --check \
    && python3 -I /usr/lib/twingate-gateway-ui/gateway_version.py --check \
    && chmod -R a+rX /usr/lib/twingate-gateway-ui /usr/share/twingate-gateway-ui \
    && s6-setuidgid nobody python3 -I /usr/lib/twingate-gateway-ui/gateway_ui.py --check \
    && s6-setuidgid audit-relay python3 -I /usr/lib/twingate-gateway-ui/audit_relay.py --check \
    && install -d -m 0755 /usr/share/twingate-gateway \
    && { s6-setuidgid nobody python3 -I /usr/lib/twingate-gateway-ui/gateway_version.py \
        --detect /usr/local/bin/twingate-gateway >/usr/share/twingate-gateway/version || true; } \
    && chmod 0644 /usr/share/twingate-gateway/version

# The Gateway answers GET /healthz inside TLS on its listener without a token.
# This is a local liveness probe over loopback, so the certificate is not
# verified.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl --fail --silent --show-error --insecure --max-time 5 \
        https://127.0.0.1:8443/healthz || exit 1
