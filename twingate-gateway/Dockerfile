# Both images are pinned by tag and by the digest of their multi-platform
# index, so each platform still resolves to its own image.

# Twingate Gateway release image (distroless, published for amd64 and arm64).
FROM twingate/gateway:2.1.0@sha256:3c351579f5cd67e4135ebe675bd26e688d440e593083dbba3648b98ef5361b94 AS gateway

# Home Assistant base image (Alpine with s6-overlay v3 and bashio). The
# Supervisor builds this Dockerfile directly with
# `docker buildx build --platform ...`, so no build.yaml is needed.
FROM ghcr.io/home-assistant/base:3.24-2026.11.0@sha256:58422480a299b16b6ea376c2167463206d430619ed02b40cd687c8bd6875519e

# openssl creates and checks the CA used for on-demand TLS certificates.
# bash, bashio, jq and ca-certificates are already part of the base image.
RUN apk add --no-cache openssl

COPY --from=gateway /gateway /usr/local/bin/twingate-gateway
COPY --from=gateway /LICENSE /usr/share/licenses/twingate-gateway/LICENSE

COPY run.sh /
RUN chmod a+x /run.sh

# The Gateway answers GET /healthz inside TLS on its listener without a token.
# This is a local liveness probe over loopback, so the certificate is not
# verified.
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD curl --fail --silent --show-error --insecure --max-time 5 \
        https://127.0.0.1:8443/healthz || exit 1

CMD [ "/run.sh" ]
