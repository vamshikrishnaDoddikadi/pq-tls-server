# =========================================================================
# PQ-TLS Server — multi-stage Docker build
# =========================================================================
# Debian 13 ships OpenSSL 3.5, which implements the hybrid ML-KEM TLS groups
# (X25519MLKEM768, SecP256r1MLKEM768) natively, so the image needs no
# oqs-provider. liboqs is still built (pinned, see scripts/deps.env) for the
# crypto-agility registry and the benchmark subcommands.
#
# Build:
#   docker build -t pq-tls-server .
#
# Run:
#   docker run -p 8443:8443 \
#     -v ./certs:/etc/pq-tls-server/certs:ro \
#     pq-tls-server --config /etc/pq-tls-server/pq-tls-server.conf \
#                   --backend host.docker.internal:8080
# =========================================================================

# --- Stage 1: build ------------------------------------------------------
FROM debian:trixie-slim AS builder

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build git ca-certificates curl xxd \
        libssl-dev pkg-config python3 openssl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Dependencies first, so this layer is cached across source changes.
COPY scripts/deps.env scripts/build-deps.sh scripts/
RUN VENDOR_DIR=/opt/pq-tls/vendor scripts/build-deps.sh --no-provider

COPY . .
RUN bash tools/embed_assets.sh \
    && cmake -S . -B build -GNinja -DCMAKE_BUILD_TYPE=Release \
        -DOQS_INCLUDE_DIR=/opt/pq-tls/vendor/liboqs/include \
        -DOQS_LIBRARY=/opt/pq-tls/vendor/liboqs/lib/liboqs.so \
    && ninja -C build \
    && ctest --test-dir build --output-on-failure \
    && LD_LIBRARY_PATH=/opt/pq-tls/vendor/liboqs/lib tests/e2e/e2e.sh build/bin/pq-tls-server

# --- Stage 2: runtime ----------------------------------------------------
FROM debian:trixie-slim

ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        libssl3t64 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /opt/pq-tls/vendor/liboqs/lib/ /app/vendor/liboqs/lib/
RUN echo "/app/vendor/liboqs/lib" > /etc/ld.so.conf.d/pq-tls.conf && ldconfig

COPY --from=builder /src/build/bin/pq-tls-server /app/bin/pq-tls-server
COPY etc/pq-tls-server.conf /etc/pq-tls-server/pq-tls-server.conf

# Fixed numeric UID/GID so Kubernetes runAsNonRoot can verify it.
RUN groupadd --system --gid 10001 pq-tls \
    && useradd --system --uid 10001 --gid 10001 --no-create-home \
               --shell /usr/sbin/nologin pq-tls \
    && mkdir -p /etc/pq-tls-server/certs /var/log/pq-tls-server \
    && chown pq-tls:pq-tls /var/log/pq-tls-server

LABEL org.opencontainers.image.title="pq-tls-server" \
      org.opencontainers.image.description="Post-quantum TLS 1.3 termination reverse proxy (hybrid ML-KEM)" \
      org.opencontainers.image.source="https://github.com/vamshikrishnaDoddikadi/pq-tls-server" \
      org.opencontainers.image.licenses="MIT"

EXPOSE 8443 9090
USER 10001:10001

# The TLS listener accepts TCP connections.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD bash -c 'exec 3<>/dev/tcp/127.0.0.1/8443' || exit 1

# SIGTERM triggers a graceful drain (drain_timeout, default 10 s).
STOPSIGNAL SIGTERM
ENTRYPOINT ["/app/bin/pq-tls-server"]
CMD ["--config", "/etc/pq-tls-server/pq-tls-server.conf"]
