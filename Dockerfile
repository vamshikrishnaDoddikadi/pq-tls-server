# =========================================================================
# PQ-TLS Server — Multi-stage Docker Build (fully vendored)
# =========================================================================
# All PQ dependencies (liboqs, oqs-provider) are built into /app/vendor/
# inside the image — zero system-wide installs.
#
# Build:
#   docker build -t pq-tls-server .
#
# Run:
#   docker run -p 8443:8443 \
#     -v ./certs:/etc/pq-tls-server/certs:ro \
#     pq-tls-server --backend host.docker.internal:8080
# =========================================================================

# --- Stage 1: Build liboqs + oqs-provider + pq-tls-server ---
FROM ubuntu:22.04 AS builder

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential cmake ninja-build git ca-certificates \
    libssl-dev pkg-config python3 astyle curl xxd \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Build liboqs into /app/vendor/liboqs
RUN git clone --depth 1 --branch 0.11.0 https://github.com/open-quantum-safe/liboqs.git && \
    cd liboqs && mkdir build && cd build && \
    cmake -GNinja -DCMAKE_INSTALL_PREFIX=/app/vendor/liboqs \
          -DBUILD_SHARED_LIBS=ON \
          -DOQS_MINIMAL_BUILD="KEM_ml_kem_768;SIG_ml_dsa_65;SIG_ml_dsa_44;SIG_ml_dsa_87" \
          .. && \
    ninja && ninja install

# Build oqs-provider, copy .so into /app/vendor/oqs-provider/build/lib/
RUN git clone --depth 1 --branch 0.7.0 https://github.com/open-quantum-safe/oqs-provider.git && \
    cd oqs-provider && mkdir build && cd build && \
    cmake -GNinja -DCMAKE_BUILD_TYPE=Release \
          -Dliboqs_DIR=/app/vendor/liboqs/lib/cmake/liboqs \
          .. && \
    ninja && \
    mkdir -p /app/vendor/oqs-provider/build/lib && \
    cp lib/oqsprovider.so /app/vendor/oqs-provider/build/lib/ 2>/dev/null \
    || find . -name 'oqsprovider.so' -exec cp {} /app/vendor/oqs-provider/build/lib/ \;

# Copy and build PQ-TLS server against vendored liboqs
COPY . /build/pq-tls-server
WORKDIR /build/pq-tls-server

# Download Chart.js and embed frontend assets into the binary
RUN curl -sL -o src/mgmt/static/vendor/chart.min.js \
      https://cdn.jsdelivr.net/npm/chart.js@4.4.1/dist/chart.umd.min.js && \
    bash tools/embed_assets.sh

RUN mkdir build && cd build && \
    cmake -DCMAKE_BUILD_TYPE=Release \
          -DOQS_INCLUDE_DIR=/app/vendor/liboqs/include \
          -DOQS_LIBRARY=/app/vendor/liboqs/lib/liboqs.so \
          .. && \
    make -j"$(nproc)"

# --- Stage 2: Runtime image ---
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy vendored PQ libraries
COPY --from=builder /app/vendor/liboqs/lib/ /app/vendor/liboqs/lib/
COPY --from=builder /app/vendor/oqs-provider/build/lib/oqsprovider.so \
                    /app/vendor/oqs-provider/build/lib/oqsprovider.so

# Copy server binary and config
COPY --from=builder /build/pq-tls-server/build/bin/pq-tls-server /app/bin/pq-tls-server
COPY --from=builder /build/pq-tls-server/etc/pq-tls-server.conf \
                    /etc/pq-tls-server/pq-tls-server.conf

# Update library cache for vendored libs
RUN echo "/app/vendor/liboqs/lib" > /etc/ld.so.conf.d/pq-tls.conf && ldconfig

# Tell OpenSSL where to find oqsprovider.so
ENV OPENSSL_MODULES=/app/vendor/oqs-provider/build/lib
ENV LD_LIBRARY_PATH=/app/vendor/liboqs/lib

# Create non-root user
RUN useradd --system --no-create-home pq-tls && \
    mkdir -p /etc/pq-tls-server/certs /var/log/pq-tls-server && \
    chown -R pq-tls:pq-tls /var/log/pq-tls-server

EXPOSE 8443 9090
USER pq-tls

ENTRYPOINT ["/app/bin/pq-tls-server"]
CMD ["--config", "/etc/pq-tls-server/pq-tls-server.conf"]
