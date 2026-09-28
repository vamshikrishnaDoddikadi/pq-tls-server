#!/usr/bin/env bash
# =========================================================================
# Build the pinned post-quantum dependencies into vendor/.
#
#   scripts/build-deps.sh                 liboqs + oqs-provider + Chart.js
#   scripts/build-deps.sh --no-provider   skip oqs-provider (OpenSSL >= 3.5)
#
# Environment:
#   VENDOR_DIR        install prefix root (default: <repo>/vendor)
#   OPENSSL_ROOT_DIR  build against a non-system OpenSSL
#
# Versions and checksums live in scripts/deps.env. Already-built components
# with the right version are skipped.
# =========================================================================
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck source=deps.env
source "$ROOT/scripts/deps.env"

VENDOR_DIR="${VENDOR_DIR:-$ROOT/vendor}"
WITH_PROVIDER=1
for arg in "$@"; do
    case "$arg" in
        --no-provider) WITH_PROVIDER=0 ;;
        -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
        *) echo "unknown option: $arg" >&2; exit 2 ;;
    esac
done

JOBS="$(nproc 2>/dev/null || echo 4)"
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
CMAKE_OPENSSL=()
if [ -n "${OPENSSL_ROOT_DIR:-}" ]; then
    CMAKE_OPENSSL=(-DOPENSSL_ROOT_DIR="$OPENSSL_ROOT_DIR")
fi

log() { printf '\033[1;36m==>\033[0m %s\n' "$*"; }

# clone_pinned URL TAG COMMIT DEST — shallow clone, then verify the commit.
clone_pinned() {
    git -c advice.detachedHead=false clone -q --depth 1 --branch "$2" "$1" "$4"
    local got
    got="$(git -C "$4" rev-parse HEAD)"
    if [ "$got" != "$3" ]; then
        echo "ERROR: $1 tag $2 resolved to $got, expected $3" >&2
        exit 1
    fi
}

stamp_ok() { [ -f "$1/.pinned" ] && [ "$(cat "$1/.pinned")" = "$2" ]; }

# ---- liboqs ---------------------------------------------------------------
OQS_PREFIX="$VENDOR_DIR/liboqs"
if stamp_ok "$OQS_PREFIX" "$LIBOQS_COMMIT"; then
    log "liboqs $LIBOQS_VERSION already built"
else
    log "Building liboqs $LIBOQS_VERSION"
    clone_pinned https://github.com/open-quantum-safe/liboqs.git \
        "$LIBOQS_VERSION" "$LIBOQS_COMMIT" "$WORK/liboqs"
    cmake -S "$WORK/liboqs" -B "$WORK/liboqs/build" -GNinja \
        -DCMAKE_BUILD_TYPE=Release \
        -DCMAKE_INSTALL_PREFIX="$OQS_PREFIX" \
        -DBUILD_SHARED_LIBS=ON \
        -DOQS_BUILD_ONLY_LIB=ON \
        -DOQS_MINIMAL_BUILD="$LIBOQS_ALGS" \
        "${CMAKE_OPENSSL[@]}" >/dev/null
    ninja -C "$WORK/liboqs/build" -j "$JOBS" install >/dev/null
    echo "$LIBOQS_COMMIT" >"$OQS_PREFIX/.pinned"
fi

# ---- oqs-provider ---------------------------------------------------------
PROV_DIR="$VENDOR_DIR/oqs-provider"
if [ "$WITH_PROVIDER" = 1 ]; then
    if stamp_ok "$PROV_DIR" "$OQS_PROVIDER_COMMIT"; then
        log "oqs-provider $OQS_PROVIDER_VERSION already built"
    else
        log "Building oqs-provider $OQS_PROVIDER_VERSION"
        clone_pinned https://github.com/open-quantum-safe/oqs-provider.git \
            "$OQS_PROVIDER_VERSION" "$OQS_PROVIDER_COMMIT" "$WORK/oqs-provider"
        cmake -S "$WORK/oqs-provider" -B "$WORK/oqs-provider/build" -GNinja \
            -DCMAKE_BUILD_TYPE=Release \
            -Dliboqs_DIR="$OQS_PREFIX/lib/cmake/liboqs" \
            "${CMAKE_OPENSSL[@]}" >/dev/null
        ninja -C "$WORK/oqs-provider/build" -j "$JOBS" >/dev/null
        mkdir -p "$PROV_DIR/build/lib"
        find "$WORK/oqs-provider/build" -name oqsprovider.so -exec cp {} "$PROV_DIR/build/lib/" \;
        [ -f "$PROV_DIR/build/lib/oqsprovider.so" ] || { echo "oqsprovider.so not built" >&2; exit 1; }
        echo "$OQS_PROVIDER_COMMIT" >"$PROV_DIR/.pinned"
    fi
fi

# ---- Chart.js (dashboard) -------------------------------------------------
CHART_JS="$ROOT/src/mgmt/static/vendor/chart.min.js"
if [ -s "$CHART_JS" ] && head -c 64 "$CHART_JS" | grep -q "Chart.js v$CHARTJS_VERSION" 2>/dev/null; then
    log "Chart.js $CHARTJS_VERSION already present"
else
    log "Fetching Chart.js $CHARTJS_VERSION"
    curl -fsSL -o "$WORK/chartjs.tgz" \
        "https://registry.npmjs.org/chart.js/-/chart.js-$CHARTJS_VERSION.tgz"
    echo "$CHARTJS_TARBALL_SHA256  $WORK/chartjs.tgz" | sha256sum -c --quiet -
    tar -xzf "$WORK/chartjs.tgz" -C "$WORK" package/dist/chart.umd.js
    mkdir -p "$(dirname "$CHART_JS")"
    cp "$WORK/package/dist/chart.umd.js" "$CHART_JS"
fi

log "Dependencies ready in $VENDOR_DIR"
if [ "$WITH_PROVIDER" = 1 ]; then
    echo "    export OPENSSL_MODULES=$PROV_DIR/build/lib   # for the openssl CLI"
fi
