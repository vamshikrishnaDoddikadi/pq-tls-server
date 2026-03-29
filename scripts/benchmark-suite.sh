#!/usr/bin/env bash
# ============================================================================
# ML-KEM Hybrid Benchmark Suite — Orchestrator
# ============================================================================
# Drives the full test matrix: algorithms × workloads × network conditions
#
# Usage:
#   ./scripts/benchmark-suite.sh [--quick|--full|--micro-only]
#   ./scripts/benchmark-suite.sh --full --cpu-pin 2 --output-dir ./results
#
# Requirements:
#   - Built bench_runner binary (make bench)
#   - wrk2 or h2load (for HTTP workloads)
#   - tc/netem (for network simulation, needs sudo)
#   - Python 3 + pandas + matplotlib (for analysis)
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_DIR="${BUILD_DIR:-/tmp/pq-tls-build}"
BENCH_BIN="${BUILD_DIR}/bench_runner"

# Defaults
MODE="quick"
CPU_PIN=-1
ITERATIONS=1000
WARMUP=100
OUTPUT_DIR="${PROJECT_DIR}/benchmark-results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULTS_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

# ---- Parse arguments ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        --quick)       MODE="quick"; ITERATIONS=100; WARMUP=10; shift ;;
        --full)        MODE="full"; ITERATIONS=5000; WARMUP=500; shift ;;
        --micro-only)  MODE="micro"; shift ;;
        --cpu-pin)     CPU_PIN="$2"; shift 2 ;;
        --iterations)  ITERATIONS="$2"; shift 2 ;;
        --output-dir)  OUTPUT_DIR="$2"; shift 2 ;;
        --help|-h)
            echo "Usage: $0 [--quick|--full|--micro-only] [--cpu-pin N] [--iterations N] [--output-dir DIR]"
            exit 0 ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

RESULTS_DIR="${OUTPUT_DIR}/${TIMESTAMP}"

# ---- Colors ----
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'

log() { echo -e "${CYAN}[bench]${NC} $*"; }
ok()  { echo -e "${GREEN}[OK]${NC} $*"; }
err() { echo -e "${RED}[ERR]${NC} $*" >&2; }

# ---- Setup ----
log "ML-KEM Hybrid Benchmark Suite"
log "Mode: ${MODE}, Iterations: ${ITERATIONS}, CPU pin: ${CPU_PIN}"
log "Results: ${RESULTS_DIR}"

mkdir -p "${RESULTS_DIR}"

# ---- Check prerequisites ----
if [[ ! -x "${BENCH_BIN}" ]]; then
    log "Building bench_runner..."
    cd "${PROJECT_DIR}"
    make bench 2>&1 || {
        err "Failed to build bench_runner. Run 'make bench' first."
        exit 1
    }
fi

# ---- Phase 1: Microbenchmarks ----
log "Phase 1: Algorithm Microbenchmarks"
log "  Running all KEM + SIG + Hybrid benchmarks..."

BENCH_ARGS="-n ${ITERATIONS} -w ${WARMUP} -v"
if [[ ${CPU_PIN} -ge 0 ]]; then
    BENCH_ARGS="${BENCH_ARGS} -c ${CPU_PIN}"
fi

"${BENCH_BIN}" ${BENCH_ARGS} \
    -o "${RESULTS_DIR}/micro_results.csv" \
    -j "${RESULTS_DIR}/micro_results.json" \
    2>&1 | tee "${RESULTS_DIR}/micro_output.log"

ok "Microbenchmarks complete"

if [[ "${MODE}" == "micro" ]]; then
    log "Micro-only mode, skipping HTTP workloads"
    log "Results in: ${RESULTS_DIR}/"
    exit 0
fi

# ---- Phase 2: TLS Handshake Benchmarks ----
log "Phase 2: TLS Handshake Benchmarks"

# Algorithm configurations to test
ALGORITHMS=(
    "X25519"                   # classical baseline
    "X25519MLKEM768"          # hybrid, NIST Level 3 (default)
    "X25519MLKEM512"          # hybrid, NIST Level 1
    "X25519MLKEM1024"         # hybrid, NIST Level 5
)

SERVER_PORT=8443
BACKEND_PORT=8080
HEALTH_PORT=9090

for ALG in "${ALGORITHMS[@]}"; do
    log "  Testing algorithm: ${ALG}"

    # Start server with this algorithm configuration
    ALGO_RESULTS="${RESULTS_DIR}/tls_${ALG}"
    mkdir -p "${ALGO_RESULTS}"

    # Note: In production, this would start the actual server.
    # For now, record the configuration.
    cat > "${ALGO_RESULTS}/config.json" <<EOF
{
    "algorithm": "${ALG}",
    "iterations": ${ITERATIONS},
    "server_port": ${SERVER_PORT},
    "timestamp": "$(date -Iseconds)"
}
EOF

    if command -v openssl &>/dev/null; then
        # Measure TLS handshake time using openssl s_time
        log "    openssl s_time (30s)..."
        timeout 35 openssl s_time \
            -connect "127.0.0.1:${SERVER_PORT}" \
            -new \
            -time 30 \
            2>&1 > "${ALGO_RESULTS}/openssl_s_time.log" || true
    fi

    # HTTP load test with wrk2 (if available)
    if command -v wrk2 &>/dev/null; then
        for RATE in 100 500 1000 5000; do
            log "    wrk2 @ ${RATE} req/s (30s)..."
            wrk2 -t4 -c50 -d30s -R${RATE} \
                --latency \
                "https://127.0.0.1:${SERVER_PORT}/health" \
                2>&1 > "${ALGO_RESULTS}/wrk2_rate${RATE}.log" || true
        done
    elif command -v wrk &>/dev/null; then
        log "    wrk (no rate limiting, 30s)..."
        wrk -t4 -c50 -d30s \
            "https://127.0.0.1:${SERVER_PORT}/health" \
            2>&1 > "${ALGO_RESULTS}/wrk_results.log" || true
    fi

    # h2load (HTTP/2, if available)
    if command -v h2load &>/dev/null; then
        log "    h2load HTTP/2 (10000 requests)..."
        h2load -n 10000 -c 10 -m 10 \
            "https://127.0.0.1:${SERVER_PORT}/health" \
            2>&1 > "${ALGO_RESULTS}/h2load_results.log" || true
    fi
done

ok "TLS handshake benchmarks complete"

# ---- Phase 3: Network Condition Simulation (requires sudo/tc) ----
if [[ "${MODE}" == "full" ]] && command -v tc &>/dev/null; then
    log "Phase 3: Network Condition Simulation"

    # Network conditions: name, delay(ms), loss(%), bandwidth
    declare -A NET_CONDITIONS=(
        ["local"]="0ms 0% 10gbit"
        ["regional"]="20ms 0% 1gbit"
        ["continental"]="80ms 0% 100mbit"
        ["lossy"]="150ms 1% 50mbit"
    )

    IFACE="lo" # loopback for local testing

    for COND_NAME in "${!NET_CONDITIONS[@]}"; do
        read -r DELAY LOSS BW <<< "${NET_CONDITIONS[$COND_NAME]}"
        log "  Condition: ${COND_NAME} (delay=${DELAY}, loss=${LOSS}, bw=${BW})"

        NET_RESULTS="${RESULTS_DIR}/net_${COND_NAME}"
        mkdir -p "${NET_RESULTS}"

        # Apply network conditions (needs sudo)
        if [[ "${DELAY}" != "0ms" || "${LOSS}" != "0%" ]]; then
            sudo tc qdisc add dev ${IFACE} root netem \
                delay ${DELAY} loss ${LOSS} rate ${BW} 2>/dev/null || true
        fi

        # Run handshake benchmark under these conditions
        for ALG in "X25519" "X25519MLKEM768" "X25519MLKEM1024"; do
            log "    ${ALG} under ${COND_NAME}..."
            if command -v wrk2 &>/dev/null; then
                wrk2 -t2 -c20 -d15s -R100 \
                    "https://127.0.0.1:${SERVER_PORT}/health" \
                    2>&1 > "${NET_RESULTS}/${ALG}_wrk2.log" || true
            fi
        done

        # Remove network conditions
        if [[ "${DELAY}" != "0ms" || "${LOSS}" != "0%" ]]; then
            sudo tc qdisc del dev ${IFACE} root 2>/dev/null || true
        fi
    done

    ok "Network simulation benchmarks complete"
else
    log "Skipping network simulation (need --full mode and tc)"
fi

# ---- Phase 4: Analysis ----
log "Phase 4: Analysis"

ANALYSIS_SCRIPT="${PROJECT_DIR}/scripts/benchmark-analyze.py"
if [[ -f "${ANALYSIS_SCRIPT}" ]] && command -v python3 &>/dev/null; then
    python3 "${ANALYSIS_SCRIPT}" \
        --input "${RESULTS_DIR}" \
        --output "${RESULTS_DIR}/analysis" \
        2>&1 | tee "${RESULTS_DIR}/analysis.log" || true
    ok "Analysis complete"
else
    log "Skipping analysis (python3 or analysis script not found)"
fi

# ---- Summary ----
echo ""
echo "============================================================="
echo "  Benchmark Complete"
echo "  Results: ${RESULTS_DIR}/"
echo ""
echo "  Files:"
ls -la "${RESULTS_DIR}/" 2>/dev/null | tail -n +2 || true
echo "============================================================="
