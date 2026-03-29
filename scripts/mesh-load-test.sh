#!/usr/bin/env bash
# ============================================================================
#  PQ-TLS MESH LOAD TEST
# ============================================================================
#  Run from any WSL distro to load-test the PQ-TLS server.
#  All WSL2 distros share the same Linux VM — 127.0.0.1 works across distros.
#
#  Prerequisites: curl, awk, flock (coreutils)
#  Optional:      python3 (for JSON delta parsing — falls back to grep)
#
#  Usage:
#    bash mesh-load-test.sh [OPTIONS]
#
#  Options:
#    -t, --target HOST        Target IP/hostname      (default: 127.0.0.1)
#    -p, --port PORT          TLS port                (default: 8443)
#    -m, --mgmt PORT          Management API port     (default: 9090)
#    -c, --connections N      Concurrent connections  (default: 20)
#    -r, --requests N         Total requests/phase    (default: 200)
#    -d, --duration SECS      Sustained phase length  (default: 30)
#    --burst N                Burst size              (default: 50)
#    --ramp-step N            Ramp concurrency step   (default: 5)
#    --ramp-max N             Ramp max concurrency    (default: 40)
#    --nodes N                Simulated mesh nodes    (default: 4)
#    --phase PHASE            Run single phase (recon|burst|sustained|ramp|mesh)
#    -v, --verbose            Show individual request results
#    -h, --help               Show this help
# ============================================================================

# Do NOT use set -e — background jobs and arithmetic make it fragile.
# We handle errors explicitly where it matters.
set -uo pipefail

# ---- Defaults ----
TARGET="127.0.0.1"
PORT=8443
MGMT_PORT=9090
CONCURRENCY=20
TOTAL_REQUESTS=200
DURATION=30
BURST_SIZE=50
RAMP_STEP=5
RAMP_MAX=40
MESH_NODES=4
SINGLE_PHASE=""
VERBOSE=false

# ---- Colors ----
C=$'\033[36m'   # cyan
F=$'\033[35m'   # fuchsia
G=$'\033[32m'   # green
Y=$'\033[33m'   # amber
R=$'\033[31m'   # red
DM=$'\033[90m'  # dim
W=$'\033[97m'   # white
BD=$'\033[1m'   # bold
RS=$'\033[0m'   # reset

# ---- Parse args ----
while [[ $# -gt 0 ]]; do
    case "$1" in
        -t|--target)      TARGET="$2";         shift 2 ;;
        -p|--port)        PORT="$2";           shift 2 ;;
        -m|--mgmt)        MGMT_PORT="$2";      shift 2 ;;
        -c|--connections) CONCURRENCY="$2";    shift 2 ;;
        -r|--requests)    TOTAL_REQUESTS="$2"; shift 2 ;;
        -d|--duration)    DURATION="$2";       shift 2 ;;
        --burst)          BURST_SIZE="$2";     shift 2 ;;
        --ramp-step)      RAMP_STEP="$2";      shift 2 ;;
        --ramp-max)       RAMP_MAX="$2";       shift 2 ;;
        --nodes)          MESH_NODES="$2";     shift 2 ;;
        --phase)          SINGLE_PHASE="$2";   shift 2 ;;
        -v|--verbose)     VERBOSE=true;        shift ;;
        -h|--help)        sed -n '2,/^# ====/{/^# ====/d;s/^# //;p}' "$0"; exit 0 ;;
        *)                echo "Unknown option: $1"; exit 1 ;;
    esac
done

TLS_URL="https://${TARGET}:${PORT}"
MGMT_URL="http://${TARGET}:${MGMT_PORT}"

# ---- Check deps ----
for cmd in curl awk flock; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "${R}Missing dependency: $cmd${RS}"
        echo "Install with:  sudo pacman -S ${cmd}  (Arch)  or  sudo apt install ${cmd}"
        exit 1
    fi
done

# ---- Results directory ----
RESULTS_DIR="/tmp/pq-tls-loadtest-$$"
mkdir -p "$RESULTS_DIR"

# Initialize counter files
for f in total_sent total_ok total_fail total_pq total_classical latency_sum; do
    echo 0 > "$RESULTS_DIR/$f"
done
echo 999999 > "$RESULTS_DIR/latency_min"
echo 0 > "$RESULTS_DIR/latency_max"
: > "$RESULTS_DIR/latencies.log"

# ---- Cleanup on exit ----
cleanup() { rm -rf "$RESULTS_DIR" 2>/dev/null; }
trap cleanup EXIT

# ============================================================================
#  Atomic file helpers (flock-based, no bc dependency)
# ============================================================================

atomic_add() {
    local file="$1" val="$2"
    (
        flock 9
        local cur; cur=$(cat "$file" 2>/dev/null || echo 0)
        echo $(( cur + val )) > "$file"
    ) 9>"${file}.lk"
}

atomic_min() {
    local file="$1" val="$2"
    (
        flock 9
        local cur; cur=$(cat "$file" 2>/dev/null || echo 999999)
        if (( val < cur )); then echo "$val" > "$file"; fi
    ) 9>"${file}.lk"
}

atomic_max() {
    local file="$1" val="$2"
    (
        flock 9
        local cur; cur=$(cat "$file" 2>/dev/null || echo 0)
        if (( val > cur )); then echo "$val" > "$file"; fi
    ) 9>"${file}.lk"
}

# ============================================================================
#  Output helpers
# ============================================================================

banner() {
    echo ""
    echo -e "${DM}┌──────────────────────────────────────────────────────────────┐${RS}"
    echo -e "${DM}│${RS} ${C}${BD}$1${RS}"
    echo -e "${DM}└──────────────────────────────────────────────────────────────┘${RS}"
}

hud_line() { printf "  ${DM}├─${RS} %-28s ${3:-$C}%s${RS}\n" "$1" "$2"; }
hud_ok()   { echo -e "  ${G}[OK]${RS}   $1"; }
hud_warn() { echo -e "  ${Y}[WARN]${RS} $1"; }
hud_fail() { echo -e "  ${R}[FAIL]${RS} $1"; }
hud_info() { echo -e "  ${C}[INFO]${RS} $1"; }

progress_bar() {
    local cur="$1" total="$2" label="${3:-}"
    local w=40 pct=0 filled=0 empty=$w
    if (( total > 0 )); then
        pct=$(( cur * 100 / total ))
        filled=$(( cur * w / total ))
        (( filled > w )) && filled=$w
        empty=$(( w - filled ))
    fi
    # Build bar with simple chars (works everywhere)
    local bar_f="" bar_e=""
    local i
    for (( i=0; i<filled; i++ )); do bar_f+="#"; done
    for (( i=0; i<empty;  i++ )); do bar_e+="."; done
    printf "\r  ${DM}[${RS}${C}%s${DM}%s${RS}${DM}]${RS} ${W}%3d%%${RS} %s  " \
        "$bar_f" "$bar_e" "$pct" "$label"
}

# ============================================================================
#  JSON field extractor (no python3 dependency)
# ============================================================================

json_int() {
    # Extract integer value for a key from a JSON string
    # Usage: json_int '{"foo":42}' foo  →  42
    local json="$1" key="$2"
    echo "$json" | grep -o "\"${key}\"[[:space:]]*:[[:space:]]*[0-9]*" | grep -o '[0-9]*$' || echo 0
}

# ============================================================================
#  Core request function
# ============================================================================

fire_request() {
    local url="$1" timeout="${2:-5}" tag="${3:-req}"

    # curl -w outputs the format string even on failure (http_code=000).
    # Capture -w output separately — do NOT use || echo fallback.
    local raw
    raw=$(curl -sk -o /dev/null \
        -w '%{http_code} %{time_total} %{ssl_version}/%{ssl_cipher}' \
        --connect-timeout "$timeout" --max-time "$((timeout + 5))" \
        "$url" 2>/dev/null) || true

    local code time_s ssl_info
    code=$(echo "$raw" | awk '{print $1}')
    time_s=$(echo "$raw" | awk '{print $2}')
    ssl_info=$(echo "$raw" | awk '{print $3}')

    # Fallbacks for empty values
    [[ -z "$code" ]]   && code="000"
    [[ -z "$time_s" ]] && time_s="0"

    # Convert seconds → integer milliseconds using awk (no bc needed)
    local latency_ms
    latency_ms=$(awk "BEGIN{printf \"%d\", ${time_s} * 1000}" 2>/dev/null || echo 0)
    [[ -z "$latency_ms" || "$latency_ms" == "" ]] && latency_ms=0

    atomic_add "$RESULTS_DIR/total_sent" 1

    if [[ "$code" =~ ^[23][0-9][0-9]$ ]]; then
        atomic_add "$RESULTS_DIR/total_ok" 1
    else
        atomic_add "$RESULTS_DIR/total_fail" 1
    fi

    # Track latency (only for successful requests — failed ones skew stats)
    if [[ "$code" =~ ^[23][0-9][0-9]$ ]] && (( latency_ms > 0 )); then
        echo "$latency_ms" >> "$RESULTS_DIR/latencies.log"
        atomic_add "$RESULTS_DIR/latency_sum" "$latency_ms"
        atomic_min "$RESULTS_DIR/latency_min" "$latency_ms"
        atomic_max "$RESULTS_DIR/latency_max" "$latency_ms"
    fi

    # PQ detection from cipher string
    if echo "$ssl_info" | grep -qi "mlkem\|kyber\|X25519MLKEM"; then
        atomic_add "$RESULTS_DIR/total_pq" 1
    else
        atomic_add "$RESULTS_DIR/total_classical" 1
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        if [[ "$code" =~ ^[23] ]]; then
            echo -e "    ${DM}${tag}${RS} ${G}${code}${RS} ${DM}${latency_ms}ms ${ssl_info}${RS}"
        else
            echo -e "    ${DM}${tag}${RS} ${R}${code}${RS} ${DM}${latency_ms}ms${RS}"
        fi
    fi
}

fire_batch() {
    local url="$1" count="$2" conc="$3" tag="${4:-batch}"
    local launched=0

    while (( launched < count )); do
        local batch_end=$(( launched + conc ))
        (( batch_end > count )) && batch_end=$count

        local pids=()
        local i
        for (( i=launched; i<batch_end; i++ )); do
            fire_request "$url" 5 "${tag}-${i}" &
            pids+=($!)
        done

        # Wait for this wave
        local p
        for p in "${pids[@]}"; do
            wait "$p" 2>/dev/null || true
        done

        launched=$batch_end

        if [[ "$VERBOSE" != "true" ]]; then
            progress_bar "$launched" "$count" "$tag"
        fi
    done

    [[ "$VERBOSE" != "true" ]] && echo ""
}

# ============================================================================
#  Snapshot: pull metrics from management API
# ============================================================================

snapshot_stats() {
    local label="$1"
    curl -s --connect-timeout 3 "${MGMT_URL}/api/stats" 2>/dev/null \
        > "$RESULTS_DIR/snap_${label}.json" || echo '{}' > "$RESULTS_DIR/snap_${label}.json"
}

print_server_delta() {
    local bf="$RESULTS_DIR/snap_$1.json"
    local af="$RESULTS_DIR/snap_$2.json"
    [[ ! -s "$bf" || ! -s "$af" ]] && return

    local bj aj
    bj=$(cat "$bf"); aj=$(cat "$af")

    local d_total=$(( $(json_int "$aj" total_connections) - $(json_int "$bj" total_connections) ))
    local d_pq=$((    $(json_int "$aj" pq_negotiations)   - $(json_int "$bj" pq_negotiations)   ))
    local d_cl=$((    $(json_int "$aj" classical_negotiations) - $(json_int "$bj" classical_negotiations) ))
    local d_hs=$((    $(json_int "$aj" handshake_failures)     - $(json_int "$bj" handshake_failures)     ))

    echo ""
    echo -e "  ${DM}── Server-Side Delta ($1 → $2) ──${RS}"
    hud_line "Connections processed" "+${d_total}" "$C"
    hud_line "PQ handshakes"        "+${d_pq}"    "$F"
    hud_line "Classical handshakes"  "+${d_cl}"    "$Y"
    local hs_color="$G"; (( d_hs > 0 )) && hs_color="$R"
    hud_line "Handshake failures"    "+${d_hs}"    "$hs_color"
}

# ============================================================================
#  PHASE 1: Reconnaissance
# ============================================================================

phase_recon() {
    banner "PHASE 1 ── RECONNAISSANCE"
    echo ""

    hud_line "Target"  "${TLS_URL}"
    hud_line "Mgmt"    "${MGMT_URL}"
    hud_line "Distro"  "$(. /etc/os-release 2>/dev/null && echo "${PRETTY_NAME:-unknown}" || echo 'unknown')"
    hud_line "Kernel"  "$(uname -r)"
    hud_line "Host"    "$(cat /etc/hostname 2>/dev/null || echo "${HOSTNAME:-$(uname -n)}")"
    echo ""

    # ---- TLS connectivity (retry up to 5 times) ----
    hud_info "Testing TLS connectivity..."
    local code="" attempt
    for attempt in 1 2 3 4 5; do
        # Capture ONLY the -w output; do NOT use || echo (curl -w prints even on failure)
        code=$(curl -sk -o /dev/null -w '%{http_code}' \
            --connect-timeout 3 --max-time 6 "${TLS_URL}/" 2>/dev/null) || true
        code="${code:-000}"
        if [[ "$code" =~ ^[23][0-9][0-9]$ ]]; then
            break
        fi
        if (( attempt < 5 )); then
            echo -e "    ${DM}attempt $attempt/5 got HTTP ${code} — retry in 3s...${RS}"
            sleep 3
        fi
    done

    if [[ "$code" =~ ^[23][0-9][0-9]$ ]]; then
        hud_ok "TLS port reachable  (HTTP $code)"
    else
        hud_fail "Cannot reach ${TLS_URL}  (HTTP ${code})"
        echo ""
        echo -e "  ${Y}The server must be running FIRST.${RS}"
        echo -e "  ${W}  Terminal 1:  bash /mnt/c/Users/vamsh/Desktop/pq-tls-server/scripts/build-and-run.sh${RS}"
        echo -e "  ${DM}  Wait for \"PQ-TLS Server is LIVE!\" then re-run this test in Terminal 2.${RS}"
        echo ""
        echo -e "  ${DM}All WSL2 distros share 127.0.0.1 — no port-forwarding needed.${RS}"
        exit 1
    fi

    # ---- Management API ----
    hud_info "Testing management API..."
    local health
    health=$(curl -s --connect-timeout 3 "${MGMT_URL}/health" 2>/dev/null) || true
    if echo "$health" | grep -q '"ok"' 2>/dev/null; then
        hud_ok "Management API healthy"
    else
        hud_warn "Management API not reachable — server-side deltas will be empty"
    fi

    # ---- TLS cipher probe ----
    hud_info "Probing TLS handshake..."
    local cipher_info
    cipher_info=$(curl -sk -o /dev/null \
        -w '%{ssl_version} | %{ssl_cipher}' \
        --connect-timeout 5 "${TLS_URL}/" 2>/dev/null) || true
    hud_line "Negotiated" "${cipher_info:-unknown}" "$G"

    # ---- Baseline snapshot ----
    snapshot_stats "baseline"
    hud_ok "Baseline captured"
}

# ============================================================================
#  PHASE 2: Burst
# ============================================================================

phase_burst() {
    banner "PHASE 2 ── BURST TEST  [${BURST_SIZE} simultaneous]"
    echo ""

    snapshot_stats "burst_pre"
    hud_info "Firing ${BURST_SIZE} requests at once..."

    local t0; t0=$(date +%s)
    fire_batch "${TLS_URL}/" "$BURST_SIZE" "$BURST_SIZE" "burst"
    local t1; t1=$(date +%s)
    local elapsed=$(( t1 - t0 ))

    snapshot_stats "burst_post"

    local ok; ok=$(cat "$RESULTS_DIR/total_ok")
    local fail; fail=$(cat "$RESULTS_DIR/total_fail")

    hud_line "Time"          "${elapsed}s"    "$C"
    hud_line "Success / Fail" "${ok} / ${fail}" "$G"

    if (( fail > 0 )); then
        hud_warn "${fail} requests failed under burst"
    else
        hud_ok "Zero failures"
    fi

    print_server_delta "burst_pre" "burst_post"
}

# ============================================================================
#  PHASE 3: Sustained Load
# ============================================================================

phase_sustained() {
    banner "PHASE 3 ── SUSTAINED LOAD  [${CONCURRENCY} conc x ${DURATION}s]"
    echo ""

    snapshot_stats "sust_pre"
    hud_info "Running for ${DURATION}s at concurrency ${CONCURRENCY}..."

    local phase_ok_start; phase_ok_start=$(cat "$RESULTS_DIR/total_ok")
    local deadline=$(( $(date +%s) + DURATION ))
    local wave=0

    while true; do
        local now; now=$(date +%s)
        (( now >= deadline )) && break
        wave=$((wave + 1))

        # Fire one wave
        local pids=() i
        for (( i=0; i<CONCURRENCY; i++ )); do
            fire_request "${TLS_URL}/" 5 "sust-w${wave}" &
            pids+=($!)
        done
        for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

        # Update progress
        local elapsed=$(( $(date +%s) - (deadline - DURATION) ))
        (( elapsed > DURATION )) && elapsed=$DURATION
        if [[ "$VERBOSE" != "true" ]]; then
            progress_bar "$elapsed" "$DURATION" "wave ${wave}"
        fi
    done
    [[ "$VERBOSE" != "true" ]] && echo ""

    snapshot_stats "sust_post"

    local phase_ok_end; phase_ok_end=$(cat "$RESULTS_DIR/total_ok")
    local phase_reqs=$(( phase_ok_end - phase_ok_start ))
    local rps=0; (( DURATION > 0 )) && rps=$(( phase_reqs / DURATION ))

    hud_line "Successful requests" "$phase_reqs"       "$C"
    hud_line "Throughput"          "~${rps} req/s"     "$G"
    hud_line "Waves"               "$wave"             "$DM"

    print_server_delta "sust_pre" "sust_post"
}

# ============================================================================
#  PHASE 4: Ramp-Up
# ============================================================================

phase_ramp() {
    banner "PHASE 4 ── RAMP-UP  [${RAMP_STEP} -> ${RAMP_MAX} concurrency]"
    echo ""

    snapshot_stats "ramp_pre"

    local batch_per_level=30 level=$RAMP_STEP

    printf "  ${DM}%-6s %-7s %-7s %-8s${RS}\n" "CONC" "OK" "FAIL" "AVG(ms)"
    printf "  ${DM}%-6s %-7s %-7s %-8s${RS}\n" "----" "-----" "-----" "-------"

    while (( level <= RAMP_MAX )); do
        local ok0; ok0=$(cat "$RESULTS_DIR/total_ok")
        local fl0; fl0=$(cat "$RESULTS_DIR/total_fail")
        local lt0; lt0=$(cat "$RESULTS_DIR/latency_sum")

        fire_batch "${TLS_URL}/" "$batch_per_level" "$level" "ramp-${level}" 2>/dev/null

        local ok1; ok1=$(cat "$RESULTS_DIR/total_ok")
        local fl1; fl1=$(cat "$RESULTS_DIR/total_fail")
        local lt1; lt1=$(cat "$RESULTS_DIR/latency_sum")

        local lv_ok=$(( ok1 - ok0 ))
        local lv_fail=$(( fl1 - fl0 ))
        local lv_lat=$(( lt1 - lt0 ))
        local lv_total=$(( lv_ok + lv_fail ))
        local lv_avg=0; (( lv_total > 0 )) && lv_avg=$(( lv_lat / lv_total ))

        local fc="$G"; (( lv_fail > 0 )) && fc="$R"

        printf "  %-6s ${G}%-7s${RS} ${fc}%-7s${RS} ${C}%-8s${RS}\n" \
            "$level" "$lv_ok" "$lv_fail" "$lv_avg"

        level=$(( level + RAMP_STEP ))
    done

    snapshot_stats "ramp_post"
    print_server_delta "ramp_pre" "ramp_post"
}

# ============================================================================
#  PHASE 5: Mesh Simulation
# ============================================================================

phase_mesh() {
    banner "PHASE 5 ── MESH SIMULATION  [${MESH_NODES} nodes]"
    echo ""

    hud_info "${MESH_NODES} nodes, each with a different traffic pattern"
    echo ""

    snapshot_stats "mesh_pre"

    local requests_per_node=$(( TOTAL_REQUESTS / MESH_NODES ))
    (( requests_per_node < 1 )) && requests_per_node=1

    local node_pids=()
    local n
    for (( n=1; n<=MESH_NODES; n++ )); do
        (
            local tag="NODE-$(printf '%02d' "$n")"
            local conc delay
            case $(( (n - 1) % 4 )) in
                0) conc=5;                     delay=0 ;;  # steady
                1) conc=$requests_per_node;    delay=0 ;;  # burst
                2) conc=2;                     delay=1 ;;  # trickle
                3) conc=10;                    delay=0 ;;  # mixed
            esac

            local sent=0
            while (( sent < requests_per_node )); do
                local batch=$conc
                (( sent + batch > requests_per_node )) && batch=$(( requests_per_node - sent ))

                local pids=() j
                for (( j=0; j<batch; j++ )); do
                    fire_request "${TLS_URL}/" 5 "$tag" &
                    pids+=($!)
                done
                for p in "${pids[@]}"; do wait "$p" 2>/dev/null || true; done

                sent=$(( sent + batch ))
                (( delay > 0 )) && sleep "$delay"
            done
        ) &
        node_pids+=($!)
    done

    # Wait with live counter
    while true; do
        local alive=0
        for p in "${node_pids[@]}"; do
            kill -0 "$p" 2>/dev/null && alive=$((alive + 1))
        done
        (( alive == 0 )) && break
        local sent_now; sent_now=$(cat "$RESULTS_DIR/total_sent" 2>/dev/null || echo 0)
        printf "\r  ${DM}[MESH]${RS} ${C}%d${RS} nodes active | ${W}%d${RS} requests sent  " "$alive" "$sent_now"
        sleep 0.5
    done
    for p in "${node_pids[@]}"; do wait "$p" 2>/dev/null || true; done
    echo ""

    snapshot_stats "mesh_post"
    hud_ok "All ${MESH_NODES} mesh nodes completed"
    print_server_delta "mesh_pre" "mesh_post"
}

# ============================================================================
#  Final Report
# ============================================================================

phase_report() {
    banner "FINAL REPORT"
    echo ""

    local total_sent; total_sent=$(cat "$RESULTS_DIR/total_sent")
    local total_ok;   total_ok=$(cat "$RESULTS_DIR/total_ok")
    local total_fail; total_fail=$(cat "$RESULTS_DIR/total_fail")
    local total_pq;   total_pq=$(cat "$RESULTS_DIR/total_pq")
    local total_cl;   total_cl=$(cat "$RESULTS_DIR/total_classical")

    # Latency percentiles
    local lat_min lat_max lat_avg p50 p95 p99
    lat_min=$(cat "$RESULTS_DIR/latency_min"); lat_max=$(cat "$RESULTS_DIR/latency_max")
    lat_avg=0; p50=0; p95=0; p99=0

    if [[ -s "$RESULTS_DIR/latencies.log" ]]; then
        local cnt; cnt=$(wc -l < "$RESULTS_DIR/latencies.log" | tr -d ' ')
        if (( cnt > 0 )); then
            local lsum; lsum=$(cat "$RESULTS_DIR/latency_sum")
            lat_avg=$(( lsum / cnt ))

            local sorted; sorted=$(sort -n "$RESULTS_DIR/latencies.log")
            p50=$(echo "$sorted" | awk -v n="$cnt" 'NR==int(n*0.50)+1{print;exit}')
            p95=$(echo "$sorted" | awk -v n="$cnt" 'NR==int(n*0.95)+1{print;exit}')
            p99=$(echo "$sorted" | awk -v n="$cnt" 'NR==int(n*0.99)+1{print;exit}')
        fi
    fi
    # Guard against empty percentiles
    : "${p50:=0}" "${p95:=0}" "${p99:=0}"
    # If no successful requests, min is meaningless
    (( lat_min > 999000 )) && lat_min=0

    local success_rate=0; (( total_sent > 0 )) && success_rate=$(( total_ok * 100 / total_sent ))
    local pq_rate=0; local nego=$(( total_pq + total_cl ))
    (( nego > 0 )) && pq_rate=$(( total_pq * 100 / nego ))

    echo -e "  ${DM}+------------------------------------------------------+${RS}"
    echo -e "  ${DM}|${RS}  ${C}${BD}PQ-TLS LOAD TEST RESULTS${RS}                              ${DM}|${RS}"
    echo -e "  ${DM}+------------------------------------------------------+${RS}"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    printf   "  ${DM}|${RS}  %-24s ${W}%-29s${RS}${DM}|${RS}\n" "Total Requests" "$total_sent"
    printf   "  ${DM}|${RS}  %-24s ${G}%-29s${RS}${DM}|${RS}\n" "Successful"     "${total_ok} (${success_rate}%)"
    printf   "  ${DM}|${RS}  %-24s ${R}%-29s${RS}${DM}|${RS}\n" "Failed"         "$total_fail"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    echo -e "  ${DM}+------------------------------------------------------+${RS}"
    echo -e "  ${DM}|${RS}  ${F}${BD}TLS NEGOTIATION${RS}                                        ${DM}|${RS}"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    printf   "  ${DM}|${RS}  %-24s ${F}%-29s${RS}${DM}|${RS}\n" "PQ Handshakes"        "$total_pq"
    printf   "  ${DM}|${RS}  %-24s ${Y}%-29s${RS}${DM}|${RS}\n" "Classical Handshakes"  "$total_cl"
    printf   "  ${DM}|${RS}  %-24s ${F}%-29s${RS}${DM}|${RS}\n" "PQ Adoption Rate"     "${pq_rate}%"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    echo -e "  ${DM}+------------------------------------------------------+${RS}"
    echo -e "  ${DM}|${RS}  ${C}${BD}LATENCY (successful requests only)${RS}                    ${DM}|${RS}"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    printf   "  ${DM}|${RS}  %-24s ${C}%-29s${RS}${DM}|${RS}\n" "Min"  "${lat_min}ms"
    printf   "  ${DM}|${RS}  %-24s ${C}%-29s${RS}${DM}|${RS}\n" "Avg"  "${lat_avg}ms"
    printf   "  ${DM}|${RS}  %-24s ${C}%-29s${RS}${DM}|${RS}\n" "P50"  "${p50}ms"
    printf   "  ${DM}|${RS}  %-24s ${Y}%-29s${RS}${DM}|${RS}\n" "P95"  "${p95}ms"
    printf   "  ${DM}|${RS}  %-24s ${R}%-29s${RS}${DM}|${RS}\n" "P99"  "${p99}ms"
    printf   "  ${DM}|${RS}  %-24s ${R}%-29s${RS}${DM}|${RS}\n" "Max"  "${lat_max}ms"
    echo -e "  ${DM}|${RS}                                                        ${DM}|${RS}"
    echo -e "  ${DM}+------------------------------------------------------+${RS}"

    # Server-side totals
    snapshot_stats "final"
    print_server_delta "baseline" "final"

    # Verdict
    echo ""
    if (( success_rate >= 99 )); then
        echo -e "  ${G}${BD}VERDICT: EXCELLENT${RS} — ${success_rate}% success rate"
    elif (( success_rate >= 95 )); then
        echo -e "  ${Y}${BD}VERDICT: GOOD${RS} — ${success_rate}% success, minor drops under heavy load"
    elif (( success_rate >= 80 )); then
        echo -e "  ${Y}${BD}VERDICT: FAIR${RS} — ${success_rate}% success, server strained"
    else
        echo -e "  ${R}${BD}VERDICT: DEGRADED${RS} — ${success_rate}% success"
    fi
    echo ""
}

# ============================================================================
#  Main
# ============================================================================

echo ""
echo -e "${C}${BD}  [ PQ-TLS ]  LOAD TEST${RS}"
echo -e "  ${DM}$(date '+%Y-%m-%d %H:%M:%S')${RS}"

if [[ -n "$SINGLE_PHASE" ]]; then
    case "$SINGLE_PHASE" in
        recon)     phase_recon ;;
        burst)     phase_recon; phase_burst;     phase_report ;;
        sustained) phase_recon; phase_sustained; phase_report ;;
        ramp)      phase_recon; phase_ramp;      phase_report ;;
        mesh)      phase_recon; phase_mesh;      phase_report ;;
        *)         echo "Unknown phase: $SINGLE_PHASE"; exit 1 ;;
    esac
else
    phase_recon
    phase_burst
    phase_sustained
    phase_ramp
    phase_mesh
    phase_report
fi

echo -e "  ${DM}Done.${RS}"
echo ""
