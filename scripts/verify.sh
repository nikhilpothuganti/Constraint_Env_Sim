#!/usr/bin/env bash
# Verification suite: stability runs of the release firmware + negative
# authentication tests. Runs strictly one simulation at a time.
#
# Run from macOS:
#   orb -m pqc bash <repo>/scripts/verify.sh [stability_runs] [only_case]
# Needs certs/mldsa44 (gen_certs.sh 44) and certs/neg (gen_neg_certs.sh).
# Per-case logs/pcaps go to results/verify_<timestamp>/<case>/, plus summary.txt.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BOOT="$ROOT/boot"
RUNS="${1:-5}"
ONLY="${2:-}"
RES="$ROOT/results/verify_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RES"
SUMMARY="$RES/summary.txt"
FAILS=0

build() {   # build <make vars...>   (always rebuild credentials + client)
    rm -f "$BOOT/certs.h"; touch "$BOOT/dtls_client.c"
    bash "$HERE/sim.sh" fw "$@" > "$RES/last_build.log" 2>&1 \
        || { echo "BUILD FAILED ($*)"; tail -20 "$RES/last_build.log"; exit 1; }
}

# case <name> <expect: ok|reject> <server args>
run_case() {
    local name=$1 expect=$2 sargs=$3 dir="$RES/$1"
    [ -n "$ONLY" ] && [[ "$name" != $ONLY ]] && return
    mkdir -p "$dir"
    echo ">>> $name (expect $expect)"
    SERVER_ARGS="-T 10 $sargs" bash "$HERE/run_dtls.sh" 900 > "$dir/console.log" 2>&1
    cp "$HERE/out/"{sim_dtls.log,server.log,dtls.pcap} "$dir/" 2>/dev/null

    local dev srv verdict detail
    if   grep -q 'client DONE'   "$dir/sim_dtls.log"; then dev=ok
    elif grep -q 'client FAILED' "$dir/sim_dtls.log"; then dev=failed
    else dev=hang; fi
    grep -q 'handshake OK' "$dir/server.log" && srv=ok || srv=rejected
    if [ "$expect" = ok ]; then
        [ $dev = ok ] && [ $srv = ok ] && verdict=PASS || verdict=FAIL
        detail="hs=$(tr -d '\r' < "$dir/sim_dtls.log" | grep -m1 '^  handshake ' | awk '{print $2}') cycles"
    else
        # Must fail cleanly on both ends: no session, no hang.
        [ $dev = failed ] && [ $srv = rejected ] && verdict=PASS || verdict=FAIL
        detail="device: $(grep -m1 -E 'FAILED: ret' "$dir/sim_dtls.log" | sed 's/.*FAILED: //')"
        detail+=" | server: $(grep -m1 'handshake FAILED' "$dir/server.log" | sed 's/.*FAILED: //')"
    fi
    [ $verdict = PASS ] || FAILS=$((FAILS + 1))
    printf "%-4s %-22s device=%-6s server=%-8s wall=%-6s %s\n" "$verdict" "$name" "$dev" "$srv" \
        "$(grep -m1 'wall time' "$dir/console.log" | awk '{print $3}')s" "$detail" | tee -a "$SUMMARY"
}

CERTS="$ROOT/certs"
echo "results: $RES"

# 1. Release firmware, genuine credentials: must succeed every time.
build
cp "$BOOT/boot.bin" "$RES/boot_release.bin"
for i in $(seq 1 "$RUNS"); do run_case "stability_$i" ok ""; done

# 2. Device must reject bad servers (same firmware).
run_case reject_rogue_ca   reject "-d $CERTS/neg/rogue"
run_case reject_wrong_cn   reject "-d $CERTS/neg/wrongcn"
run_case reject_expired    reject "-d $CERTS/neg/expired"

# 3. Server must reject bad devices (firmware variants).
if [ -z "$ONLY" ] || [[ "rogue_client" == $ONLY ]]; then
    build CERT_DIR=../certs/neg/rogueclient
    run_case rogue_client  reject ""
fi
if [ -z "$ONLY" ] || [[ "no_client_cert" == $ONLY ]]; then
    build NOCLIENTCERT=1
    run_case no_client_cert reject ""
fi

# Leave the release firmware in place.
build
echo
echo "=== $( [ $FAILS -eq 0 ] && echo ALL PASSED || echo "$FAILS FAILED" ) ===" | tee -a "$SUMMARY"
echo "summary: $SUMMARY"
