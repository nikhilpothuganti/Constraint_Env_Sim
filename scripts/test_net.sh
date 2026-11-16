#!/usr/bin/env bash
# End-to-end network test: UDP echo server + packet capture + firmware in sim.
# Run from macOS:  orb -m pqc bash <repo>/scripts/test_net.sh [seconds]
# Outputs (in scripts/out/): sim.log, echo.log, net.pcap
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
OUT="$HERE/out"; mkdir -p "$OUT"
SECS="${1:-300}"

cleanup() {
    sudo pkill -f 'udp_echo.py' 2>/dev/null
    sudo pkill -x tcpdump 2>/dev/null
    sudo pkill -x Vsim 2>/dev/null
}
trap cleanup EXIT
cleanup

python3 "$HERE/udp_echo.py" 11111 > "$OUT/echo.log" 2>&1 &

# Capture on tap0 as soon as the simulator creates it.
( for _ in $(seq 1 600); do ip link show tap0 >/dev/null 2>&1 && break; sleep 0.5; done
  sudo tcpdump -i tap0 -U -w "$OUT/net.pcap" 2>/dev/null ) &

# Stop the sim once the firmware reports the test result (or on timeout).
timeout "$SECS" bash "$HERE/sim.sh" run < /dev/null > "$OUT/sim.log" 2>&1 &
SIM=$!
while kill -0 $SIM 2>/dev/null; do
    grep -qE '=== UDP echo test (PASSED|FAILED)' "$OUT/sim.log" && { sleep 1; break; }
    sleep 1
done

sed -n '/Executing booted program/,$p' "$OUT/sim.log" | grep -vE '^[0-9a-f]{64,}$'
echo "--- echo server ---"; cat "$OUT/echo.log"
sleep 1; sudo pkill -x tcpdump; sleep 1
echo "--- capture ---"; sudo tcpdump -nr "$OUT/net.pcap" 2>/dev/null | head -20
