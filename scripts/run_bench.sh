#!/usr/bin/env bash
# Clean-build the BENCH=1 firmware (plus any make vars) and print the crypto
# microbenchmarks. No network needed.
#   orb -m pqc bash <repo>/scripts/run_bench.sh [make vars...]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOT="$HERE/../boot"
source "$HOME/litex-env/bin/activate"
# Let just-saved edits from macOS settle in the VM's view of the shared
# folder (a file read mid-update showed up as "unterminated comment").
sleep 2
( cd "$BOOT" && BUILD_DIR=../build/sim make -s clean >/dev/null 2>&1; rm -f certs.h )
bash "$HERE/sim.sh" fw BENCH=1 "$@" > "$HERE/out/bench_build.log" 2>&1 \
    || { grep error "$HERE/out/bench_build.log" | head; exit 1; }
sudo pkill -x Vsim 2>/dev/null
timeout 1200 bash "$HERE/sim.sh" run < /dev/null > "$HERE/out/sim_bench.log" 2>&1 &
SIM=$!
while kill -0 $SIM 2>/dev/null; do
    grep -qE '=== bench (DONE|FAILED)' "$HERE/out/sim_bench.log" && break
    sleep 2
done
sudo pkill -x Vsim 2>/dev/null
tr -d '\r' < "$HERE/out/sim_bench.log" | sed -n '/=== crypto microbenchmarks/,/=== bench/p'
