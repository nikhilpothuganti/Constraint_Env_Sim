#!/usr/bin/env bash
# Profile the crypto microbenchmark (BENCH=1 PROFILE=1) and print a histogram
# of the samples taken while the ML-DSA-44 signatures run.
#   orb -m pqc bash .../scripts/prof_bench.sh [top N] [make vars...]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOT="$HERE/../boot"
TOP="${1:-30}"; shift || true
source "$HOME/litex-env/bin/activate"
sleep 2
( cd "$BOOT" && BUILD_DIR=../build/sim make -s clean >/dev/null 2>&1; rm -f certs.h )
bash "$HERE/sim.sh" fw BENCH=1 PROFILE=1 PROFILE_PERIOD=20000 "$@" > "$HERE/out/bench_build.log" 2>&1 \
    || { grep error "$HERE/out/bench_build.log" | head; exit 1; }
sudo pkill -x Vsim 2>/dev/null
timeout 1500 bash "$HERE/sim.sh" run < /dev/null > "$HERE/out/sim_bench.log" 2>&1 &
SIM=$!
while kill -0 $SIM 2>/dev/null; do
    grep -qaE 'bench (DONE|FAILED)|firmware finished' "$HERE/out/sim_bench.log" && break
    sleep 2
done
sudo pkill -x Vsim 2>/dev/null
cd "$HERE/out"
tr -d '\r' < sim_bench.log > prof_bench_all.log
sed -n '/ML-DSA-44 keygen/,/ML-DSA-44 sign (min)/p' prof_bench_all.log > prof_sign.log
grep -aE 'ML-DSA' prof_bench_all.log | grep -v prof
bash "$HERE/profile.sh" prof_sign.log "$BOOT/boot.elf" "$TOP"
