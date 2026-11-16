#!/usr/bin/env bash
# Clean-build the firmware with the given make variables, run one end-to-end
# DTLS session, and print the metrics in one block. Appends to
# results/bench_log.txt so every optimisation step is recorded.
#
# Run from macOS:
#   orb -m pqc bash <repo>/scripts/bench.sh "<label>" [make vars...]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BOOT="$ROOT/boot"
LABEL="$1"; shift

source "$HOME/litex-env/bin/activate"
# Let just-saved edits from macOS settle in the VM's view of the shared
# folder (a file read mid-update showed up as "unterminated comment").
sleep 2
( cd "$BOOT" && BUILD_DIR=../build/sim make -s clean >/dev/null 2>&1; rm -f certs.h )
bash "$HERE/sim.sh" fw "$@" > "$HERE/out/bench_build.log" 2>&1 \
    || { grep -E 'error' "$HERE/out/bench_build.log" | head; exit 1; }
read -r TEXT DATA BSS _ < <(riscv64-unknown-elf-size "$BOOT/boot.elf" | tail -1)
BIN=$(stat -c %s "$ROOT/boot.bin")

bash "$HERE/run_dtls.sh" 900 > "$HERE/out/bench_run.log" 2>&1
L=$(tr -d '\r' < "$HERE/out/sim_dtls.log")
cyc() { echo "$L" | grep -m1 -E "^ *$1 +[0-9]+ cycles" | sed -E 's/.* ([0-9]+) cycles.*/\1/'; }
HS=$(cyc handshake); WAIT=$(cyc "of which waiting on net"); SETUP=$(cyc "context setup")
TP=$(echo "$L" | grep -m1 throughput: | sed -E 's/.* -> ([0-9]+) cycles\/B.*/\1/')
HEAP=$(echo "$L" | grep -m1 '^heap:' | awk '{print $3}')
STK=$(echo "$L" | grep -m1 '^heap:' | awk '{print $(NF-1)}')
NET=$(echo "$L" | grep -m1 '^net:' | sed 's/^net: //')
OK=$(echo "$L" | grep -q 'client DONE' && echo OK || echo FAILED)

{
echo "== $(date '+%F %T')  $LABEL  [$*]  $OK"
printf "   handshake %s cyc (wait %s) | setup %s | bulk %s cyc/B | ROM bin %s B (text %s) | heap peak %s B | stack %s B\n" \
    "$HS" "$WAIT" "$SETUP" "$TP" "$BIN" "$TEXT" "$HEAP" "$STK"
echo "   net: $NET"
} | tee -a "$ROOT/results/bench_log.txt"
