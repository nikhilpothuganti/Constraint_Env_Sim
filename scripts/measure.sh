#!/usr/bin/env bash
# Measurement campaign for the report: build the release firmware once, run
# N complete DTLS sessions back to back (run_dtls.sh defaults: netem link
# model, server -T 10), and summarise every metric with median / mean / p90 /
# min / max. ML-DSA signing has a random number of rejection-loop attempts,
# so single runs are not representative.
#
# Run from macOS:
#   orb -m pqc bash <repo>/scripts/measure.sh [N=25] [make vars...]
# Output: results/measure_<timestamp>/{runs.csv,summary.txt,run_*/}
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
BOOT="$ROOT/boot"
N="${1:-25}"; shift || true
RES="$ROOT/results/measure_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$RES"

source "$HOME/litex-env/bin/activate"
sleep 2
( cd "$BOOT" && BUILD_DIR=../build/sim make -s clean >/dev/null 2>&1; rm -f certs.h )
bash "$HERE/sim.sh" fw "$@" > "$RES/build.log" 2>&1 || { tail -20 "$RES/build.log"; exit 1; }
cp "$ROOT/boot.bin" "$RES/boot.bin"
read -r TEXT DATA _ < <(riscv64-unknown-elf-size "$BOOT/boot.elf" | tail -1)
# (Berkeley "bss" also counts the reserved heap/stack regions; use .bss itself)
BSS=$(riscv64-unknown-elf-size -A "$BOOT/boot.elf" | awk '$1==".bss"{print $2}')
BIN=$(stat -c %s "$RES/boot.bin")

echo "run,ok,setup,handshake,wait,sign,verify,kem_keygen,kem_decaps,keccak,bulk_cyc_per_B,heap_peak,stack_peak,tx_pkts,rx_pkts,mac_drops" > "$RES/runs.csv"
for i in $(seq 1 "$N"); do
    bash "$HERE/run_dtls.sh" 900 > "$RES/console_$i.log" 2>&1
    L=$(tr -d '\r' < "$HERE/out/sim_dtls.log")
    mkdir -p "$RES/run_$i"; cp "$HERE/out/"{sim_dtls.log,server.log,dtls.pcap} "$RES/run_$i/" 2>/dev/null
    cyc() { echo "$L" | grep -m1 -E "^ *$1 +[0-9]+ cycles" | sed -E 's/.* ([0-9]+) cycles.*/\1/'; }
    ph()  { echo "$L" | grep -m1 -E "^ +$1 +[0-9]+ cycles" | awk '{for(i=1;i<=NF;i++) if($i=="cycles"){print $(i-1); exit}}'; }
    OK=$(echo "$L" | grep -q 'client DONE' && echo 1 || echo 0)
    TP=$(echo "$L" | grep -m1 throughput: | sed -E 's/.* -> ([0-9]+) cycles\/B.*/\1/')
    HEAP=$(echo "$L" | grep -m1 '^heap:' | awk '{print $3}')
    STK=$(echo "$L" | grep -m1 '^heap:' | awk '{print $(NF-1)}')
    KEC=$(echo "$L" | grep -m1 'Keccak-f\[1600\] calls' | awk '{print $NF}')
    NET=$(echo "$L" | grep -m1 '^net:')
    TX=$(echo "$NET" | sed -E 's/.*tx ([0-9]+) pkts.*/\1/'); RX=$(echo "$NET" | sed -E 's/.*rx ([0-9]+) pkts.*/\1/')
    MAC=$(echo "$NET" | sed -E 's/.* ([0-9]+) \(MAC\).*/\1/')
    echo "$i,$OK,$(cyc 'context setup'),$(cyc handshake),$(cyc 'of which waiting on net'),$(ph 'ML-DSA-44 sign'),$(ph 'ML-DSA-44 verify'),$(ph 'ML-KEM-512 keygen'),$(ph 'ML-KEM-512 decaps'),$KEC,$TP,$HEAP,$STK,$TX,$RX,$MAC" >> "$RES/runs.csv"
    echo "run $i/$N: $(tail -1 "$RES/runs.csv")"
done

python3 - "$RES" "$BIN" "$TEXT" "$DATA" "$BSS" <<'EOF'
import csv, statistics, sys
res, binsz, text, data, bss = sys.argv[1], *map(int, sys.argv[2:])
rows = [r for r in csv.DictReader(open(f"{res}/runs.csv"))]
ok = [r for r in rows if r["ok"] == "1"]
out = [f"runs: {len(rows)}, successful: {len(ok)}",
       f"ROM (boot.bin): {binsz} B  (.text+.rodata {text} B, .data {data} B), .bss {bss} B", ""]
def pct(v, p):
    v = sorted(v); k = (len(v) - 1) * p; f = int(k); c = min(f + 1, len(v) - 1)
    return v[f] + (v[c] - v[f]) * (k - f)
out.append(f"{'metric':<18}{'median':>12}{'mean':>12}{'p90':>12}{'min':>12}{'max':>12}")
for m in ["setup", "handshake", "wait", "sign", "verify", "kem_keygen", "kem_decaps",
          "keccak", "bulk_cyc_per_B", "heap_peak", "stack_peak", "tx_pkts", "rx_pkts", "mac_drops"]:
    v = [float(r[m]) for r in ok if r[m]]
    if not v: continue
    out.append(f"{m:<18}{statistics.median(v):>12.0f}{statistics.mean(v):>12.0f}"
               f"{pct(v, .9):>12.0f}{min(v):>12.0f}{max(v):>12.0f}")
hs = [float(r["handshake"]) + float(r["setup"]) for r in ok]
out.append(f"{'setup+handshake':<18}{statistics.median(hs):>12.0f}{statistics.mean(hs):>12.0f}"
           f"{pct(hs, .9):>12.0f}{min(hs):>12.0f}{max(hs):>12.0f}")
tp = statistics.median([float(r["bulk_cyc_per_B"]) for r in ok])
out += ["", "at 100 MHz (cycles / 100e6):",
        f"  handshake median {statistics.median([float(r['handshake']) for r in ok])/1e5:.1f} ms, "
        f"full session (setup+handshake) median {statistics.median(hs)/1e5:.1f} ms",
        f"  bulk throughput {100e6/tp/1024:.0f} KiB/s ({tp:.0f} cycles/B)"]
open(f"{res}/summary.txt", "w").write("\n".join(out) + "\n")
print("\n".join(out))
EOF
echo "results: $RES"
