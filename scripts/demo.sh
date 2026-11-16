#!/usr/bin/env bash
# End-to-end demo, run from macOS (for the demo video):
#   1. starts one complete session in the OrbStack VM (server + tcpdump +
#      LiteX/Verilator RISC-V simulation) via scripts/run_dtls.sh,
#   2. streams the device console live,
#   3. shows the server's view,
#   4. decrypts the captured DTLS 1.3 handshake with tshark + the exported
#      key log (needs Wireshark >= 4.4 on the Mac: brew install wireshark).
#
# usage: scripts/demo.sh [--build]     (--build: rebuild the release firmware first)
set -uo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$ROOT/scripts/out"
VM="${VM:-pqc}"
B=$'\e[1m'; C=$'\e[36m'; G=$'\e[32m'; Y=$'\e[33m'; N=$'\e[0m'
step() { printf "\n${B}${C}== %s ==${N}\n" "$*"; }

step "PQC DTLS 1.3 on a bare-metal RISC-V device (LiteX VexRiscv + Verilator)"
cat <<EOF
  key exchange    ML-KEM-512 (FIPS 203)
  authentication  ML-DSA-44 certificates on BOTH sides (mutual)
  records         TLS_CHACHA20_POLY1305_SHA256, DTLS 1.3 (RFC 9147)
  device          192.168.1.50 (simulated)  <->  server 192.168.1.100 (VM, tap0)
EOF

if [ "${1:-}" = "--build" ]; then
    step "Building release firmware"
    orb -m "$VM" bash -lc "bash '$ROOT/scripts/sim.sh' fw" | tail -2
fi
orb -m "$VM" bash -c "riscv64-unknown-elf-size '$ROOT/boot/boot.elf'" 2>/dev/null \
    | awk 'NR==2{printf "  firmware: %d B code+rodata, %d B data\n", $1, $2}'

step "Running one session (server, packet capture and simulator start in the VM)"
rm -f "$OUT/sim_dtls.log"
orb -m "$VM" bash "$ROOT/scripts/run_dtls.sh" 900 > "$OUT/demo_console.log" 2>&1 &
RUN=$!

# Stream the device console from the moment the firmware starts.
for _ in $(seq 1 240); do [ -s "$OUT/sim_dtls.log" ] && break; sleep 0.5; done
printf "${Y}(simulator booting; the device prints from here on)${N}\n"
# (polling instead of `tail -f`, which would outlive the run and hold the
# terminal's pipe open)
shown=0
show_new() {
    local lines
    lines=$(tr -d '\r' < "$OUT/sim_dtls.log" 2>/dev/null | sed -n '/=== PQC DTLS 1.3 client ===/,$p')
    local n; n=$(printf "%s\n" "$lines" | grep -c '')
    [ -n "$lines" ] && [ "$n" -gt "$shown" ] && printf "%s\n" "$lines" | tail -n +$((shown + 1)) && shown=$n
}
while kill -0 $RUN 2>/dev/null; do show_new; sleep 0.5; done
show_new

# The simulated SoC's nominal clock is 1 MHz, so the firmware's "ms" are at
# 1 MHz; restate the cycle counts at a realistic 100 MHz.
L=$(tr -d '\r' < "$OUT/sim_dtls.log")
cyc() { echo "$L" | grep -m1 -E "^ *$1 +[0-9]+ cycles" | sed -E 's/.* ([0-9]+) cycles.*/\1/'; }
HS=$(cyc handshake); SU=$(cyc 'context setup')
TP=$(echo "$L" | grep -m1 throughput: | sed -E 's/.* -> ([0-9]+) cycles\/B.*/\1/')
if [ -n "$HS" ] && [ -n "$SU" ] && [ -n "$TP" ]; then
    printf "${G}${B}  At 100 MHz: handshake %d ms, full session %d ms, throughput %d KB/s${N}\n" \
        $((HS / 100000)) $(((HS + SU) / 100000)) $((100000000 / TP / 1024))
fi

step "Server's view"
sed -n '/\[conn 0\]/p' "$OUT/server.log"

step "Decrypted DTLS 1.3 handshake on the wire (tshark + exported TLS secrets)"
if command -v tshark >/dev/null; then
    tshark -r "$OUT/dtls.pcap" -o tls.keylog_file:"$OUT/sslkeylog.log" -Y dtls \
        -T fields -e frame.number -e ip.src -e ip.dst -e udp.length -e _ws.col.Info 2>/dev/null \
      | awk -F'\t' '{printf "  %4s  %-13s -> %-13s %5s B  %s\n", $1, $2, $3, $4, $5}' | head -40
    printf "${G}  The device's own Certificate + CertificateVerify above = mutual authentication.${N}\n"
    echo "  (open $OUT/dtls.pcap in Wireshark with TLS key log $OUT/sslkeylog.log)"
else
    echo "  tshark not found (brew install wireshark); capture: $OUT/dtls.pcap"
fi
