#!/usr/bin/env bash
# End-to-end PQC DTLS 1.3 demo: host server + tap0 capture + RISC-V firmware.
# Run from macOS:
#   orb -m pqc bash <repo>/scripts/run_dtls.sh [timeout_s] [KEM] [mldsa_level]
# Outputs (scripts/out/): server.log, sim_dtls.log, dtls.pcap, sslkeylog.log
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
OUT="$HERE/out"; mkdir -p "$OUT"
SECS="${1:-1800}"
KEM="${2:-ML_KEM_512}"
LVL="${3:-44}"

cleanup() {
    sudo pkill -x dtls_server 2>/dev/null
    sudo pkill -x tcpdump 2>/dev/null
    sudo pkill -x Vsim 2>/dev/null
}
trap cleanup EXIT
cleanup

make -s -C "$ROOT/host" >/dev/null || exit 1

# Server's initial DTLS retransmission timer: 10 s of wall time by default.
# The simulator executes ~2M device cycles per wall-clock second, so the
# server (real time) would otherwise time out and resend whole flights while
# the device is still computing, distorting the device's measurements.
# Lost records are recovered by the device's gap ACK, not by this timer.
SERVER_ARGS="${SERVER_ARGS:--T 10}"

# Server (writes TLS secrets to sslkeylog.log for Wireshark decryption).
# wolfSSL (built with --enable-keylog-export) appends to ./sslkeylog.log.
( cd "$OUT" && rm -f sslkeylog.log &&
  stdbuf -oL "$ROOT/host/dtls_server" -n 1 -k "$KEM" -d "$ROOT/certs/mldsa$LVL" ${SERVER_ARGS:-} \
      > "$OUT/server.log" 2>&1 ) &

# Link model (NET_RATE, default 2mbit; "none" = raw tap). The simulated
# PHY otherwise delivers frames back to back at one byte per CPU cycle, far
# faster than any real link, and the LiteEth MAC (2 RX slots) drops the
# 3rd frame of a burst while the ISR is still copying the 1st (~5k cycles
# for a full frame from the uncached MAC buffer).
# Derivation of the default: real 100 Mbit/s Ethernet on a 100 MHz core is
# 8 CPU cycles per byte. The simulator runs ~2M cycles per wall second, so
# 8 cycles = 4 us of wall time, i.e. 250 kB/s = 2 Mbit/s on tap0 is the same
# link speed *in device cycles*. netem's rate serialises every packet by its
# length (no burst bucket), like a wire.
NET_RATE="${NET_RATE:-2mbit}"

# Capture on tap0 once the simulator has created it.
( for _ in $(seq 1 600); do ip link show tap0 >/dev/null 2>&1 && break; sleep 0.5; done
  # No IPv6 on the device link: the host's ICMPv6 multicast chatter
  # (router/MLD solicitations) would otherwise occupy the MAC's RX slots.
  sudo sysctl -qw net.ipv6.conf.tap0.disable_ipv6=1
  if [ "$NET_RATE" != none ]; then
      sudo tc qdisc replace dev tap0 root netem rate "$NET_RATE" limit 1000
  fi
  sudo tcpdump -i tap0 -U -w "$OUT/dtls.pcap" 2>/dev/null ) &

START=$(date +%s)
timeout "$SECS" bash "$HERE/sim.sh" run < /dev/null > "$OUT/sim_dtls.log" 2>&1 &
SIM=$!
while kill -0 $SIM 2>/dev/null; do
    # (also "firmware finished": profiler samples can split the DONE line)
    grep -qaE 'client (DONE|FAILED) ===|firmware finished' "$OUT/sim_dtls.log" && { sleep 2; break; }
    sleep 2
done
echo "wall time: $(( $(date +%s) - START )) s"

sed -n '/Executing booted program/,$p' "$OUT/sim_dtls.log"
echo "--- server ---"; cat "$OUT/server.log"
sleep 1; sudo pkill -x tcpdump; sleep 1
echo "--- capture: $(sudo tcpdump -nr "$OUT/dtls.pcap" udp 2>/dev/null | wc -l) UDP datagrams in $OUT/dtls.pcap ---"
