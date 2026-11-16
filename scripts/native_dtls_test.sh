#!/usr/bin/env bash
# Reference PQC-DTLS 1.3 handshake between native wolfSSL example client and
# server (both on the VM, loopback). Pins down the config/certs before the
# client is ported to the RISC-V firmware.
#
#   DTLS 1.3, ML-KEM key exchange only, ML-DSA certs, mutual authentication
#   (the example server requires a client cert unless -d is given).
#
# Run from macOS:
#   orb -m pqc bash <repo>/scripts/native_dtls_test.sh [ML_KEM_512|ML_KEM_768|...] [44|65|87]
# Outputs (scripts/out/): native_server.log, native_client.log, native.pcap
set -uo pipefail

KEM="${1:-ML_KEM_512}"
LVL="${2:-44}"
HERE="$(cd "$(dirname "$0")" && pwd)"
C="$HERE/../certs/mldsa$LVL"
O="$HERE/out"; mkdir -p "$O"
W="$HOME/wolfssl"   # native wolfSSL 5.8.4 build (see README / setup notes)

[ -f "$C/ca-cert.pem" ] || bash "$HERE/gen_certs.sh" "$LVL"

sudo pkill -x tcpdump 2>/dev/null
sudo tcpdump -i lo -U -w "$O/native.pcap" udp port 11111 2>/dev/null &
sleep 1

cd "$W"
./examples/server/server -u -v 4 -p 11111 --pqc "$KEM" \
    -c "$C/server-cert.pem" -k "$C/server-key.pem" -A "$C/ca-cert.pem" \
    > "$O/native_server.log" 2>&1 &
SRV=$!
sleep 1
timeout 60 ./examples/client/client -u -v 4 -h 127.0.0.1 -p 11111 --pqc "$KEM" \
    -c "$C/client-cert.pem" -k "$C/client-key.pem" -A "$C/ca-cert.pem" \
    > "$O/native_client.log" 2>&1
RC=$?
wait $SRV 2>/dev/null
sleep 1; sudo pkill -x tcpdump

for f in client server; do
    echo "--- $f ---"
    grep -E '^SSL (version|cipher|curve)|^Peer sent|^Client message|^I hear' "$O/native_$f.log"
done
echo "--- wire (payload bytes per datagram) ---"
tshark -r "$O/native.pcap" -T fields -e udp.srcport -e udp.length 2>/dev/null |
  awk '{d=($1==11111)?"S->C":"C->S"; t[d]+=$2-8; n[d]++}
       END{for(k in t) printf "%s: %d datagrams, %d bytes\n",k,n[k],t[k]}'
[ $RC -eq 0 ] && echo "RESULT: handshake OK" || echo "RESULT: client exit $RC"
exit $RC
