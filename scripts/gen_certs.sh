#!/usr/bin/env bash
# Generate an ML-DSA PKI for mutual-auth DTLS 1.3:
#   ca     self-signed root (trusted by both sides)
#   server signed by ca, used by the host DTLS server
#   client signed by ca, embedded in the RISC-V firmware
#
# Needs OpenSSL >= 3.5 (built in the VM at ~/openssl35).
# Run from macOS:  orb -m pqc bash <repo>/scripts/gen_certs.sh [44|65|87]
set -euo pipefail

LEVEL="${1:-44}"
ALG="ML-DSA-$LEVEL"
OUT="$(cd "$(dirname "$0")/.." && pwd)/certs/mldsa$LEVEL"
DAYS=3650

export LD_LIBRARY_PATH="$HOME/openssl35/lib"
OSSL="$HOME/openssl35/bin/openssl"

mkdir -p "$OUT"; cd "$OUT"

key() { "$OSSL" genpkey -algorithm "$ALG" -out "$1-key.pem"; }

# Root CA
key ca
"$OSSL" req -x509 -new -key ca-key.pem -out ca-cert.pem -days $DAYS \
    -subj "/O=PQC-DTLS Test/CN=PQC-DTLS Test CA $ALG" \
    -addext "basicConstraints=critical,CA:TRUE" \
    -addext "keyUsage=critical,keyCertSign,cRLSign"

# Leaf certificates: name, CN, extendedKeyUsage
leaf() {
    key "$1"
    "$OSSL" req -new -key "$1-key.pem" -out "$1.csr" -subj "/O=PQC-DTLS Test/CN=$2"
    "$OSSL" x509 -req -in "$1.csr" -CA ca-cert.pem -CAkey ca-key.pem \
        -CAcreateserial -out "$1-cert.pem" -days $DAYS \
        -extfile <(printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n" "$3")
    rm -f "$1.csr"
}
leaf server "pqc-dtls-server"  serverAuth
leaf client "riscv-iot-device" clientAuth

# DER copies (what the firmware will embed: smaller, no base64 parsing).
for f in ca server client; do
    "$OSSL" x509 -in "$f-cert.pem" -outform DER -out "$f-cert.der"
    "$OSSL" pkey -in "$f-key.pem"  -outform DER -out "$f-key.der"
done
# Device key in expanded-only form (what the firmware embeds, see Makefile
# KEY_FILE): loads without re-running ML-DSA key generation from the seed.
"$OSSL" pkey -in client-key.pem -provparam ml-dsa.output_formats=priv-only \
    -outform DER -out client-key-priv.der

"$OSSL" verify -CAfile ca-cert.pem server-cert.pem client-cert.pem
echo "Sizes (bytes):"
ls -l *.der | awk '{printf "  %-16s %6d\n", $NF, $5}'
