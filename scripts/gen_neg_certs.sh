#!/usr/bin/env bash
# Credentials for the negative (must-fail) authentication tests, derived
# from the real ML-DSA-44 PKI in certs/mldsa44 (run gen_certs.sh 44 first).
#
#   certs/neg/rogue/        complete second PKI, same CNs, different CA
#                           -> device must reject this server (untrusted CA)
#   certs/neg/wrongcn/      server cert from the REAL CA but CN=evil-server
#                           -> device must reject (hostname check)
#   certs/neg/expired/      server cert from the REAL CA, expired in 2020
#                           -> device must reject (validity dates)
#   certs/neg/rogueclient/  real CA (to trust the server) + client cert/key
#                           from the rogue CA, embedded in a firmware variant
#                           -> SERVER must reject the device
#
# Run from macOS:  orb -m pqc bash <repo>/scripts/gen_neg_certs.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
REAL="$ROOT/certs/mldsa44"
NEG="$ROOT/certs/neg"
ALG=ML-DSA-44
export LD_LIBRARY_PATH="$HOME/openssl35/lib"
OSSL="$HOME/openssl35/bin/openssl"

[ -f "$REAL/ca-key.pem" ] || { echo "missing $REAL, run gen_certs.sh 44" >&2; exit 1; }
rm -rf "$NEG"; mkdir -p "$NEG"/{rogue,wrongcn,expired,rogueclient}

ext() { printf "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=%s\n" "$1"; }

# leaf <dir> <name> <CN> <eku> <ca-dir> [extra x509 args...]
leaf() {
    local d=$1 n=$2 cn=$3 eku=$4 ca=$5; shift 5
    "$OSSL" genpkey -algorithm $ALG -out "$d/$n-key.pem"
    "$OSSL" req -new -key "$d/$n-key.pem" -out "$d/$n.csr" -subj "/O=PQC-DTLS Test/CN=$cn"
    "$OSSL" x509 -req -in "$d/$n.csr" -CA "$ca/ca-cert.pem" -CAkey "$ca/ca-key.pem" \
        -CAcreateserial -out "$d/$n-cert.pem" -extfile <(ext "$eku") "$@"
    rm -f "$d/$n.csr"
}

# 1. Rogue PKI: a CA nobody trusts, issuing certs with the genuine names.
R="$NEG/rogue"
"$OSSL" genpkey -algorithm $ALG -out "$R/ca-key.pem"
"$OSSL" req -x509 -new -key "$R/ca-key.pem" -out "$R/ca-cert.pem" -days 3650 \
    -subj "/O=PQC-DTLS Test/CN=PQC-DTLS Test CA $ALG" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign"
leaf "$R" server pqc-dtls-server  serverAuth "$R" -days 3650
leaf "$R" client riscv-iot-device clientAuth "$R" -days 3650

# 2. Genuine CA, wrong server name. The server dir must also hold the real
#    CA so the server itself still trusts the (genuine) device.
leaf "$NEG/wrongcn" server evil-server serverAuth "$REAL" -days 3650
cp "$REAL/ca-cert.pem" "$NEG/wrongcn/"

# 3. Genuine CA and name, but expired.
leaf "$NEG/expired" server pqc-dtls-server serverAuth "$REAL" \
    -not_before 20190101000000Z -not_after 20200101000000Z
cp "$REAL/ca-cert.pem" "$NEG/expired/"

# 4. Firmware credentials: real CA, rogue client identity (DER, for der2c.py).
C="$NEG/rogueclient"
"$OSSL" x509 -in "$REAL/ca-cert.pem" -outform DER -out "$C/ca-cert.der"
"$OSSL" x509 -in "$REAL/server-cert.pem" -outform DER -out "$C/server-cert.der"
"$OSSL" x509 -in "$R/client-cert.pem" -outform DER -out "$C/client-cert.der"
"$OSSL" pkey -in "$R/client-key.pem" -outform DER -out "$C/client-key.der"
"$OSSL" pkey -in "$R/client-key.pem" -provparam ml-dsa.output_formats=priv-only \
    -outform DER -out "$C/client-key-priv.der"

rm -f "$REAL"/*.srl "$R"/*.srl
echo "--- expected verify failures against the real CA:"
"$OSSL" verify -CAfile "$REAL/ca-cert.pem" "$R/server-cert.pem" "$NEG/expired/server-cert.pem" 2>&1 | grep -iE 'error|OK' || true
"$OSSL" x509 -in "$NEG/wrongcn/server-cert.pem" -noout -subject
