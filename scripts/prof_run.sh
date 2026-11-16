#!/usr/bin/env bash
# PROFILE=1 build + one run (server -T 10), then per-phase histograms.
# usage (VM): prof_run.sh [top N] [extra make vars...]
set -uo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
BOOT="$HERE/../boot"
TOP="${1:-25}"; shift || true
source "$HOME/litex-env/bin/activate"
# Let just-saved edits from macOS settle in the VM's view of the shared
# folder (a file read mid-update showed up as "unterminated comment").
sleep 2
( cd "$BOOT" && BUILD_DIR=../build/sim make -s clean >/dev/null 2>&1; rm -f certs.h )
bash "$HERE/sim.sh" fw PROFILE=1 PROFILE_PERIOD=50000 "$@" > "$HERE/out/prof_build.log" 2>&1 || exit 1
bash "$HERE/run_dtls.sh" 900 > "$HERE/out/prof_console.log" 2>&1
cd "$HERE/out"
tr -d '\r' < sim_dtls.log > prof_all.log
sed -n '/handshake: connecting/,/handshake OK/p' prof_all.log > prof_hs.log
sed -n '/=== PQC DTLS 1.3 client ===/,/handshake: connecting/p' prof_all.log > prof_setup.log
grep -E '^ *(context setup|handshake|  of which)' prof_all.log
echo "=== SETUP (50k cycles/sample)"; bash "$HERE/profile.sh" prof_setup.log "$BOOT/boot.elf" 10
echo "=== HANDSHAKE (50k cycles/sample)"; bash "$HERE/profile.sh" prof_hs.log "$BOOT/boot.elf" "$TOP"
