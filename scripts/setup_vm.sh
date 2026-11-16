#!/usr/bin/env bash
# One-time setup of the LiteX + Verilator + RISC-V toolchain environment
# inside the OrbStack Ubuntu 24.04 (arm64) machine "pqc".
#
# Run from macOS:   orb -m pqc bash <repo>/scripts/setup_vm.sh
# Re-running is safe; finished steps are skipped or are no-ops.
set -euo pipefail

PROJ="$(cd "$(dirname "$0")/.." && pwd)"
REPO="$PROJ"
VENV="$HOME/litex-env"          # Linux-side venv (faster than the shared Mac FS)

echo "==> [1/3] System packages"
sudo apt-get update -qq
sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq \
    build-essential git python3 python3-venv python3-pip \
    verilator libevent-dev libjson-c-dev zlib1g-dev \
    gcc-riscv64-unknown-elf picolibc-riscv64-unknown-elf \
    meson ninja-build \
    iproute2 net-tools tcpdump tshark >/dev/null

echo "==> [2/3] Python venv at $VENV"
[ -d "$VENV" ] || python3 -m venv "$VENV"
# shellcheck disable=SC1091
source "$VENV/bin/activate"
pip install -q --upgrade pip
pip install -q meson ninja

echo "==> [3/3] LiteX (litex_setup.py --init --install), this clones many repos"
cd "$REPO"
python3 litex_setup.py --init --install

# The repo bundles LiteX 2025.08, but --init pulls the latest picolibc wrapper
# (June 2026), which moved libc.a out of newlib/ and breaks the LiteX libc
# Makefile ("cp: cannot stat 'newlib/libc.a'"). Pin it to the last version
# before the kit was made (2025-12-03), which is picolibc f165dc22 (Nov 2022).
( cd pythondata-software-picolibc && \
  git checkout -q "$(git rev-list -1 --before=2025-12-03 HEAD)" && \
  git submodule update -q --init --recursive )

# Same skew for the LiteX cores (e.g. latest liteeth calls stream.byte_count,
# which LiteX 2025.08 lacks). Pin every cloned core to the 2025.08 release.
for d in lite*/ valentyusb/; do
  d=${d%/}; [ "$d" = litex ] && continue; [ -e "$d/.git" ] || continue
  git -C "$d" rev-parse -q --verify refs/tags/2025.08 >/dev/null && \
    git -C "$d" checkout -q 2025.08
done

# Make the venv auto-activate in interactive shells.
grep -q 'litex-env/bin/activate' "$HOME/.bashrc" || \
    echo "source $VENV/bin/activate" >> "$HOME/.bashrc"

echo
echo "Setup done."
echo "  riscv gcc : $(riscv64-unknown-elf-gcc --version | head -1)"
echo "  verilator : $(verilator --version)"
echo "  litex_sim : $(command -v litex_sim)"
