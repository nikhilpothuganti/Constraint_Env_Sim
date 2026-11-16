#!/usr/bin/env bash
# Build / run helpers for the LiteX + Verilator RISC-V simulation.
# Run from macOS:  orb -m pqc bash <repo>/scripts/sim.sh <cmd>
#
#   soc    regenerate the SoC + BIOS + Verilator model (needed once, or after changing SoC options)
#   fw [make vars]  build the firmware in boot/ -> boot.bin
#   run    boot boot.bin in the simulator (Ctrl+C to quit)
#   all    fw + run
set -euo pipefail

REPO="$(cd "$(dirname "$0")/.." && pwd)"
# shellcheck disable=SC1091
source "$HOME/litex-env/bin/activate"
cd "$REPO"

# Must stay identical between "soc" and "run". README values + simulated
# Ethernet: a tap0 interface in the VM. Device = 192.168.1.50, VM side =
# 192.168.1.100. LiteX runs the sim with sudo automatically when ethernet is on.
SIM_ARGS=(--csr-json csr.json --cpu-type=vexriscv --cpu-variant=full
          --integrated-main-ram-size=0x06400000
          --with-ethernet --local-ip=192.168.1.50 --remote-ip=192.168.1.100)

# litex_sim needs a TTY unless --non-interactive is given.
[ -t 0 ] || SIM_ARGS+=(--non-interactive)

case "${1:-all}" in
  soc) litex_sim "${SIM_ARGS[@]}" ;;
  # Same as the README's `litex_bare_metal_demo --build-path=build/sim`, but
  # stops on compile errors (the demo tool ignores them and keeps the old
  # boot.bin).
  # Extra args go to make, e.g. `sim.sh fw TRACE=1` or `sim.sh fw CERT_DIR=...`.
  fw)  shift; ( cd boot && BUILD_DIR=../build/sim make -j"$(nproc)" "$@" )
       cp boot/boot.bin ./boot.bin
       ls -l boot.bin ;;
  run) litex_sim "${SIM_ARGS[@]}" --ram-init=boot.bin ;;
  all) "$0" fw && "$0" run ;;
  *)   echo "usage: $0 {soc|fw|run|all}" >&2; exit 1 ;;
esac
