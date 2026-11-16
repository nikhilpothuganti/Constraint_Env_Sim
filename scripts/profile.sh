#!/usr/bin/env bash
# Turn "[prof] pc=0x..." samples from a PROFILE=1 firmware log into a
# per-function histogram (each sample = PROFILE_PERIOD cycles).
# usage (in the VM): profile.sh <sim log> [elf] [top N]
set -euo pipefail
LOG="$1"
ELF="${2:-$(cd "$(dirname "$0")/../boot" && pwd)/boot.elf}"
TOP="${3:-30}"

grep -oE '\[prof\] pc=0x[0-9a-f]+' "$LOG" | sed 's/.*pc=//' > /tmp/prof_pcs.txt
N=$(wc -l < /tmp/prof_pcs.txt)
echo "$N samples"
riscv64-unknown-elf-addr2line -f -e "$ELF" < /tmp/prof_pcs.txt | awk 'NR%2==1' |
    sort | uniq -c | sort -rn | head -"$TOP" |
    awk -v n="$N" '{printf "%6d  %5.1f%%  %s\n", $1, 100*$1/n, $2}'
