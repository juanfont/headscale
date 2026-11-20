#!/usr/bin/env bash
# The runs behind differential.md. Run mode in one process; Tab in chunks of
# 125k lines, because cobra keeps every completion func in a package map.
set -eu
B="$1"
cd "$(dirname "$0")"
mkdir -p results/final
for g in delivered fixed; do
  "$B" -n 2000000 -seed 7 -grammar $g -crate 0.05 -out results/final/run-$g.md 2>/dev/null
  for k in 0 1 2 3 4 5 6 7; do
    "$B" -n 125000 -offset $((k*125000)) -seed 7 -mode tab -grammar $g -crate 0.05 -out results/final/tab-$g-$k.md 2>/dev/null
  done
done
echo all-done
