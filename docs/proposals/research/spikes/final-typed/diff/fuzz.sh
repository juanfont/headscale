#!/usr/bin/env bash
# Runs every fuzz target for $1 (duration, e.g. 4m) against the final
# prototype, one after another, 6 workers each. Logs to results/fuzz-<target>.log.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
mkdir -p "$here/results"
for t in FuzzRun FuzzLeaf FuzzTab; do
  "$here/go.sh" go test -run XXX -fuzz "^$t\$" -fuzztime "$1" -parallel 6 . > "$here/results/fuzz-$t.log" 2>&1
  echo "$t: $(tail -4 "$here/results/fuzz-$t.log" | tr '\n' ' ')"
done
