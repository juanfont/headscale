#!/usr/bin/env bash
# Runs every fuzz target for $1 (duration, e.g. 6m) against FUZZ_OWN=$2
# (delivered or fixed; fixed is the default), one after another, 6 workers each. Logs to results/fuzz-<own>-<target>.log.
set -u
here="$(cd "$(dirname "$0")" && pwd)"
for t in FuzzRun FuzzLeaf FuzzTab; do
  "$here/go.sh" env FUZZ_OWN="$2" go test -run XXX -fuzz "^$t\$" -fuzztime "$1" -parallel 6 . \
    > "$here/results/fuzz-$2-$t.log" 2>&1
  echo "$t: $(tail -4 "$here/results/fuzz-$2-$t.log" | tr '\n' ' ')"
done
