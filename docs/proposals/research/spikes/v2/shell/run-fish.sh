#!/usr/bin/env bash
# fish's own completion engine, no terminal: complete -C "<line>" for every line.
# usage: run-fish.sh <candidate>  -> out/fishc-<candidate>.txt
. "$(dirname "$0")/env.sh"
c=$1 set=${2:-}
export PATH="$HERE/path$set/$c:$PATH"
cd "$HERE/cwd"
{
while IFS= read -r line; do
  [[ -z $line || $line == \#* ]] && continue
  echo "LINE: $line"
  $FISH --no-config -c "headscale completion fish | source; complete -C '$line'" 2>&1 | sed 's/^/  /'
done < "$HERE/${LINES_FILE:-lines.txt}"
} > "$HERE/out/fishc$set-$c.txt"
