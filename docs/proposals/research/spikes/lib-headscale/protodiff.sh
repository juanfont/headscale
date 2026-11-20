#!/usr/bin/env bash
# Asks two binaries the same __complete questions and diffs the answers.
# usage: protodiff.sh BIN_A BIN_B < lines   (one Tab line per input line; a trailing space = new word)
a=$1 b=$2 n=0 d=0
while IFS= read -r line; do
  [[ -z $line || $line == \#* ]] && continue
  read -ra w <<<"${line#headscale }"
  [[ $line == *" " ]] && w+=("")
  n=$((n + 1))
  if ! diff <("$a" __complete "${w[@]}") <("$b" __complete "${w[@]}") >/dev/null; then
    d=$((d + 1)); echo "DIFF: $line"; diff <("$a" __complete "${w[@]}") <("$b" __complete "${w[@]}") | sed 's/^/  /'
  fi
done
echo "$n lines, $d differ"
