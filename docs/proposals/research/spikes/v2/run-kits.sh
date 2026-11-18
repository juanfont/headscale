#!/usr/bin/env bash
# Runs kit v1 and kit v2 against every adapter copy under spikes/v2.
# usage (from the Headscale worktree):
#   nix shell nixpkgs#zsh nixpkgs#powershell -c nix develop -c bash <this> [tag]
# Writes results/<name>-v1<tag>.md and results/<name>-v2<tag>.md.
here=$(cd "$(dirname "$0")" && pwd)
tag=${1:-}
mkdir -p "$here/results"
for c in cobra urfave kong creachadair own-grammar own-pflag; do
  cd "$here/$c" || exit 1
  CONF_OUT="$here/results/$c-v1$tag.md" go test -buildvcs=false -count=1 -modfile=go.v1.mod ./ >/dev/null 2>&1
  CONF_OUT="$here/results/$c-v2$tag.md" go test -buildvcs=false -count=1 ./ >/dev/null 2>&1
  printf '%-12s v1: %s\n%-12s v2: %s\n' "$c" "$(sed -n 3p "$here/results/$c-v1$tag.md")" "$c" "$(sed -n 3p "$here/results/$c-v2$tag.md")"
done
