#!/usr/bin/env bash
# usage: run-pwsh.sh <candidate> [set]  -> out/pwsh<set>-<candidate>.txt
. "$(dirname "$0")/env.sh"
c=$1 set=${2:-}
export PATH="$HERE/path$set/$c:$PATH"
tmp="$HERE/out/ps1$set-$c"; mkdir -p "$tmp"
headscale completion powershell > "$tmp/headscale.ps1"   # urfave's script reads its own file name
cd "$HERE/cwd"
$PWSH -NoProfile -NonInteractive -File "$HERE/pwsh-tab.ps1" "$tmp/headscale.ps1" "$HERE/lines.txt" > "$HERE/out/pwsh$set-$c.txt" 2>&1
