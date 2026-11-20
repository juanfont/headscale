#!/usr/bin/env bash
# Runs the referee's shell harness (spikes/v2/shell, read only) against
# bin/headscale: pty bash/zsh/fish, fish complete -C, pwsh TabExpansion2.
# Output lands in shell/out/ with the referee's file names, for diffing.
set -u
ref="$(cd "$(dirname "$0")/../../v2/shell" && pwd)"
. "$ref/env.sh"
out="$(cd "$(dirname "$0")" && pwd)/out"
mkdir -p "$out"
export PATH="$(cd "$(dirname "$0")/../bin" && pwd):$PATH"
cd "$ref/cwd"
for sh in bash zsh fish; do
  case $sh in
    bash) export SHELL_BIN=$BASHI SETUP="source $BASHC/share/bash-completion/bash_completion; source <(headscale completion bash); bind 'set show-all-if-ambiguous on'; bind 'set completion-query-items 0'";;
    zsh) export SHELL_BIN=$ZSH SETUP="bindkey -e; autoload -U compinit; compinit -u; source <(headscale completion zsh); compdef _headscale headscale 2>/dev/null; zstyle ':completion:*' list-prompt ''";;
    fish) export SHELL_BIN=$FISH SETUP="headscale completion fish | source";;
  esac
  python3 -I "$ref/ptyrun.py" "$sh" "$ref/lines.txt" > "$out/pty-lib-$sh.txt" 2>&1
done
while IFS= read -r line; do
  [[ -z $line || $line == \#* ]] && continue
  echo "LINE: $line"
  $FISH --no-config -c "headscale completion fish | source; complete -C '$line'" 2>&1 | sed 's/^/  /'
done < "$ref/lines.txt" > "$out/fishc-lib.txt"
mkdir -p "$out/ps1"
headscale completion powershell > "$out/ps1/headscale.ps1"
$PWSH -NoProfile -NonInteractive -File "$ref/pwsh-tab.ps1" "$out/ps1/headscale.ps1" "$ref/lines.txt" > "$out/pwsh-lib.txt" 2>&1
