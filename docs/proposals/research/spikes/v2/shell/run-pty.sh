#!/usr/bin/env bash
# usage: run-pty.sh <candidate> <shell>  -> out/pty-<candidate>-<shell>.txt
set -u
. "$(dirname "$0")/env.sh"
c=$1 sh=$2 set=${3:-}
export PATH="$HERE/path$set/$c:$PATH"
cd "$HERE/cwd"
case $sh in
  bash) export SHELL_BIN=$BASHI SETUP="source $BASHC/share/bash-completion/bash_completion; source <(headscale completion bash); bind 'set show-all-if-ambiguous on'; bind 'set completion-query-items 0'";;
  zsh) export SHELL_BIN=$ZSH SETUP="bindkey -e; autoload -U compinit; compinit -u; source <(headscale completion zsh); compdef _headscale headscale 2>/dev/null; zstyle ':completion:*' list-prompt ''";;
  fish) export SHELL_BIN=$FISH SETUP="headscale completion fish | source";;
esac
mkdir -p "$HERE/out"
python3 -I "$HERE/ptyrun.py" "$sh" "$HERE/${LINES_FILE:-lines.txt}" > "$HERE/out/pty$set-$c-$sh.txt" 2>&1
