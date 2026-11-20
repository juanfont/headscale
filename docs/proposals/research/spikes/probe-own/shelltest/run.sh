#!/usr/bin/env bash
# Runs each case in bash, zsh and fish through ptytab.py. Needs `headscale`
# (the probe) on PATH, and BASHC, ZSH, FISH store paths in the environment.
here=$(cd "$(dirname "$0")" && pwd)
cases=(
  "headscale no"
  "headscale nodes "
  "headscale nodes list --columns id,na"
  "headscale nodes list --columns=id,na"
  "headscale nodes list --sort -l"
  "headscale nodes list --filter na"
  "headscale nodes list --columns +ho"
  "headscale nodes routes ap"
  "headscale -c x no"
  "headscale nodes list -o "
  "headscale policy set pol"
  "headscale nodes rm --f"
  "headscale completion f"
)
for sh in bash zsh fish; do
  case $sh in
    bash) export SHELL_BIN=$BASHI/bin/bash SETUP="source $BASHC/share/bash-completion/bash_completion; source <(headscale completion bash); bind 'set show-all-if-ambiguous on'";;
    zsh) export SHELL_BIN=$ZSH/bin/zsh SETUP="bindkey -e; autoload -U compinit; compinit -u; source <(headscale completion zsh)";;
    fish) export SHELL_BIN=$FISH SETUP="headscale completion fish | source";;
  esac
  for c in "${cases[@]}"; do
    echo "### $sh: «$c<TAB>»"
    timeout 20 python3 -I "$here/ptytab.py" "$sh" "$c" 1 | grep -a '^\[' | tail -1
  done
done
