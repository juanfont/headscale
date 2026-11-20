#!/usr/bin/env bash
# Drives the generated scripts without a terminal. Needs `headscale` (this
# module's cmd/headscale) on PATH and BASHC = a bash-completion store path, BASHI = bash-interactive (the
# dev shell bash lacks the complete builtins).
# bash: set COMP_* and call the completion function. fish: complete -C.
# zsh has no non-terminal entry into compsys; see ptytab.py in probe-own.
lines=(
  "headscale no"
  "headscale nodes list --columns "
  "headscale nodes list --columns id,na"
  "headscale nodes list -o "
  "headscale policy set "
  "headscale nodes routes ap"
  "headscale nodes list --sort -la"
  "headscale nodes list --columns=id,na"
)
echo "## bash"
for l in "${lines[@]}"; do
  "$BASHI/bin/bash" --norc --noprofile -c '
    source "$BASHC/share/bash-completion/bash_completion"
    source <(headscale completion bash)
    COMP_LINE=$1 COMP_POINT=${#1}
    read -ra COMP_WORDS <<<"$1"
    [[ $1 == *" " ]] && COMP_WORDS+=("")
    COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
    __start_headscale headscale "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
    printf "%-45s -> %s\n" "$1<TAB>" "$(printf "[%s] " "${COMPREPLY[@]}")"
  ' _ "$l"
done
echo "## fish"
for l in "${lines[@]}"; do
  printf "%-45s -> %s\n" "$l<TAB>" "$(fish --no-config -c 'headscale completion fish | source; complete -C $argv[1]' "$l" 2>&1 | tr '\n' ' ')"
done
