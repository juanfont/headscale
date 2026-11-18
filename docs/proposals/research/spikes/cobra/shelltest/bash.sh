# usage: bash.sh <bindir>; run with bashInteractive (non-interactive mode) and bash-completion
source /nix/store/1cnx874222bwskar75diqlv1d74pzhdl-bash-completion-2.17.0/share/bash-completion/bash_completion
export PATH="$1:$PATH"; cd "$1/pdir"
source "$1/comp.bash"
t() { COMP_WORDS=("$@"); COMP_CWORD=$((${#COMP_WORDS[@]}-1)); COMP_LINE="${COMP_WORDS[*]}"; COMP_POINT=${#COMP_LINE}; COMPREPLY=(); __start_headscale 2>/dev/null; printf '%-42s -> ' "$*<Tab>"; printf '[%s] ' "${COMPREPLY[@]}"; echo; }
COMP_TYPE=9
t headscale no
t headscale nodes list --columns ""
t headscale nodes list --columns id,na
t headscale nodes list -o ""
t headscale policy set ""
t headscale nodes routes ap
t headscale -c /x nodes l
t headscale nodes list --sort -la
