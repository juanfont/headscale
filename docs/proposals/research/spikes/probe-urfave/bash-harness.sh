#!/usr/bin/env bash
# Drive urfave's bash completion function the way bash would on <Tab>.
# usage: bash-harness.sh <bash_completion.sh path> <hs binary dir>
COMP_WORDBREAKS=$'"\x27><=;|&(: \t\n'
source "$1"
export PATH="$2:$PATH"
source <(hs completion bash)

# t <COMP_TYPE> <line as typed up to the cursor>
t() {
	local ctype=$1 line=$2
	COMP_LINE=$line
	COMP_POINT=${#line}
	COMP_TYPE=$ctype
	# split like readline: whitespace, and COMP_WORDBREAKS chars as own words
	local IFS=$' \t\n'
	read -ra COMP_WORDS <<<"$(sed -E 's/([=:])/ \1 /g' <<<"$line")"
	[[ $line == *" " ]] && COMP_WORDS+=("")
	COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
	COMPREPLY=()
	__hs_bash_autocomplete
	printf '%-36s -> [%s]\n' "$line<TAB>" "$(printf '%s|' "${COMPREPLY[@]}")"
}

t 9 "hs "
t 9 "hs no"
t 9 "hs nodes "
t 63 "hs nodes "
t 9 "hs nodes list --"
t 9 "hs nodes list --so"
t 9 "hs nodes list --sort "
t 9 "hs nodes list --sort la"
t 9 "hs nodes list --sort -la"
t 9 "hs nodes list --sort="
t 9 "hs nodes list --columns id,"
t 9 "hs nodes list --columns id,na"
t 9 "hs nodes list -o "
t 9 "hs -o "
t 9 "hs nodes delete "
t 9 "hs check config "
t 9 "hs nodes list --filter owner=tag:"
