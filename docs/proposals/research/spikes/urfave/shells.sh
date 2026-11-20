#!/usr/bin/env bash
# Drive the generated completion scripts through real bash, zsh and fish, no terminal.
# usage: shells.sh <bash_completion path> <dir with headscale>
export PATH="$2:$PATH"
lines=("headscale no" "headscale nodes list --columns " "headscale nodes list -o " "headscale policy set " "headscale nodes list --sort la" "headscale nodes list --sort=" "headscale nodes list --columns id," "headscale nodes delete " "headscale nodes list --filter owner=tag:")

echo "## bash (bash-interactive, non-interactive shell, bash-completion sourced)"
bash_one() {
	COMP_WORDBREAKS=$'"\x27><=;|&(: \t\n'
	source "$1" >/dev/null 2>&1
	source <(headscale completion bash)
	local line=$2
	COMP_LINE=$line COMP_POINT=${#line} COMP_TYPE=9
	read -ra COMP_WORDS <<<"$(sed -E 's/([=:])/ \1 /g' <<<"$line")"
	[[ $line == *" " ]] && COMP_WORDS+=("")
	COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
	COMPREPLY=()
	__headscale_bash_autocomplete
	local note=""
	[[ ${#COMPREPLY[@]} -eq 0 || -z ${COMPREPLY[0]} ]] && note="  (empty: complete -o default offers files)"
	printf '%-44s -> [%s]%s\n' "$line<TAB>" "${COMPREPLY[*]}" "$note"
}
for l in "${lines[@]}"; do (bash_one "$1" "$l"); done

echo "## zsh (script sourced; _describe/_files stubbed to print what they are given)"
for l in "${lines[@]}"; do
	zsh -f -c '
		compdef() { : }
		_describe() { local -a a; a=("${(@P)2}"); print -rn -- "describe: ${a[*]}" }
		_files() { print -rn -- "FILES" }
		source <(headscale completion zsh)
		words=(${=1}); [[ $1 == *" " ]] && words+=("")
		CURRENT=${#words}
		print -rn -- "$(printf "%-44s -> " "$1<TAB>")"; _headscale; print
	' zsh "$l"
done

echo "## fish (complete -C)"
for l in "${lines[@]}"; do
	printf '%-44s -> [%s]\n' "$l<TAB>" "$(fish --no-config -c "headscale completion fish | source; complete -C'$l'" | cut -f1 | tr '\n' ' ')"
done
