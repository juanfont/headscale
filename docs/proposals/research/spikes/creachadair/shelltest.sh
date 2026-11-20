#!/usr/bin/env bash
# Drive the generated completion scripts through real shells, no terminal.
# usage: shelltest.sh <spike dir> <bash_completion file>
# Build first: go build -buildvcs=false -o bin/headscale ./cmd/headscale (inside nix develop).
# Run with zsh and an interactive bash on PATH: nix shell nixpkgs#zsh nixpkgs#bashInteractive -c bash shelltest.sh . "$(nix build nixpkgs#bash-completion --print-out-paths --no-link)/share/bash-completion/bash_completion"
set -u
dir=$(cd "$1" && pwd)
export PATH="$dir/bin:$PATH"
lines=("headscale no" "headscale nodes list --columns " "headscale nodes list -o " "headscale policy set "
	"headscale nodes list --columns id,na" "headscale nodes routes ap" "headscale -c /x nodes l")

echo "== bash"
for line in "${lines[@]}"; do
	bash --norc --noprofile -c '
		source "$1"; source <(headscale completion bash)
		line=$2
		COMP_LINE=$line; COMP_POINT=${#line}; COMP_TYPE=9; COMP_KEY=9
		read -ra COMP_WORDS <<<"$line"
		[[ $line == *" " ]] && COMP_WORDS+=("")
		COMP_CWORD=$((${#COMP_WORDS[@]} - 1))
		COMPREPLY=()
		__start_headscale headscale "${COMP_WORDS[COMP_CWORD]}" "${COMP_WORDS[COMP_CWORD-1]}"
		printf "%-42s -> [%s]\n" "$line<TAB>" "$(IFS="|"; echo "${COMPREPLY[*]}")"
	' _ "$2" "$line"
done

echo "== fish"
for line in "${lines[@]}"; do
	out=$(fish --no-config -c 'headscale completion fish | source; complete -C $argv[1]' "$line" | cut -f1 | tr '\n' '|')
	printf "%-42s -> [%s]\n" "$line<TAB>" "$out"
done

echo "== zsh (script function _headscale called with _describe/_arguments stubbed: no line editor)"
if command -v zsh >/dev/null; then
	for line in "${lines[@]}"; do
		out=$(zsh -f -c '
			compdef() { :; }
			source <(headscale completion zsh)
			_describe() { print -rn -- "${(j:|:)${completions%%:*}}"; (( ${#completions} )) }  # completions is a local of _headscale
			_arguments() { print -rn -- "FILES($*)"; return 0 }
			words=(${(z)0}); [[ $0 == *" " ]] && words+=("")
			CURRENT=${#words}
			_headscale
		' "$line" 2>&1)
		printf "%-42s -> [%s]\n" "$line<TAB>" "$out"
	done
fi
