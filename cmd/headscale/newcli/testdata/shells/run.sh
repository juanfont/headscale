#!/usr/bin/env bash
# The real-shell Tab job: builds the new CLI, types each active line of
# lines.txt into interactive bash, zsh and fish in a pseudo-terminal,
# presses Tab once and records what the shell shows; asks fish with
# `complete -C` and PowerShell with TabExpansion2. It compares the record
# with want/, faults of cobra's scripts included, and fails on a change.
# Run it in the dev shell that carries the shells, from the repository:
#
#   nix develop .#shells -c cmd/headscale/newcli/testdata/shells/run.sh           # compare
#   nix develop .#shells -c cmd/headscale/newcli/testdata/shells/run.sh -update   # rewrite want/
set -euo pipefail

here="$(cd "$(dirname "$0")" && pwd)"
root="$(cd "$here/../../../../.." && pwd)"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

if [[ -z ${BASH_COMPLETION_SH:-} ]]; then
  echo "run.sh needs the shells' dev shell: nix develop .#shells -c $0${*:+ $*}" >&2
  exit 2
fi

(cd "$root" && CGO_ENABLED=0 go build -tags newcli -o "$work/bin/headscale" ./cmd/headscale)
(cd "$root" && CGO_ENABLED=0 go build -o "$work/ptyrun" ./cmd/headscale/newcli/testdata/shells/ptyrun)
# The job runs on Linux and macOS; each checks that the other's driver builds.
for os in linux darwin; do
  (cd "$root" && CGO_ENABLED=0 GOOS=$os go vet ./cmd/headscale/newcli/testdata/shells/ptyrun)
done

# A line waits while the command it names is not in the tree; the Go test
# TestShellLines (command/kit_test.go) fails once it is, so the line is
# made active.
grep -v '^#' "$here/lines.txt" | grep -v '^$' | grep -v "$(printf '\t')waits " >"$work/lines" || true
grep "$(printf '\t')waits " "$here/lines.txt" | sed 's/^/waiting: /' || true

# Tab offers file names here; the folder is the same on every machine.
mkdir -p "$work/cwd" "$work/home" "$work/out"
touch "$work/cwd/config.yaml" "$work/cwd/policy.hujson"

export PATH="$work/bin:$PATH" HOME="$work/home" XDG_CONFIG_HOME="$work/home/.config" XDG_DATA_HOME="$work/home/.local/share"
# Readline sorts what it lists in the order of the locale.
export LC_ALL=C.UTF-8
export POWERSHELL_TELEMETRY_OPTOUT=1 POWERSHELL_UPDATECHECK=Off DOTNET_CLI_TELEMETRY_OPTOUT=1
cd "$work/cwd"

pty() {
  local sh=$1 setup
  case $sh in
  bash) setup="source $BASH_COMPLETION_SH; source <(headscale completion bash); bind 'set show-all-if-ambiguous on'; bind 'set completion-query-items 0'" ;;
  zsh) setup="PS1='$ '; bindkey -e; autoload -U compinit; compinit -u; source <(headscale completion zsh); compdef _headscale headscale 2>/dev/null; zstyle ':completion:*' list-prompt ''" ;;
  fish) setup="set -g fish_greeting; function fish_prompt; echo -n '$ '; end; headscale completion fish | source" ;;
  esac
  SHELL_BIN="$(command -v "$sh")" SETUP="$setup" "$work/ptyrun" "$sh" "$work/lines" >"$work/out/$sh.txt" 2>&1
}

pids=()
for sh in bash zsh fish; do
  pty "$sh" &
  pids+=($!)
done

while IFS= read -r row; do
  echo "LINE: $row"
  fish --no-config -c "headscale completion fish | source; complete -C '${row%|}'" 2>&1 | sed 's/^/  /' | grep . || echo "  (none)"
done <"$work/lines" >"$work/out/fish-c.txt"

headscale completion powershell >"$work/headscale.ps1"
pwsh -NoProfile -NonInteractive -File "$here/tab.ps1" "$work/headscale.ps1" "$work/lines" >"$work/out/pwsh.txt" 2>&1

failed=0
for pid in "${pids[@]}"; do
  wait "$pid" || failed=1
done

if ((failed)); then
  tail -n 3 "$work"/out/{bash,zsh,fish}.txt >&2
  echo "a shell run failed" >&2
  exit 1
fi

if [[ ${1:-} == -update ]]; then
  cp "$work"/out/*.txt "$here/want/"
  exit 0
fi

diff -ru "$here/want" "$work/out"
