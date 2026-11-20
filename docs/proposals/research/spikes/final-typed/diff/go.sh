#!/usr/bin/env bash
# Runs a command in this folder inside Headscale's nix dev shell (Go 1.27.3).
here="$(cd "$(dirname "$0")" && pwd)"
cd /home/kradalby/worktrees/headscale/cli-restructure-proposal || exit 1
exec nix develop -c env GOFLAGS=-buildvcs=false bash -c 'cd "$0" && "$@"' "$here" "$@"
