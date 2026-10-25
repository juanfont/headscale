#!/usr/bin/env bash
set -euo pipefail

status=$(git status --porcelain --untracked-files=all)
if [[ -n "$status" ]]; then
    printf 'release: working tree is dirty\n%s\n' "$status" >&2
    exit 1
fi

for binary in "$@"; do
    info=$(go version -m "$binary")
    if ! grep -Eq '[[:space:]]vcs.modified=false$' <<< "$info"; then
        printf 'release: %s lacks clean VCS metadata\n%s\n' "$binary" "$info" >&2
        exit 1
    fi
    revision=$(git rev-parse HEAD)
    if ! grep -Eq "[[:space:]]vcs.revision=${revision}$" <<< "$info"; then
        printf 'release: %s was not built from HEAD\n%s\n' "$binary" "$info" >&2
        exit 1
    fi
done
