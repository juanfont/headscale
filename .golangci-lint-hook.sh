#!/usr/bin/env bash
# Wrapper script for golangci-lint pre-commit hook
# Finds where the current branch diverged from the main branch

set -euo pipefail

# Try to find the main branch reference in order of preference:
# 1. upstream/main (common in forks)
# 2. origin/main (common in direct clones)
# 3. main (local branch)
for ref in upstream/main origin/main main; do
    if git rev-parse --verify "$ref" >/dev/null 2>&1; then
        MAIN_REF="$ref"
        break
    fi
done

# If we couldn't find any main branch, just check the last commit
if [ -z "${MAIN_REF:-}" ]; then
    MAIN_REF="HEAD~1"
fi

# Find where current branch diverged from main
MERGE_BASE=$(git merge-base HEAD "$MAIN_REF" 2>/dev/null || echo "HEAD~1")

# Run golangci-lint only on changes since branch point
exec golangci-lint run --new-from-rev="$MERGE_BASE" --timeout=5m --fix
