#!/usr/bin/env bash
set -euo pipefail

root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
export GOWORK=off CGO_ENABLED=0 LC_ALL=C
unset GOFLAGS GOOS GOARCH

mkdir -p "$tmp/headscale/cmd/headscale" "$tmp/headscale/tools"
cp "$root/.goreleaser.yml" "$tmp/headscale/"
cp "$root/tools/release-check.sh" "$tmp/headscale/tools/"
cd "$tmp/headscale"
cat > go.mod <<'MOD'
module example.com/headscale

go 1.24.0

// Tidy removes this block, reproducing release-time go.mod edits.
require (
)
MOD
printf 'package main\nfunc main() {}\n' > cmd/headscale/main.go
printf 'dist/\nvendor/\n' > .gitignore
git init -q
git config user.name 'Release check test'
git config user.email 'release-check@example.invalid'
git remote add origin https://github.com/juanfont/headscale.git
git add .
git commit -qm 'Create release fixture'
git tag v0.0.1
check="$PWD/tools/release-check.sh"

expect_failure() {
    local label=$1 message=$2
    shift 2
    if "$@" > "$tmp/failure.log" 2>&1; then
        printf 'FAIL: %s unexpectedly succeeded\n' "$label" >&2
        exit 1
    fi
    if ! grep -Fq "$message" "$tmp/failure.log"; then
        cat "$tmp/failure.log" >&2
        exit 1
    fi
    printf 'PASS: %s\n' "$label"
}

# Use the real release hooks and every configured target, without publishing.
if ! goreleaser build --snapshot --clean > "$tmp/build.log" 2>&1; then
    cat "$tmp/build.log" >&2
    exit 1
fi
binaries=(dist/headscale_*/headscale)
bash "$check" "${binaries[@]}"
printf 'PASS: clean release builds, including cross-compiled binaries\n'

git config status.showUntrackedFiles no
printf '// dirty\n' >> cmd/headscale/main.go
expect_failure 'unstaged change' 'working tree is dirty' bash "$check"
go build -o dist/dirty ./cmd/headscale
git add cmd/headscale/main.go
expect_failure 'staged change' 'working tree is dirty' bash "$check"
git restore --staged --worktree cmd/headscale/main.go
expect_failure 'dirty binary after source cleanup' 'lacks clean VCS metadata' bash "$check" dist/dirty

touch untracked
expect_failure 'untracked file despite Git display settings' 'working tree is dirty' bash "$check"
rm untracked

go build -buildvcs=false -o dist/unstamped ./cmd/headscale
expect_failure 'missing VCS metadata' 'lacks clean VCS metadata' bash "$check" dist/unstamped
expect_failure 'missing binary' 'no such file or directory' bash "$check" dist/missing

git commit --allow-empty -qm 'Advance fixture HEAD'
expect_failure 'binary from another commit' 'was not built from HEAD' bash "$check" "${binaries[0]}"

# Reintroducing a mutating preparation hook must abort the actual build pipeline.
sed -i '/    - go mod vendor/a\    - go mod tidy' .goreleaser.yml
git add .goreleaser.yml
git commit -qm 'Reproduce release-time tidy'
expect_failure 'preparation dirties source' 'working tree is dirty' goreleaser build --snapshot --clean --single-target

cd "$tmp"
expect_failure 'Git failure' 'not a git repository' bash "$check"
