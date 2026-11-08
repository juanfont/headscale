#!/usr/bin/env bash
# Writes the files a release ships from the binary it builds, so they match
# that version. release-assets/ is gitignored: release-check.sh still sees a
# clean tree.
set -euo pipefail

rm -rf release-assets
mkdir release-assets
go build -o release-assets/headscale ./cmd/headscale
release-assets/headscale generate config > release-assets/config-example.yaml
release-assets/headscale generate nixos-options --release > release-assets/headscale-nixos-options.nix
rm release-assets/headscale
