#!/usr/bin/env bash
set -eu
exec kubectl -n headscale exec -ti pod/headscale-0 -- /go/bin/headscale "$@"
