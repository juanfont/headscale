#!/bin/bash
set -e

if [ $# -gt 0 ]; then
    # CLI mode: run headscale with the given arguments
    exec "$@"
else
    # Generate a unique deploy ID for this container instance
    # to prevent Litestream replica corruption during blue-green deploys
    export DEPLOY_ID=${DEPLOY_ID:-$(date -u +%Y%m%d)_$(genxid)}
    echo "Litestream DEPLOY_ID: $DEPLOY_ID"
    exec litestream replicate -exec 'headscale serve' -config /etc/litestream.yml
fi
