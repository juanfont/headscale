#!/usr/bin/env bash
set -eux
cd $(dirname $0)

umask 022
mkdir -p base/site/
[ ! -e base/site/public.env ] && (
    cat >base/site/public.env <<EOF
public-hostname=localhost
public-proto=http
contact-email=headscale@example.com
EOF
)
[ ! -e base/site/derp.yaml ] && cp ../derp.yaml base/site/derp.yaml

umask 077
mkdir -p base/secrets/
[ ! -e base/secrets/private-key ] && (
    wg genkey > base/secrets/private-key
)
mkdir -p postgres/secrets/
[ ! -e postgres/secrets/password ] && (head -c 32 /dev/urandom | base64 -w0 > postgres/secrets/password)
