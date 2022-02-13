#!/usr/bin/env bash
set -eux
cd "$(dirname "$0")"

umask 022
mkdir -p base/site/
[ ! -e base/site/public.env ] && (
    cat >base/site/public.env <<EOF
public-hostname=localhost
public-proto=http
contact-email=headscale@example.com
EOF
)
[ ! -e base/site/derp.yaml ] && (
    cat >base/site/derp.yaml <<EOF
regions:
  900:
    regionid: 900
    regioncode: custom
    regionname: My Region
    nodes:
      - name: 900a
        regionid: 900
        hostname: myderp.mydomain.no
        ipv4: 123.123.123.123
        ipv6: "2604:a880:400:d1::828:b001"
        stunport: 0
        stunonly: false
        derptestport: 0
EOF
)

wg_version=$(wg --version || (echo "wg command not found. Please install wireguard and try again" && exit 1))
echo "Using wireguard version: $wg_version"

umask 077
mkdir -p base/secrets/
[ ! -e base/secrets/private-key ] && (
    wg genkey > base/secrets/private-key
)
mkdir -p postgres/secrets/
[ ! -e postgres/secrets/password ] && (head -c 32 /dev/urandom | base64 -w0 > postgres/secrets/password)
