#!/bin/sh
# Determine OS platform
# shellcheck source=/dev/null
. /etc/os-release

if command -V systemctl >/dev/null 2>&1; then
	echo "Stop and disable headscale service"
	systemctl stop headscale >/dev/null 2>&1 || true
	systemctl disable headscale >/dev/null 2>&1 || true
	echo "Running daemon-reload"
	systemctl daemon-reload || true
fi

echo "Removing run directory"
rm -rf "/var/run/headscale.sock"
