#!/bin/sh
# Determine OS platform
# shellcheck source=/dev/null
. /etc/os-release

HEADSCALE_EXE="/usr/bin/headscale"
BSD_HIER=""
HEADSCALE_RUN_DIR="/var/run/headscale"
HEADSCALE_HOME_DIR="/var/lib/headscale"
HEADSCALE_USER="headscale"
HEADSCALE_GROUP="headscale"
HEADSCALE_SHELL="/usr/sbin/nologin"

ensure_sudo() {
	if [ "$(id -u)" = "0" ]; then
		echo "Sudo permissions detected"
	else
		echo "No sudo permission detected, please run as sudo"
		exit 1
	fi
}

ensure_headscale_path() {
	if [ ! -f "$HEADSCALE_EXE" ]; then
		echo "headscale not in default path, exiting..."
		exit 1
	fi

	printf "Found headscale %s\n" "$HEADSCALE_EXE"
}

create_headscale_user() {
	printf "PostInstall: Adding headscale user %s\n" "$HEADSCALE_USER"
	useradd -s "$HEADSCALE_SHELL" -d "$HEADSCALE_HOME_DIR" -c "headscale default user" "$HEADSCALE_USER"
}

create_headscale_group() {
	if command -V systemctl >/dev/null 2>&1; then
		printf "PostInstall: Adding headscale group %s\n" "$HEADSCALE_GROUP"
		groupadd "$HEADSCALE_GROUP"

		printf "PostInstall: Adding headscale user %s to group %s\n" "$HEADSCALE_USER" "$HEADSCALE_GROUP"
		usermod -a -G "$HEADSCALE_GROUP" "$HEADSCALE_USER"
	fi

	if [ "$ID" = "alpine" ]; then
		printf "PostInstall: Adding headscale group %s\n" "$HEADSCALE_GROUP"
		addgroup "$HEADSCALE_GROUP"

		printf "PostInstall: Adding headscale user %s to group %s\n" "$HEADSCALE_USER" "$HEADSCALE_GROUP"
		addgroup "$HEADSCALE_USER" "$HEADSCALE_GROUP"
	fi
}

create_run_dir() {
	printf "PostInstall: Creating headscale run directory \n"
	mkdir -p "$HEADSCALE_RUN_DIR"

	printf "PostInstall: Modifying group ownership of headscale run directory \n"
	chown "$HEADSCALE_USER":"$HEADSCALE_GROUP" "$HEADSCALE_RUN_DIR"
}

summary() {
	echo "----------------------------------------------------------------------"
	echo " headscale package has been successfully installed."
	echo ""
	echo " Please follow the next steps to start the software:"
	echo ""
	echo "    sudo systemctl enable headscale"
	echo "    sudo systemctl start headscale"
	echo ""
	echo " Configuration settings can be adjusted here:"
	echo "    ${BSD_HIER}/etc/headscale/config.yaml"
	echo ""
	echo "----------------------------------------------------------------------"
}

#
# Main body of the script
#
{
	ensure_sudo
	ensure_headscale_path
	create_headscale_user
	create_headscale_group
	create_run_dir
	summary
}
