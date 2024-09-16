# Official releases

Official releases for headscale are available as binaries for various platforms and DEB packages for Debian and Ubuntu.
Both are available on the [GitHub releases page](https://github.com/juanfont/headscale/releases).

## Using packages for Debian/Ubuntu (recommended)

It is recommended to use our DEB packages to install headscale on a Debian based system as those packages configure a
user to run headscale, provide a default configuration and ship with a systemd service file. Supported distributions are
Ubuntu 20.04 or newer, Debian 11 or newer.

1. Download the [latest Headscale package](https://github.com/juanfont/headscale/releases/latest) for your platform (`.deb` for Ubuntu and Debian).

    ```shell
    HEADSCALE_VERSION="" # See above URL for latest version, e.g. "X.Y.Z" (NOTE: do not add the "v" prefix!)
    HEADSCALE_ARCH="" # Your system architecture, e.g. "amd64"
    wget --output-document=headscale.deb \
      "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${HEADSCALE_ARCH}.deb"
    ```

1. Install Headscale:

    ```shell
    sudo apt install ./headscale.deb
    ```

1. [Configure Headscale by editing the configuration file](../../ref/configuration.md):

    ```shell
    sudo nano /etc/headscale/config.yaml
    ```

1. Enable and start the Headscale service:

    ```shell
    sudo systemctl enable --now headscale
    ```

1. Check that Headscale is running as intended:

    ```shell
    sudo systemctl status headscale
    ```
