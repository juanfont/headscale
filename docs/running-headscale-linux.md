# Running headscale on Linux

## Requirements

- Ubuntu 20.04 or newer, Debian 11 or newer.

## Goal

Get Headscale up and running.

This includes running Headscale with SystemD.

## Migrating from manual install

If you are migrating from the old manual install, the best thing would be to remove
the files installed by following [the guide in reverse](./running-headscale-linux-manual.md).

You should _not_ delete the database (`/var/lib/headscale/db.sqlite`) and the
configuration (`/etc/headscale/config.yaml`).

## Installation

1. Download the latest Headscale package for your platform (`.deb` for Ubuntu and Debian) from [Headscale's releases page](https://github.com/juanfont/headscale/releases):

    ```shell
    wget --output-document=headscale.deb \
      https://github.com/juanfont/headscale/releases/download/v<HEADSCALE VERSION>/headscale_<HEADSCALE VERSION>_linux_<ARCH>.deb
    ```

1. Install Headscale:

    ```shell
    sudo apt install headscale.deb
    ```

1. Enable Headscale service, this will start Headscale at boot:

    ```shell
    sudo systemctl enable headscale
    ```

1. Configure Headscale by editing the configuration file:

    ```shell
    nano /etc/headscale/config.yaml
    ```

1. Start Headscale:

    ```shell
    sudo systemctl start headscale
    ```

1. Check that Headscale is running as intended:

    ```shell
    systemctl status headscale
    ```

## Using Headscale

### Create a user

```shell
headscale users create myfirstuser
```

### Register a machine (normal login)

On a client machine, run the `tailscale` login command:

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL>
```

Register the machine:

```shell
headscale --user myfirstuser nodes register --key <YOUR_MACHINE_KEY>
```

### Register machine using a pre authenticated key

Generate a key using the command line:

```shell
headscale --user myfirstuser preauthkeys create --reusable --expiration 24h
```

This will return a pre-authenticated key that is used to
connect a node to `headscale` during the `tailscale` command:

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
```
