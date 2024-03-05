# Running headscale on OpenBSD

!!! warning "Community documentation"

    This page is not actively maintained by the headscale authors and is
    written by community members. It is _not_ verified by `headscale` developers.

    **It might be outdated and it might miss necessary steps**.

## Goal

This documentation has the goal of showing a user how-to install and run `headscale` on OpenBSD 7.1.
In additional to the "get up and running section", there is an optional [rc.d section](#running-headscale-in-the-background-with-rcd)
describing how to make `headscale` run properly in a server environment.

## Install `headscale`

1. Install from ports (not recommended)

    !!! info

        As of OpenBSD 7.2, there's a headscale in ports collection, however, it's severely outdated(v0.12.4). You can install it via `pkg_add headscale`.

1. Install from source on OpenBSD 7.2

    ```shell
    # Install prerequistes
    pkg_add go

    git clone https://github.com/juanfont/headscale.git

    cd headscale

    # optionally checkout a release
    # option a. you can find offical relase at https://github.com/juanfont/headscale/releases/latest
    # option b. get latest tag, this may be a beta release
    latestTag=$(git describe --tags `git rev-list --tags --max-count=1`)

    git checkout $latestTag

    go build -ldflags="-s -w -X github.com/juanfont/headscale/cmd/headscale/cli.Version=$latestTag" github.com/juanfont/headscale

    # make it executable
    chmod a+x headscale

    # copy it to /usr/local/sbin
    cp headscale /usr/local/sbin
    ```

1. Install from source via cross compile

    ```shell
    # Install prerequistes
    # 1. go v1.20+: headscale newer than 0.21 needs go 1.20+ to compile
    # 2. gmake: Makefile in the headscale repo is written in GNU make syntax

    git clone https://github.com/juanfont/headscale.git

    cd headscale

    # optionally checkout a release
    # option a. you can find offical relase at https://github.com/juanfont/headscale/releases/latest
    # option b. get latest tag, this may be a beta release
    latestTag=$(git describe --tags `git rev-list --tags --max-count=1`)

    git checkout $latestTag

    make build GOOS=openbsd

    # copy headscale to openbsd machine and put it in /usr/local/sbin
    ```

## Configure and run `headscale`

1. Prepare a directory to hold `headscale` configuration and the [SQLite](https://www.sqlite.org/) database:

    ```shell
    # Directory for configuration

    mkdir -p /etc/headscale

    # Directory for Database, and other variable data (like certificates)
    mkdir -p /var/lib/headscale
    ```

1. Create an empty SQLite database:

    ```shell
    touch /var/lib/headscale/db.sqlite
    ```

1. Create a `headscale` configuration:

    ```shell
    touch /etc/headscale/config.yaml
    ```

**(Strongly Recommended)** Download a copy of the [example configuration][config-example.yaml](https://github.com/juanfont/headscale/blob/main/config-example.yaml) from the headscale repository.

1. Start the headscale server:

    ```shell
    headscale serve
    ```

    This command will start `headscale` in the current terminal session.

    ***

    To continue the tutorial, open a new terminal and let it run in the background.
    Alternatively use terminal emulators like [tmux](https://github.com/tmux/tmux).

    To run `headscale` in the background, please follow the steps in the [rc.d section](#running-headscale-in-the-background-with-rcd) before continuing.

1. Verify `headscale` is running:

    Verify `headscale` is available:

    ```shell
    curl http://127.0.0.1:9090/metrics
    ```

1. Create a user ([tailnet](https://tailscale.com/kb/1136/tailnet/)):

    ```shell
    headscale users create myfirstuser
    ```

### Register a machine (normal login)

On a client machine, execute the `tailscale` login command:

```shell
tailscale up --login-server YOUR_HEADSCALE_URL
```

Register the machine:

```shell
headscale --user myfirstuser nodes register --key <YOU_+MACHINE_KEY>
```

### Register machine using a pre authenticated key

Generate a key using the command line:

```shell
headscale --user myfirstuser preauthkeys create --reusable --expiration 24h
```

This will return a pre-authenticated key that can be used to connect a node to `headscale` during the `tailscale` command:

```shell
tailscale up --login-server <YOUR_HEADSCALE_URL> --authkey <YOUR_AUTH_KEY>
```

## Running `headscale` in the background with rc.d

This section demonstrates how to run `headscale` as a service in the background with [rc.d](https://man.openbsd.org/rc.d).

1. Create a rc.d service at `/etc/rc.d/headscale` containing:

    ```shell
    #!/bin/ksh

    daemon="/usr/local/sbin/headscale"
    daemon_logger="daemon.info"
    daemon_user="root"
    daemon_flags="serve"
    daemon_timeout=60

    . /etc/rc.d/rc.subr

    rc_bg=YES
    rc_reload=NO

    rc_cmd $1
    ```

1. `/etc/rc.d/headscale` needs execute permission:

    ```shell
    chmod a+x /etc/rc.d/headscale
    ```

1. Start `headscale` service:

    ```shell
    rcctl start headscale
    ```

1. Make `headscale` service start at boot:

    ```shell
    rcctl enable headscale
    ```

1. Verify the headscale service:

    ```shell
    rcctl check headscale
    ```

    Verify `headscale` is available:

    ```shell
    curl http://127.0.0.1:9090/metrics
    ```

    `headscale` will now run in the background and start at boot.
