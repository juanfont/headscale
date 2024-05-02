# Running headscale on Linux

## Note: Outdated and "advanced"

This documentation is considered the "legacy"/advanced/manual version of the documentation, you most likely do not
want to use this documentation and rather look at the distro specific documentation (TODO LINK)[].

## Goal

This documentation has the goal of showing a user how-to set up and run `headscale` on Linux.
In additional to the "get up and running section", there is an optional [SystemD section](#running-headscale-in-the-background-with-systemd)
describing how to make `headscale` run properly in a server environment.

## Configure and run `headscale`

1. Download the latest [`headscale` binary from GitHub's release page](https://github.com/juanfont/headscale/releases):

    ```shell
    wget --output-document=/usr/local/bin/headscale \
    https://github.com/juanfont/headscale/releases/download/v<HEADSCALE VERSION>/headscale_<HEADSCALE VERSION>_linux_<ARCH>
    ```

1. Make `headscale` executable:

    ```shell
    chmod +x /usr/local/bin/headscale
    ```

1. Prepare a directory to hold `headscale` configuration and the [SQLite](https://www.sqlite.org/) database:

    ```shell
    # Directory for configuration

    mkdir -p /etc/headscale

    # Directory for Database, and other variable data (like certificates)
    mkdir -p /var/lib/headscale
    # or if you create a headscale user:
    useradd \
      --create-home \
      --home-dir /var/lib/headscale/ \
      --system \
      --user-group \
      --shell /usr/sbin/nologin \
      headscale
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

    ---

    To continue the tutorial, open a new terminal and let it run in the background.
    Alternatively use terminal emulators like [tmux](https://github.com/tmux/tmux) or [screen](https://www.gnu.org/software/screen/).

    To run `headscale` in the background, please follow the steps in the [SystemD section](#running-headscale-in-the-background-with-systemd) before continuing.

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
headscale --user myfirstuser nodes register --key <YOUR_MACHINE_KEY>
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

## Running `headscale` in the background with SystemD

:warning: **Deprecated**: This part is very outdated and you should use the [pre-packaged Headscale for this](./running-headscale-linux.md)

This section demonstrates how to run `headscale` as a service in the background with [SystemD](https://www.freedesktop.org/wiki/Software/systemd/).
This should work on most modern Linux distributions.

1. Create a SystemD service configuration at `/etc/systemd/system/headscale.service` containing:

    ```systemd
    [Unit]
    Description=headscale controller
    After=syslog.target
    After=network.target

    [Service]
    Type=simple
    User=headscale
    Group=headscale
    ExecStart=/usr/local/bin/headscale serve
    Restart=always
    RestartSec=5

    # Optional security enhancements
    NoNewPrivileges=yes
    PrivateTmp=yes
    ProtectSystem=strict
    ProtectHome=yes
    WorkingDirectory=/var/lib/headscale
    ReadWritePaths=/var/lib/headscale /var/run/headscale
    AmbientCapabilities=CAP_NET_BIND_SERVICE
    RuntimeDirectory=headscale

    [Install]
    WantedBy=multi-user.target
    ```

    Note that when running as the headscale user ensure that, either you add your current user to the headscale group:

    ```shell
    usermod -a -G headscale current_user
    ```

    or run all headscale commands as the headscale user:

    ```shell
    su - headscale
    ```

1. In `/etc/headscale/config.yaml`, override the default `headscale` unix socket with path that is writable by the `headscale` user or group:

    ```yaml
    unix_socket: /var/run/headscale/headscale.sock
    ```

1. Reload SystemD to load the new configuration file:

    ```shell
    systemctl daemon-reload
    ```

1. Enable and start the new `headscale` service:

    ```shell
    systemctl enable --now headscale
    ```

1. Verify the headscale service:

    ```shell
    systemctl status headscale
    ```

    Verify `headscale` is available:

    ```shell
    curl http://127.0.0.1:9090/metrics
    ```

`headscale` will now run in the background and start at boot.
