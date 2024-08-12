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

1. Download the [latest Headscale package](https://github.com/juanfont/headscale/releases/latest) for your platform (`.deb` for Ubuntu and Debian).

    ```shell
    HEADSCALE_VERSION="" # See above URL for latest version, e.g. "X.Y.Z" (NOTE: do not add the "v" prefix!)
    # Or you can use the following bash one liner
    # HEADSCALE_VERSION="$(curl -v https://github.com/juanfont/headscale/releases/latest 2>&1 |grep location | awk -F'/' '{print $NF}' | sed -e 's/v//' | |tr -d '\r')"

    HEADSCALE_ARCH="" # Your system architecture, e.g. "amd64"
    # Or you can use:
    # HEADSCALE_ARCH="$(dpkg --print-architecture)"

    wget --output-document=headscale.deb \
      "https://github.com/juanfont/headscale/releases/download/v${HEADSCALE_VERSION}/headscale_${HEADSCALE_VERSION}_linux_${HEADSCALE_ARCH}.deb"
    ```

1. Install Headscale:

    ```shell
    sudo apt install ./headscale.deb
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

# Sample config.yml

A sane config.yml might look like this

```yaml
---

# Remember to punch a hole in your firewall for this port
server_url: https://headscale.example.com:28000

listen_addr: 0.0.0.0:28000

metrics_listen_addr: 127.0.0.1:9090

grpc_listen_addr: 127.0.0.1:50443

grpc_allow_insecure: false

private_key_path: /var/lib/headscale/private.key

noise:
  private_key_path: /var/lib/headscale/noise_private.key

ip_prefixes:
  - fd7a:115c:a1e0::/48
  - 100.64.0.0/10

derp:
  server:
    enabled: false

    region_id: 999

    region_code: "headscale"
    region_name: "Headscale Embedded DERP"

    stun_listen_addr: "0.0.0.0:3478"

  urls:
    - https://controlplane.tailscale.com/derpmap/default

  paths: []

  auto_update_enabled: true

  update_frequency: 24h

disable_check_updates: false

ephemeral_node_inactivity_timeout: 30m

node_update_check_interval: 10s

db_type: sqlite3

db_path: /var/lib/headscale/db.sqlite



acme_url: https://acme-v02.api.letsencrypt.org/directory

acme_email: "contact@example.com"


tls_letsencrypt_cache_dir: /var/lib/headscale/cache

tls_letsencrypt_challenge_type: HTTP-01
tls_letsencrypt_listen: ":http"

# Provisioned via certbot
tls_cert_path: "/etc/letsencrypt/live/headscale.example.com/fullchain.pem"
tls_key_path: "/etc/letsencrypt/live/headscale.example.com/privkey.pem"

log:
  format: text
  level: info

acl_policy_path: ""

dns_config:
  override_local_dns: true

  nameservers:
    - 9.9.9.9
    - 1.1.1.1



  domains: []


  magic_dns: true

  base_domain: example.com

unix_socket: /var/run/headscale/headscale.sock
unix_socket_permission: "0770"

logtail:
  enabled: false

randomize_client_port: false
```
