# Headscale

[![Join the chat at https://gitter.im/headscale-dev/community](https://badges.gitter.im/headscale-dev/community.svg)](https://gitter.im/headscale-dev/community?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge&utm_content=badge) ![ci](https://github.com/juanfont/headscale/actions/workflows/test.yml/badge.svg)

An open source, self-hosted implementation of the Tailscale coordination server.

## Overview

Tailscale is [a modern VPN](https://tailscale.com/) built on top of [Wireguard](https://www.wireguard.com/). It [works like an overlay network](https://tailscale.com/blog/how-tailscale-works/) between the computers of your networks - using all kinds of [NAT traversal sorcery](https://tailscale.com/blog/how-nat-traversal-works/).

Everything in Tailscale is Open Source, except the GUI clients for proprietary OS (Windows and macOS/iOS), and the 'coordination/control server'.

The control server works as an exchange point of Wireguard public keys for the nodes in the Tailscale network. It also assigns the IP addresses of the clients, creates the boundaries between each user, enables sharing machines between users, and exposes the advertised routes of your nodes.

Headscale implements this coordination server.

## Status

- [x] Base functionality (nodes can communicate with each other)
- [x] Node registration through the web flow
- [x] Network changes are relayed to the nodes
- [x] Namespace support (~equivalent to multi-user in Tailscale.com)
- [x] Routing (advertise & accept, including exit nodes)
- [x] Node registration via pre-auth keys (including reusable keys, and ephemeral node support)
- [x] JSON-formatted output
- [x] ACLs
- [x] Support for alternative IP ranges in the tailnets (default Tailscale's 100.64.0.0/10)
- [x] DNS (passing DNS servers to nodes)
- [x] Share nodes between ~~users~~ namespaces
- [ ] MagicDNS / Smart DNS

## Roadmap 🤷

Suggestions/PRs welcomed!

## Running it

1. Download the Headscale binary https://github.com/juanfont/headscale/releases, and place it somewhere in your PATH or use the docker container

```shell
docker pull headscale/headscale:x.x.x
```

<!--
  or
  ```shell
  docker pull ghrc.io/juanfont/headscale:x.x.x
  ``` -->

2. (Optional, you can also use SQLite) Get yourself a PostgreSQL DB running

```shell
docker run --name headscale -e POSTGRES_DB=headscale -e \
  POSTGRES_USER=foo -e POSTGRES_PASSWORD=bar -p 5432:5432 -d postgres
```

3. Set some stuff up (headscale Wireguard keys & the config.json file)

```shell
wg genkey > private.key
wg pubkey < private.key > public.key  # not needed

# Postgres
cp config.json.postgres.example config.json
# or
# SQLite
cp config.json.sqlite.example config.json
```

4. Create a namespace (a namespace is a 'tailnet', a group of Tailscale nodes that can talk to each other)

```shell
headscale namespaces create myfirstnamespace
```

or docker:

```shell
docker run -v ./private.key:/private.key -v ./config.json:/config.json headscale/headscale:x.x.x headscale namespace create myfirstnamespace
```

5. Run the server

```shell
headscale serve
```

or docker:

```shell
docker run -v $(pwd)/private.key:/private.key -v $(pwd)/config.json:/config.json -v $(pwd)/derb.yaml:/derb.yaml -p 127.0.0.1:8080:8080 headscale/headscale:x.x.x headscale serve
```

6. If you used tailscale.com before in your nodes, make sure you clear the tailscaled data folder

```shell
systemctl stop tailscaled
rm -fr /var/lib/tailscale
systemctl start tailscaled
```

7. Add your first machine

```shell
tailscale up -login-server YOUR_HEADSCALE_URL
```

8. Navigate to the URL you will get with `tailscale up`, where you'll find your machine key.

9. In the server, register your machine to a namespace with the CLI

```shell
headscale -n myfirstnamespace node register YOURMACHINEKEY
```

or docker:

```shell
docker run -v ./private.key:/private.key -v ./config.json:/config.json headscale/headscale:x.x.x headscale -n myfirstnamespace node register YOURMACHINEKEY
```

Alternatively, you can use Auth Keys to register your machines:

1. Create an authkey
   ```shell
   headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
   ```
   or docker:

```shell
docker run -v ./private.key:/private.key -v ./config.json:/config.json headscale/headscale:x.x.x headscale -n myfirstnamespace preauthkeys create --reusable --expiration 24h
```

2. Use the authkey from your machine to register it
   ```shell
   tailscale up -login-server YOUR_HEADSCALE_URL --authkey YOURAUTHKEY
   ```

If you create an authkey with the `--ephemeral` flag, that key will create ephemeral nodes. This implies that `--reusable` is true.

Please bear in mind that all the commands from headscale support adding `-o json` or `-o json-line` to get a nicely JSON-formatted output.

## Configuration reference

Headscale's configuration file is named `config.json` or `config.yaml`. Headscale will look for it in `/etc/headscale`, `~/.headscale` and finally the directory from where the Headscale binary is executed.

```
    "server_url": "http://192.168.1.12:8080",
    "listen_addr": "0.0.0.0:8080",
    "ip_prefix": "100.64.0.0/10"
```

`server_url` is the external URL via which Headscale is reachable. `listen_addr` is the IP address and port the Headscale program should listen on. `ip_prefix` is the IP prefix (range) in which IP addresses for nodes will be allocated (default 100.64.0.0/10, e.g., 192.168.4.0/24, 10.0.0.0/8)

```
    "log_level": "debug"
```

`log_level` can be used to set the Log level for Headscale, it defaults to `debug`, and the available levels are: `trace`, `debug`, `info`, `warn` and `error`.

```
    "private_key_path": "private.key",
```

`private_key_path` is the path to the Wireguard private key. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```
    "derp_map_path": "derp.yaml",
```

`derp_map_path` is the path to the [DERP](https://pkg.go.dev/tailscale.com/derp) map file. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```
    "ephemeral_node_inactivity_timeout": "30m",
```

`ephemeral_node_inactivity_timeout` is the timeout after which inactive ephemeral node records will be deleted from the database. The default is 30 minutes. This value must be higher than 65 seconds (the keepalive timeout for the HTTP long poll is 60 seconds, plus a few seconds to avoid race conditions).

```
    "db_host": "localhost",
    "db_port": 5432,
    "db_name": "headscale",
    "db_user": "foo",
    "db_pass": "bar",
```

The fields starting with `db_` are used for the PostgreSQL connection information.

### Running the service via TLS (optional)

```
    "tls_cert_path": ""
    "tls_key_path": ""
```

Headscale can be configured to expose its web service via TLS. To configure the certificate and key file manually, set the `tls_cert_path` and `tls_cert_path` configuration parameters. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```
    "tls_letsencrypt_hostname": "",
    "tls_letsencrypt_listen": ":http",
    "tls_letsencrypt_cache_dir": ".cache",
    "tls_letsencrypt_challenge_type": "HTTP-01",
```

To get a certificate automatically via [Let's Encrypt](https://letsencrypt.org/), set `tls_letsencrypt_hostname` to the desired certificate hostname. This name must resolve to the IP address(es) Headscale is reachable on (i.e., it must correspond to the `server_url` configuration parameter). The certificate and Let's Encrypt account credentials will be stored in the directory configured in `tls_letsencrypt_cache_dir`. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from. The certificate will automatically be renewed as needed.

#### Challenge type HTTP-01

The default challenge type `HTTP-01` requires that Headscale is reachable on port 80 for the Let's Encrypt automated validation, in addition to whatever port is configured in `listen_addr`. By default, Headscale listens on port 80 on all local IPs for Let's Encrypt automated validation.

If you need to change the ip and/or port used by Headscale for the Let's Encrypt validation process, set `tls_letsencrypt_listen` to the appropriate value. This can be handy if you are running Headscale as a non-root user (or can't run `setcap`). Keep in mind, however, that Let's Encrypt will _only_ connect to port 80 for the validation callback, so if you change `tls_letsencrypt_listen` you will also need to configure something else (e.g. a firewall rule) to forward the traffic from port 80 to the ip:port combination specified in `tls_letsencrypt_listen`.

#### Challenge type TLS-ALPN-01

Alternatively, `tls_letsencrypt_challenge_type` can be set to `TLS-ALPN-01`. In this configuration, Headscale listens on the ip:port combination defined in `listen_addr`. Let's Encrypt will _only_ connect to port 443 for the validation callback, so if `listen_addr` is not set to port 443, something else (e.g. a firewall rule) will be required to forward the traffic from port 443 to the ip:port combination specified in `listen_addr`.

### Policy ACLs

Headscale implements the same policy ACLs as Tailscale.com, adapted to the self-hosted environment.

For instance, instead of referring to users when defining groups you must
use namespaces (which are the equivalent to user/logins in Tailscale.com).

Please check https://tailscale.com/kb/1018/acls/, and `./tests/acls/` in this repo for working examples.

### Apple devices

An endpoint with information on how to connect your Apple devices (currently macOS only) is available at `/apple` on your running instance.

## Disclaimer

1. We have nothing to do with Tailscale, or Tailscale Inc.
2. The purpose of writing this was to learn how Tailscale works.

## More on Tailscale

- https://tailscale.com/blog/how-tailscale-works/
- https://tailscale.com/blog/tailscale-key-management/
- https://tailscale.com/blog/an-unlikely-database-migration/
