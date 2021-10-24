# Configuration reference

Headscale will look for a configuration file named `config.yaml` (or `config.json`) in the following order:

- `/etc/headscale`
- `~/.headscale`
- current working directory

```yaml
server_url: http://headscale.mydomain.net
listen_addr: 0.0.0.0:8080
ip_prefix: 100.64.0.0/10
disable_check_updates: false
```

`server_url` is the external URL via which Headscale is reachable. `listen_addr` is the IP address and port the Headscale program should listen on. `ip_prefix` is the IP prefix (range) in which IP addresses for nodes will be allocated (default 100.64.0.0/10, e.g., 192.168.4.0/24, 10.0.0.0/8). `disable_check_updates` disables the automatic check for updates.

```yaml
log_level: debug
```

`log_level` can be used to set the Log level for Headscale, it defaults to `debug`, and the available levels are: `trace`, `debug`, `info`, `warn` and `error`.

```yaml
private_key_path: private.key
```

`private_key_path` is the path to the Wireguard private key. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml
derp_map_path: derp.yaml
```

`derp_map_path` is the path to the [DERP](https://pkg.go.dev/tailscale.com/derp) map file. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml
ephemeral_node_inactivity_timeout": "30m"
```

`ephemeral_node_inactivity_timeout` is the timeout after which inactive ephemeral node records will be deleted from the database. The default is 30 minutes. This value must be higher than 65 seconds (the keepalive timeout for the HTTP long poll is 60 seconds, plus a few seconds to avoid race conditions).

PostgresSQL

```yaml
db_host: localhost
db_port: 5432
db_name: headscale
db_user: foo
db_pass: bar
```

SQLite

```yaml
db_type: sqlite3
db_path: db.sqlite
```

The fields starting with `db_` are used for the DB connection information.

### TLS configuration

Please check [`TLS.md`](TLS.md).

### DNS configuration

Please refer to [`DNS.md`](DNS.md).

### Policy ACLs

Headscale implements the same policy ACLs as Tailscale.com, adapted to the self-hosted environment.

For instance, instead of referring to users when defining groups you must
use namespaces (which are the equivalent to user/logins in Tailscale.com).

Please check https://tailscale.com/kb/1018/acls/, and `./tests/acls/` in this repo for working examples.

### Apple devices

An endpoint with information on how to connect your Apple devices (currently macOS only) is available at `/apple` on your running instance.
