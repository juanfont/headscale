# Configuration reference

Headscale's configuration file is named `config.json` or `config.yaml`. Headscale will look for it in `/etc/headscale`, `~/.headscale` and finally the directory from where the Headscale binary is executed.

```yaml
server_url: http://192.168.1.12:8080
listen_addr: 0.0.0.0:8080
ip_prefix: 100.64.0.0/10
```

`server_url` is the external URL via which Headscale is reachable. `listen_addr` is the IP address and port the Headscale program should listen on. `ip_prefix` is the IP prefix (range) in which IP addresses for nodes will be allocated (default 100.64.0.0/10, e.g., 192.168.4.0/24, 10.0.0.0/8)

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

```yaml
db_host: localhost
db_port: 5432
db_name: headscale
db_user: foo
db_pass: bar
```

The fields starting with `db_` are used for the PostgreSQL connection information.

### Running the service via TLS (optional)

```yaml
tls_cert_path: ''
tls_key_path: ''
```

Headscale can be configured to expose its web service via TLS. To configure the certificate and key file manually, set the `tls_cert_path` and `tls_cert_path` configuration parameters. If the path is relative, it will be interpreted as relative to the directory the configuration file was read from.

```yaml
tls_letsencrypt_hostname: ''
tls_letsencrypt_listen: ":http"
tls_letsencrypt_cache_dir: ".cache"
tls_letsencrypt_challenge_type: HTTP-01
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
