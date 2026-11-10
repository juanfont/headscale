# Configuration

- Headscale loads its configuration from a YAML, JSON or HuJSON file
- It searches for `config.json`, `config.yaml`, `config.yml` or `config.hujson`, in that order, in the following paths:
    - `/etc/headscale`
    - `$XDG_CONFIG_HOME/headscale` (default `$HOME/.config/headscale`)
    - `headscale` under each directory in `$XDG_CONFIG_DIRS` (default `/etc/xdg`)
    - `$HOME/.headscale`
    - the current working directory
- A `config.toml`, `config.env` or `config.dotenv` in these paths stops headscale: convert it to YAML
- Only `server_url` is required. Every other key has a working default, so a file with
  `server_url: https://headscale.example.com`, or `HEADSCALE_SERVER_URL` alone, is a complete configuration. With the
  defaults, headscale needs writable `/var/lib/headscale` and `/var/run/headscale` (for its socket) and must reach
  Tailscale's DERP map
- Keys are lower case. An unknown or removed key in the configuration file stops headscale; an unknown or removed
  `HEADSCALE_*` environment variable logs a warning
- A secret takes the value itself or `file:<path>`, which reads it from that file, e.g.
  `file:${CREDENTIALS_DIRECTORY}/oidc_client_secret` with systemd's `LoadCredential`. Headscale trims surrounding
  whitespace and expands environment variables in the path; an empty file is an error. This applies to
  `oidc.client_secret`, `database.postgres.pass`, `cli.api_key` and every text setting of `dns.challenge.provider`, and
  headscale reads each file only where the secret is used
- These paths, when relative, are resolved against the directory of the configuration file (or the working directory
  without one): `noise.private_key_path`, `policy.path`, `database.sqlite.path`, `tls.cert_path`, `tls.key_path`,
  `tls.acme.cache_dir` and `derp.server.private_key_path`. Other paths, such as `unix_socket`,
  `dns.extra_records_path` and `derp.paths`, are used as given
- To load the configuration from a different path, use:
    - the command line flag `-c`, `--config`
    - the environment variable `HEADSCALE_CONFIG`
- Check the configuration with `headscale check config`. `headscale check all` also checks every file it names (policy,
  DERP maps, extra records, TLS pair, keys) and prints one line per file. Pass `-f <path>` to check a file other than
  the one `headscale serve` would load.

## Example configuration

`headscale generate config` prints a configuration file with every key, its default and its documentation as comments.
Write it to a file to start a new configuration:

```shell
headscale generate config > /etc/headscale/config.yaml
```

`--no-docs` leaves the comments out, and `--minimal` prints only the keys every server must set. `--running` prints the
configuration of the running server instead, with secrets redacted. [Configuration options](configuration-options.md)
describes every key, with examples for the configuration file, the environment and NixOS.

??? example "Example configuration of this version"

    ```yaml
    {% include "./config-example.yaml" start="do not edit.\n" %}
    ```
