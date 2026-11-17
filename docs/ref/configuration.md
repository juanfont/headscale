# Configuration

- Headscale loads its configuration from a YAML, JSON or HuJSON file
- It searches for `config.json`, `config.yaml`, `config.yml` or `config.hujson`, in that order, in the following paths:
    - `/etc/headscale`
    - `$XDG_CONFIG_HOME/headscale` (default `$HOME/.config/headscale`)
    - `headscale` under each directory in `$XDG_CONFIG_DIRS` (default `/etc/xdg`)
    - `$HOME/.headscale`
    - the current working directory
- Configuration keys are always lower case. An unknown or removed configuration entry prevents Headscale from starting
- An unknown or removed `HEADSCALE_*` environment variable logs a warning
- A [secret](configuration-options.md#secrets) can be either a string value or a file path starting with `file:`:
    - an empty file is an error
    - file is only read where the secret is used
- To load the configuration from a different path, use:
    - the command line flag `-c`, `--config`
    - the environment variable `HEADSCALE_CONFIG`
- The configuration can be checked with: `headscale check config`. Use `-f <path>` to load from path.
- Additional configuration can be checked with: `headscale check all`:
    - [Policy](configuration-options.md#policy.path)
    - [DERP Maps](configuration-options.md#derp.paths)
    - [TLS Certs](configuration-options.md#tls.cert_path)
    - [Extra records](configuration-options.md#dns.extra_records_path)

## Example configuration

The full configuration for your version can be generated using `headscale generate config` and will print a
configuration file with all configuration options, their documentation and the default values.

Write it to a file to start a new configuration:

```shell
headscale generate config > /etc/headscale/config.yaml
```

Use `--no-docs` to print a dense configuration file without the comments/documentation.

Use `--minimal` to print the most essential configuration options.

Use `--running` to print the current running configuration of the live Headscale server, with secrets redacted.

[Configuration options](configuration-options.md) describes every key, with examples for the configuration file, the
environment and NixOS.

??? example "Example configuration of this version"

    ```yaml
    {% include "./config-example.yaml" start="do not edit.\n" %}
    ```
