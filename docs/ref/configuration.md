# Configuration

- Headscale loads its configuration from a YAML file
- It searches for `config.yaml` in the following paths:
    - `/etc/headscale`
    - `$HOME/.headscale`
    - the current working directory
- To load the configuration from a different path, use:
    - the command line flag `-c`, `--config`
    - the environment variable `HEADSCALE_CONFIG`
- Validate the configuration file with: `headscale check config`. Use `headscale check all` to also check every file it
  names (policy, DERP map, extra records, TLS pair, keys), one line per file. Both run offline and write nothing; pass
  `-f <path>` to check a file other than the one `headscale serve` would load.

!!! example "Get the [example configuration from the GitHub repository](https://github.com/juanfont/headscale/blob/main/config-example.yaml)"

    Always select the [same GitHub tag](https://github.com/juanfont/headscale/tags) as the released version you use to
    ensure you have the correct example configuration. The `main` branch might contain unreleased changes.

    === "View on GitHub"

        - Development version: <https://github.com/juanfont/headscale/blob/main/config-example.yaml>
        - Version {{ headscale.version }}: https://github.com/juanfont/headscale/blob/v{{ headscale.version }}/config-example.yaml

    === "Download with `wget`"

        ```shell
        # Development version
        wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

        # Version {{ headscale.version }}
        wget -O config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
        ```

    === "Download with `curl`"

        ```shell
        # Development version
        curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/main/config-example.yaml

        # Version {{ headscale.version }}
        curl -o config.yaml https://raw.githubusercontent.com/juanfont/headscale/v{{ headscale.version }}/config-example.yaml
        ```
