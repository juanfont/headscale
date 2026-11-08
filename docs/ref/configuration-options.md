# Configuration options

!!! note "Generated page"

    This page is generated from the doc comments in `hscontrol/types/config.go` by
    `go generate ./hscontrol/types/`. Edit the comments there, not this page.

Every key headscale reads, in the order `headscale generate config` prints them, with its type, default,
environment variable and an example for a configuration file, the environment and NixOS. Keys that no longer
work are listed under [Removed keys](#removed-keys). [Configuration](configuration.md) explains where headscale
finds its configuration, how to check it, and shows the full example.

## Conventions { #conventions }

### Value types { #types }

| Type                                                 | Format                                                                                                    | Example                                                   |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------- | --------------------------------------------------------- |
| <span id="type-string"></span>string                 | Text. Quote it where YAML would read another type, as in `"0x1F"` or `"null"`.                            | `/var/lib/headscale/db.sqlite`                            |
| <span id="type-boolean"></span>boolean               | `true` or `false`.                                                                                        | `true`                                                    |
| <span id="type-integer"></span>integer               | A whole number.                                                                                           | `1024`                                                    |
| <span id="type-duration"></span>duration             | A number with a unit, `ms`, `s`, `m`, `h`, `d`, `w` or `y`, units combined largest first; `0` needs none. | `1h30m`                                                   |
| <span id="type-file-mode"></span>file mode           | Octal permission bits, quoted.                                                                            | `"0770"`                                                  |
| <span id="type-listen-address"></span>listen address | `host:port`. An empty host listens on every address; the port may be `http` or `https`.                   | `0.0.0.0:8080`                                            |
| <span id="type-URL"></span>URL                       | An absolute `http://` or `https://` URL with a host.                                                      | `https://headscale.example.com`                           |
| <span id="type-prefix"></span>prefix                 | An IP range in CIDR notation.                                                                             | `100.64.0.0/10`                                           |
| secret                                               | Text, or `file:<path>` to read it from a file.                                                            | `file:/run/secrets/oidc_client_secret`                    |
| <span id="type-enum"></span>enum                     | One of the values listed with the key.                                                                    | `sqlite`                                                  |
| DNS record                                           | An object with `name`, `type` and `value`.                                                                | `{name: grafana.example.com, type: A, value: 100.64.0.3}` |
| value                                                | Whatever the setting takes: text, a number, a boolean, a list or a map.                                   | `file:/run/secrets/cloudflare`                            |
| <span id="type-list"></span>list                     | A list. A variable holds it as a JSON array or, unless its values are objects, separated by spaces.       | `[9.9.9.9, 2620:fe::fe]`                                  |
| <span id="type-map"></span>map                       | Keys you choose, each with a value. A variable holds a JSON object.                                       | `{corp.example.com: [192.0.2.53]}`                        |

### Environment variables { #env }

Every key can also be set with an environment variable: `HEADSCALE_` and the key's path in capitals, with `_` for
`.`, e.g. `HEADSCALE_LOG_LEVEL` for `log.level`. Each key below names its variable. A variable wins over the
configuration file, which wins over the default; an empty variable counts as unset.

A list is a JSON array or, unless its values are objects, its values separated by spaces. A map is a JSON object,
which replaces the map in the configuration file instead of merging into it. The examples below write every list
and map as JSON.

A `HEADSCALE_` variable that names no key logs a warning, and one for a removed key also says what to do instead.
Other software uses the same prefix, so neither stops headscale.

A DNS provider setting that takes text can also be set on its own as `HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>`,
e.g. `HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN`; see [`dns.challenge.provider`](#dns.challenge.provider).

### Secrets { #secrets }

A secret takes the value itself or `file:<path>`, which reads it from that file. Environment variables in the path
are expanded, as in `file:${CREDENTIALS_DIRECTORY}/oidc_client_secret`, and whitespace around the file's contents
is trimmed; an empty file is an error. Headscale reads the file only where the secret is used, and
`headscale check config` and `headscale check all` never read it. `headscale generate config --running` and
`/debug/config` show a literal secret as `<redacted>` and a `file:` reference as written.

The secrets are [`database.postgres.pass`](#database.postgres.pass), [`oidc.client_secret`](#oidc.client_secret), [`cli.api_key`](#cli.api_key) and every string setting of [`dns.challenge.provider`](#dns.challenge.provider).

On NixOS, keep a secret out of the Nix store: load it as a systemd credential and point the key at it.

```nix
services.headscale.settings.oidc.client_secret = "file:\${CREDENTIALS_DIRECTORY}/oidc_client_secret";
systemd.services.headscale.serviceConfig.LoadCredential = [ "oidc_client_secret:/run/secrets/oidc_client_secret" ];
```

## `server_url` { #server_url data-toc-label="server_url" }

- **Type:** [string](#type-string)
- **Required**
- **Env:** `HEADSCALE_SERVER_URL`

The URL clients connect to, with its `http://` or `https://` scheme, e.g. `https://headscale.example.com:443`. A trailing slash is trimmed on load. Its host must not be [`dns.base_domain`](#dns.base_domain) or a name below it.

=== "YAML"

    ```yaml
    server_url: https://headscale.example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_SERVER_URL=https://headscale.example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.server_url = "https://headscale.example.com";
    ```

## `listen_addr` { #listen_addr data-toc-label="listen_addr" }

- **Type:** [listen address](#type-listen-address)
- **Default:** `""`
- **Env:** `HEADSCALE_LISTEN_ADDR`

The host:port the server listens on for clients, the API and the web pages. It serves HTTPS when [`tls.cert_path`](#tls.cert_path) or [`tls.acme.hostname`](#tls.acme.hostname) is set, plain HTTP otherwise.

=== "YAML"

    ```yaml
    listen_addr: 0.0.0.0:8080
    ```

=== "Environment"

    ```shell
    export HEADSCALE_LISTEN_ADDR=0.0.0.0:8080
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.listen_addr = "0.0.0.0:8080";
    ```

## `metrics_listen_addr` { #metrics_listen_addr data-toc-label="metrics_listen_addr" }

- **Type:** [listen address](#type-listen-address)
- **Default:** `""`
- **Env:** `HEADSCALE_METRICS_LISTEN_ADDR`

The host:port serving `/metrics` and `/debug`; keep it private. Empty disables this listener.

=== "YAML"

    ```yaml
    metrics_listen_addr: 127.0.0.1:9090
    ```

=== "Environment"

    ```shell
    export HEADSCALE_METRICS_LISTEN_ADDR=127.0.0.1:9090
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.metrics_listen_addr = "127.0.0.1:9090";
    ```

## `unix_socket` { #unix_socket data-toc-label="unix_socket" }

- **Type:** [string](#type-string)
- **Default:** `/var/run/headscale/headscale.sock`
- **Env:** `HEADSCALE_UNIX_SOCKET`

Where the server serves the API without authentication, for the CLI on the same host. The CLI connects to it when [`cli.address`](#cli.address) is empty.

=== "YAML"

    ```yaml
    unix_socket: /run/headscale/headscale.sock
    ```

=== "Environment"

    ```shell
    export HEADSCALE_UNIX_SOCKET=/run/headscale/headscale.sock
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.unix_socket = "/run/headscale/headscale.sock";
    ```

## `unix_socket_permission` { #unix_socket_permission data-toc-label="unix_socket_permission" }

- **Type:** [file mode](#type-file-mode)
- **Default:** `"0770"`
- **Env:** `HEADSCALE_UNIX_SOCKET_PERMISSION`

The file mode of [`unix_socket`](#unix_socket), in quoted octal (`"0770"`): unquoted, YAML reads `0770` as the number 504.

=== "YAML"

    ```yaml
    unix_socket_permission: "0660"
    ```

=== "Environment"

    ```shell
    export HEADSCALE_UNIX_SOCKET_PERMISSION=0660
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.unix_socket_permission = "0660";
    ```

## `trusted_proxies` { #trusted_proxies data-toc-label="trusted_proxies" }

- **Type:** [list of prefixes](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_TRUSTED_PROXIES` ([space-separated or JSON array](#env))

The CIDRs of reverse proxies whose `True-Client-IP`, `X-Real-IP` and `X-Forwarded-For` headers are honoured. Empty ignores those headers. Set without a proxy in front, clients can spoof their source IP in logs and the v2 API.

=== "YAML"

    ```yaml
    trusted_proxies:
      - 192.0.2.10/32
      - 2001:db8::10/128
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TRUSTED_PROXIES='["192.0.2.10/32","2001:db8::10/128"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.trusted_proxies = [
      "192.0.2.10/32"
      "2001:db8::10/128"
    ];
    ```

## `disable_check_updates` { #disable_check_updates data-toc-label="disable_check_updates" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DISABLE_CHECK_UPDATES`

Skips the check for a newer headscale release that commands make at start.

=== "YAML"

    ```yaml
    disable_check_updates: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DISABLE_CHECK_UPDATES=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.disable_check_updates = true;
    ```

## `noise` { #noise data-toc-label="noise" }

The Noise protocol (TS2021) clients connect over.

??? example "All `noise` keys and defaults"

    ```yaml
    noise:
      private_key_path: ""
    ```

### `noise.private_key_path` { #noise.private_key_path data-toc-label="private_key_path" }

- **Type:** [string](#type-string)
- **Required**
- **Env:** `HEADSCALE_NOISE_PRIVATE_KEY_PATH`

The file holding the Noise private key, which encrypts traffic between headscale and clients, relative to the configuration file. A missing file is created with a new key.

=== "YAML"

    ```yaml
    noise:
      private_key_path: /var/lib/headscale/noise_private.key
    ```

=== "Environment"

    ```shell
    export HEADSCALE_NOISE_PRIVATE_KEY_PATH=/var/lib/headscale/noise_private.key
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.noise.private_key_path = "/var/lib/headscale/noise_private.key";
    ```

Replaces `private_key_path` ([removed](#private_key_path)).
Replaces `noise_private_key_path` ([removed](#noise_private_key_path)).

## `prefixes` { #prefixes data-toc-label="prefixes" }

The IP ranges node addresses are allocated from. Set at least one of [`prefixes.v4`](#prefixes.v4) and [`prefixes.v6`](#prefixes.v6). Use the Tailscale ranges, `100.64.0.0/10` and `fd7a:115c:a1e0::/48`, or ranges inside them: the client assumes them, and other ranges are unsupported.

??? example "All `prefixes` keys and defaults"

    ```yaml
    prefixes:
      v4: ""
      v6: ""
      allocation: sequential
    ```

### `prefixes.v4` { #prefixes.v4 data-toc-label="v4" }

- **Type:** [prefix](#type-prefix)
- **Default:** `""`
- **Env:** `HEADSCALE_PREFIXES_V4`

The IPv4 range, e.g. `100.64.0.0/10`. Empty gives nodes no IPv4 address.

=== "YAML"

    ```yaml
    prefixes:
      v4: 100.64.0.0/10
    ```

=== "Environment"

    ```shell
    export HEADSCALE_PREFIXES_V4=100.64.0.0/10
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.prefixes.v4 = "100.64.0.0/10";
    ```

Replaces `ip_prefixes` ([removed](#ip_prefixes)).

### `prefixes.v6` { #prefixes.v6 data-toc-label="v6" }

- **Type:** [prefix](#type-prefix)
- **Default:** `""`
- **Env:** `HEADSCALE_PREFIXES_V6`

The IPv6 range, e.g. `fd7a:115c:a1e0::/48`. Empty gives nodes no IPv6 address.

=== "YAML"

    ```yaml
    prefixes:
      v6: fd7a:115c:a1e0::/48
    ```

=== "Environment"

    ```shell
    export HEADSCALE_PREFIXES_V6=fd7a:115c:a1e0::/48
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.prefixes.v6 = "fd7a:115c:a1e0::/48";
    ```

Replaces `ip_prefixes` ([removed](#ip_prefixes)).

### `prefixes.allocation` { #prefixes.allocation data-toc-label="allocation" }

- **Type:** [enum](#type-enum): `sequential`, `random`
- **Default:** `sequential`
- **Env:** `HEADSCALE_PREFIXES_ALLOCATION`

How a new node's addresses are picked.

| Value        | Meaning                                                                                               |
| ------------ | ----------------------------------------------------------------------------------------------------- |
| `sequential` | Takes the next free address after the last one handed out, and wraps around to reuse freed addresses. |
| `random`     | Picks a free address at random.                                                                       |

=== "YAML"

    ```yaml
    prefixes:
      allocation: random
    ```

=== "Environment"

    ```shell
    export HEADSCALE_PREFIXES_ALLOCATION=random
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.prefixes.allocation = "random";
    ```

## `policy` { #policy data-toc-label="policy" }

Where the access control policy is kept: in a file headscale reads, or in the database. See [Policy](policy.md).

??? example "All `policy` keys and defaults"

    ```yaml
    policy:
      path: ""
      mode: file
    ```

### `policy.path` { #policy.path data-toc-label="path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_POLICY_PATH`

The HuJSON policy file read when [`policy.mode`](#policy.mode) is `file`, relative to the configuration file. Empty starts without a policy, which allows all traffic.

=== "YAML"

    ```yaml
    policy:
      path: /etc/headscale/policy.hujson
    ```

=== "Environment"

    ```shell
    export HEADSCALE_POLICY_PATH=/etc/headscale/policy.hujson
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.policy.path = "/etc/headscale/policy.hujson";
    ```

Replaces `acl_policy_path` ([removed](#acl_policy_path)).

### `policy.mode` { #policy.mode data-toc-label="mode" }

- **Type:** [enum](#type-enum): `file`, `database`
- **Default:** `file`
- **Env:** `HEADSCALE_POLICY_MODE`

Where the policy is kept: in the file [`policy.path`](#policy.path), or in the database, edited through the CLI or API.

| Value      | Meaning                                                                                                                  |
| ---------- | ------------------------------------------------------------------------------------------------------------------------ |
| `file`     | Reads the policy from [`policy.path`](#policy.path). Send headscale `SIGHUP` to reload it after an edit.                 |
| `database` | Keeps the policy in the database, set with `headscale policy set` or the API. [`policy.path`](#policy.path) is not read. |

=== "YAML"

    ```yaml
    policy:
      mode: database
    ```

=== "Environment"

    ```shell
    export HEADSCALE_POLICY_MODE=database
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.policy.mode = "database";
    ```

## `log` { #log data-toc-label="log" }

Headscale's own log output. See [Debugging](debug.md#application-logging).

??? example "All `log` keys and defaults"

    ```yaml
    log:
      level: info
      format: text
    ```

### `log.level` { #log.level data-toc-label="level" }

- **Type:** [enum](#type-enum): `trace`, `debug`, `info`, `warn`, `error`, `fatal`, `panic`, `disabled`
- **Default:** `info`
- **Env:** `HEADSCALE_LOG_LEVEL`

The lowest level logged.

=== "YAML"

    ```yaml
    log:
      level: debug
    ```

=== "Environment"

    ```shell
    export HEADSCALE_LOG_LEVEL=debug
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.log.level = "debug";
    ```

Replaces `log_level` ([removed](#log_level)).

### `log.format` { #log.format data-toc-label="format" }

- **Type:** [enum](#type-enum): `text`, `json`
- **Default:** `text`
- **Env:** `HEADSCALE_LOG_FORMAT`

How log lines are written.

| Value  | Meaning                                                                                  |
| ------ | ---------------------------------------------------------------------------------------- |
| `text` | Writes human-readable lines, coloured when stderr is a terminal and `NO_COLOR` is unset. |
| `json` | Writes one JSON object per line, for log collectors.                                     |

=== "YAML"

    ```yaml
    log:
      format: json
    ```

=== "Environment"

    ```shell
    export HEADSCALE_LOG_FORMAT=json
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.log.format = "json";
    ```

Replaces `json_logs` ([removed](#json_logs)).

## `node` { #node data-toc-label="node" }

Covers node key expiry, ephemeral nodes and subnet routes.

??? example "All `node` keys and defaults"

    ```yaml
    node:
      expiry: 0s
      ephemeral:
        inactivity_timeout: 2m
      routes:
        ha:
          probe_interval: 10s
          probe_timeout: 5s
    ```

### `node.expiry` { #node.expiry data-toc-label="expiry" }

- **Type:** [duration](#type-duration)
- **Default:** `0s`
- **Env:** `HEADSCALE_NODE_EXPIRY`

The key expiry given to a non-tagged node that registers without one, whatever the method (auth key, CLI, web, OIDC). An expiry the client asks for, [`oidc.use_expiry_from_token`](#oidc.use_expiry_from_token) and an admin's `headscale nodes expire` still apply. Tagged nodes never get this default. Zero or negative disables the default.

=== "YAML"

    ```yaml
    node:
      expiry: 2160h
    ```

=== "Environment"

    ```shell
    export HEADSCALE_NODE_EXPIRY=2160h
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.node.expiry = "2160h";
    ```

Replaces `oidc.expiry` ([removed](#oidc.expiry)).

### `node.ephemeral` { #node.ephemeral data-toc-label="ephemeral" }

Covers ephemeral nodes, which register with an ephemeral auth key and are deleted once they have been offline for [`node.ephemeral.inactivity_timeout`](#node.ephemeral.inactivity_timeout).

??? example "All `node.ephemeral` keys and defaults"

    ```yaml
    node:
      ephemeral:
        inactivity_timeout: 2m
    ```

#### `node.ephemeral.inactivity_timeout` { #node.ephemeral.inactivity_timeout data-toc-label="inactivity_timeout" }

- **Type:** [duration](#type-duration)
- **Default:** `2m`
- **Env:** `HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT`

How long an ephemeral node can be offline before it is automatically deleted. It must exceed 65s, the client keepalive plus a margin.

=== "YAML"

    ```yaml
    node:
      ephemeral:
        inactivity_timeout: 30m
    ```

=== "Environment"

    ```shell
    export HEADSCALE_NODE_EPHEMERAL_INACTIVITY_TIMEOUT=30m
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.node.ephemeral.inactivity_timeout = "30m";
    ```

Replaces `ephemeral_node_inactivity_timeout` ([removed](#ephemeral_node_inactivity_timeout)).

### `node.routes` { #node.routes data-toc-label="routes" }

Covers the routes nodes advertise. See [Routes](routes.md).

??? example "All `node.routes` keys and defaults"

    ```yaml
    node:
      routes:
        ha:
          probe_interval: 10s
          probe_timeout: 5s
    ```

#### `node.routes.ha` { #node.routes.ha data-toc-label="ha" }

Health probing of HA subnet routers. When two or more nodes advertise the same route, headscale pings each over Noise and moves the route away from one that does not answer in time. See [High availability](routes.md#high-availability).

??? example "All `node.routes.ha` keys and defaults"

    ```yaml
    node:
      routes:
        ha:
          probe_interval: 10s
          probe_timeout: 5s
    ```

##### `node.routes.ha.probe_interval` { #node.routes.ha.probe_interval data-toc-label="probe_interval" }

- **Type:** [duration](#type-duration)
- **Default:** `10s`
- **Env:** `HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL`

How often HA subnet routers are probed; a positive interval must be at least 2s. Zero or negative disables probing, and with it the [`node.routes.ha.probe_timeout`](#node.routes.ha.probe_timeout) rules.

=== "YAML"

    ```yaml
    node:
      routes:
        ha:
          probe_interval: 30s
    ```

=== "Environment"

    ```shell
    export HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL=30s
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.node.routes.ha.probe_interval = "30s";
    ```

##### `node.routes.ha.probe_timeout` { #node.routes.ha.probe_timeout data-toc-label="probe_timeout" }

- **Type:** [duration](#type-duration)
- **Default:** `5s`
- **Env:** `HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT`

The maximum time to wait for a probe response before declaring a node unhealthy; at least 1s and less than [`node.routes.ha.probe_interval`](#node.routes.ha.probe_interval).

=== "YAML"

    ```yaml
    node:
      routes:
        ha:
          probe_timeout: 3s
    ```

=== "Environment"

    ```shell
    export HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT=3s
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.node.routes.ha.probe_timeout = "3s";
    ```

## `preauth_keys` { #preauth_keys data-toc-label="preauth_keys" }

Covers the cleanup of revoked pre-auth keys. See [Pre authenticated key](registration.md#pre-authenticated-key).

??? example "All `preauth_keys` keys and defaults"

    ```yaml
    preauth_keys:
      revoked_retention: 168h
    ```

### `preauth_keys.revoked_retention` { #preauth_keys.revoked_retention data-toc-label="revoked_retention" }

- **Type:** [duration](#type-duration)
- **Default:** `168h`
- **Env:** `HEADSCALE_PREAUTH_KEYS_REVOKED_RETENTION`

How long a soft-revoked pre-auth key (revoked via the v2 API's DELETE) is kept retrievable before the background collector hard-deletes it. Keys still backing a node are kept until the node is deleted. A zero or negative duration disables the collector.

=== "YAML"

    ```yaml
    preauth_keys:
      revoked_retention: 720h
    ```

=== "Environment"

    ```shell
    export HEADSCALE_PREAUTH_KEYS_REVOKED_RETENTION=720h
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.preauth_keys.revoked_retention = "720h";
    ```

## `derp` { #derp data-toc-label="derp" }

The DERP map: the relay servers clients use when they cannot connect directly, from [`derp.urls`](#derp.urls), [`derp.paths`](#derp.paths) and the embedded server in [`derp.server`](#derp.server). A region replaces an earlier one with the same ID. See [DERP](derp.md).

??? example "All `derp` keys and defaults"

    ```yaml
    derp:
      server:
        enabled: false
        region_id: 0
        region_code: ""
        region_name: ""
        verify_clients: true
        stun_listen_addr: ""
        private_key_path: ""
        ipv4: ""
        ipv6: ""
        automatically_add_embedded_derp_region: true
      urls: []
      paths: []
      auto_update_enabled: false
      update_frequency: 3h
    ```

### `derp.server` { #derp.server data-toc-label="server" }

The embedded DERP server, a relay and STUN server run by headscale itself. See [Enable embedded DERP](derp.md#enable-embedded-derp).

??? example "All `derp.server` keys and defaults"

    ```yaml
    derp:
      server:
        enabled: false
        region_id: 0
        region_code: ""
        region_name: ""
        verify_clients: true
        stun_listen_addr: ""
        private_key_path: ""
        ipv4: ""
        ipv6: ""
        automatically_add_embedded_derp_region: true
    ```

#### `derp.server.enabled` { #derp.server.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DERP_SERVER_ENABLED`

Runs the embedded DERP server. DERP needs TLS, so [`server_url`](#server_url) must be `https://`.

=== "YAML"

    ```yaml
    derp:
      server:
        enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.enabled = true;
    ```

#### `derp.server.region_id` { #derp.server.region_id data-toc-label="region_id" }

- **Type:** [integer](#type-integer)
- **Default:** `0`
- **Env:** `HEADSCALE_DERP_SERVER_REGION_ID`

The embedded server's region ID. It replaces a region with the same ID from the other sources.

=== "YAML"

    ```yaml
    derp:
      server:
        region_id: 999
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_REGION_ID=999
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.region_id = 999;
    ```

#### `derp.server.region_code` { #derp.server.region_code data-toc-label="region_code" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_REGION_CODE`

The region's short code, shown by Tailscale clients.

=== "YAML"

    ```yaml
    derp:
      server:
        region_code: headscale
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_REGION_CODE=headscale
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.region_code = "headscale";
    ```

#### `derp.server.region_name` { #derp.server.region_name data-toc-label="region_name" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_REGION_NAME`

The region's name, shown by Tailscale clients.

=== "YAML"

    ```yaml
    derp:
      server:
        region_name: Headscale Embedded DERP
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_REGION_NAME='Headscale Embedded DERP'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.region_name = "Headscale Embedded DERP";
    ```

#### `derp.server.verify_clients` { #derp.server.verify_clients data-toc-label="verify_clients" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_DERP_SERVER_VERIFY_CLIENTS`

Admits only nodes registered with this server.

=== "YAML"

    ```yaml
    derp:
      server:
        verify_clients: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_VERIFY_CLIENTS=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.verify_clients = false;
    ```

#### `derp.server.stun_listen_addr` { #derp.server.stun_listen_addr data-toc-label="stun_listen_addr" }

- **Type:** [listen address](#type-listen-address)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR`

The UDP host:port of the STUN server, which helps clients with NAT traversal; required when [`derp.server.enabled`](#derp.server.enabled) is true.

=== "YAML"

    ```yaml
    derp:
      server:
        stun_listen_addr: 0.0.0.0:3478
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR=0.0.0.0:3478
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.stun_listen_addr = "0.0.0.0:3478";
    ```

#### `derp.server.private_key_path` { #derp.server.private_key_path data-toc-label="private_key_path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH`

The file holding the DERP server's private key, relative to the configuration file; required when [`derp.server.enabled`](#derp.server.enabled) is true. A missing file is created with a new key. It must differ from [`noise.private_key_path`](#noise.private_key_path).

=== "YAML"

    ```yaml
    derp:
      server:
        private_key_path: /var/lib/headscale/derp_server_private.key
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH=/var/lib/headscale/derp_server_private.key
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.private_key_path = "/var/lib/headscale/derp_server_private.key";
    ```

#### `derp.server.ipv4` { #derp.server.ipv4 data-toc-label="ipv4" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_IPV4`

The server's public IPv4 address, published in the DERP map so clients reach it without DNS. Empty publishes none.

=== "YAML"

    ```yaml
    derp:
      server:
        ipv4: 198.51.100.1
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_IPV4=198.51.100.1
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.ipv4 = "198.51.100.1";
    ```

#### `derp.server.ipv6` { #derp.server.ipv6 data-toc-label="ipv6" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DERP_SERVER_IPV6`

The server's public IPv6 address, published in the DERP map so clients reach it without DNS. Empty publishes none.

=== "YAML"

    ```yaml
    derp:
      server:
        ipv6: 2001:db8::1
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_IPV6=2001:db8::1
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.ipv6 = "2001:db8::1";
    ```

#### `derp.server.automatically_add_embedded_derp_region` { #derp.server.automatically_add_embedded_derp_region data-toc-label="automatically_add_embedded_derp_region" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION`

Adds the embedded server's region to the DERP map. When it is false and [`derp.server.enabled`](#derp.server.enabled) is true, [`derp.paths`](#derp.paths) is required: write the region there yourself.

=== "YAML"

    ```yaml
    derp:
      server:
        automatically_add_embedded_derp_region: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_SERVER_AUTOMATICALLY_ADD_EMBEDDED_DERP_REGION=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.server.automatically_add_embedded_derp_region = false;
    ```

### `derp.urls` { #derp.urls data-toc-label="urls" }

- **Type:** [list of URLs](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_DERP_URLS` ([space-separated or JSON array](#env))

DERP maps in JSON to fetch. One that fails to load is logged and skipped; startup fails only when no region remains.

=== "YAML"

    ```yaml
    derp:
      urls:
        - https://controlplane.tailscale.com/derpmap/default
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_URLS='["https://controlplane.tailscale.com/derpmap/default"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.urls = [
      "https://controlplane.tailscale.com/derpmap/default"
    ];
    ```

### `derp.paths` { #derp.paths data-toc-label="paths" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_DERP_PATHS` ([space-separated or JSON array](#env))

DERP map files. The extension picks the format: `.yaml` or `.yml`, or Tailscale JSON as `.json` or `.hujson`, both accepting comments and trailing commas.

=== "YAML"

    ```yaml
    derp:
      paths:
        - /etc/headscale/derp.yaml
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_PATHS='["/etc/headscale/derp.yaml"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.paths = [
      "/etc/headscale/derp.yaml"
    ];
    ```

Replaces `derp_map_path` ([removed](#derp_map_path)).

### `derp.auto_update_enabled` { #derp.auto_update_enabled data-toc-label="auto_update_enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DERP_AUTO_UPDATE_ENABLED`

Reloads [`derp.urls`](#derp.urls) and [`derp.paths`](#derp.paths) every [`derp.update_frequency`](#derp.update_frequency).

=== "YAML"

    ```yaml
    derp:
      auto_update_enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_AUTO_UPDATE_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.auto_update_enabled = true;
    ```

### `derp.update_frequency` { #derp.update_frequency data-toc-label="update_frequency" }

- **Type:** [duration](#type-duration)
- **Default:** `3h`
- **Env:** `HEADSCALE_DERP_UPDATE_FREQUENCY`

How often [`derp.auto_update_enabled`](#derp.auto_update_enabled) reloads the DERP map. Zero disables reloading.

=== "YAML"

    ```yaml
    derp:
      update_frequency: 24h
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DERP_UPDATE_FREQUENCY=24h
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.derp.update_frequency = "24h";
    ```

## `database` { #database data-toc-label="database" }

Where headscale stores nodes, users and keys. SQLite is recommended; PostgreSQL is supported for legacy deployments only. [`database.sqlite`](#database.sqlite) is read only for SQLite, [`database.postgres`](#database.postgres) only for PostgreSQL.

??? example "All `database` keys and defaults"

    ```yaml
    database:
      type: ""
      debug: false
      gorm:
        slow_threshold: 0
        skip_err_record_not_found: false
        parameterized_queries: false
      sqlite:
        path: ""
        write_ahead_log: true
        wal_autocheckpoint: 1000
      postgres:
        host: ""
        port: 0
        name: ""
        user: ""
        pass: ""
        ssl: "false"
        max_open_conns: 10
        max_idle_conns: 10
        conn_max_idle_time_secs: 3600
    ```

### `database.type` { #database.type data-toc-label="type" }

- **Type:** [enum](#type-enum): `sqlite`, `sqlite3`, `postgres`
- **Required**
- **Env:** `HEADSCALE_DATABASE_TYPE`

The database backend. SQLite is recommended; PostgreSQL is supported for legacy deployments only.

| Value      | Meaning                                                              |
| ---------- | -------------------------------------------------------------------- |
| `sqlite`   | SQLite, in the file [`database.sqlite.path`](#database.sqlite.path). |
| `sqlite3`  | The same as `sqlite`.                                                |
| `postgres` | PostgreSQL, at [`database.postgres.host`](#database.postgres.host).  |

=== "YAML"

    ```yaml
    database:
      type: sqlite
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_TYPE=sqlite
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.type = "sqlite";
    ```

Replaces `db_type` ([removed](#db_type)).

### `database.debug` { #database.debug data-toc-label="debug" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DATABASE_DEBUG`

Turns on query logging: ordinary queries at log level debug, shown only when [`log.level`](#log.level) is `debug` or `trace`, slow ones at warn and failed ones at error. Off, no query is logged. [`database.gorm`](#database.gorm) shapes the query log. See [Database logging](debug.md#database-logging).

=== "YAML"

    ```yaml
    database:
      debug: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_DEBUG=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.debug = true;
    ```

### `database.gorm` { #database.gorm data-toc-label="gorm" }

Query logging, applied only when [`database.debug`](#database.debug) is true.

??? example "All `database.gorm` keys and defaults"

    ```yaml
    database:
      gorm:
        slow_threshold: 0
        skip_err_record_not_found: false
        parameterized_queries: false
    ```

#### `database.gorm.slow_threshold` { #database.gorm.slow_threshold data-toc-label="slow_threshold" }

- **Type:** [integer](#type-integer)
- **Default:** `0`
- **Env:** `HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD`

The query time, in milliseconds, above which a query is logged as a warning. Zero disables the warning.

=== "YAML"

    ```yaml
    database:
      gorm:
        slow_threshold: 1000
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_GORM_SLOW_THRESHOLD=1000
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.gorm.slow_threshold = 1000;
    ```

#### `database.gorm.skip_err_record_not_found` { #database.gorm.skip_err_record_not_found data-toc-label="skip_err_record_not_found" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DATABASE_GORM_SKIP_ERR_RECORD_NOT_FOUND`

Logs a query that finds no record as an ordinary query, not as an error.

=== "YAML"

    ```yaml
    database:
      gorm:
        skip_err_record_not_found: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_GORM_SKIP_ERR_RECORD_NOT_FOUND=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.gorm.skip_err_record_not_found = true;
    ```

#### `database.gorm.parameterized_queries` { #database.gorm.parameterized_queries data-toc-label="parameterized_queries" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DATABASE_GORM_PARAMETERIZED_QUERIES`

Logs queries without their parameter values.

=== "YAML"

    ```yaml
    database:
      gorm:
        parameterized_queries: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_GORM_PARAMETERIZED_QUERIES=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.gorm.parameterized_queries = true;
    ```

### `database.sqlite` { #database.sqlite data-toc-label="sqlite" }

SQLite, read only when [`database.type`](#database.type) is `sqlite` or `sqlite3`.

??? example "All `database.sqlite` keys and defaults"

    ```yaml
    database:
      sqlite:
        path: ""
        write_ahead_log: true
        wal_autocheckpoint: 1000
    ```

#### `database.sqlite.path` { #database.sqlite.path data-toc-label="path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DATABASE_SQLITE_PATH`

The database file, relative to the configuration file; `:memory:` keeps the database in memory.

=== "YAML"

    ```yaml
    database:
      sqlite:
        path: /var/lib/headscale/db.sqlite
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_SQLITE_PATH=/var/lib/headscale/db.sqlite
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.sqlite.path = "/var/lib/headscale/db.sqlite";
    ```

Replaces `db_path` ([removed](#db_path)).

#### `database.sqlite.write_ahead_log` { #database.sqlite.write_ahead_log data-toc-label="write_ahead_log" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG`

Applies [`database.sqlite.wal_autocheckpoint`](#database.sqlite.wal_autocheckpoint) and compacts the database (`VACUUM`) on shutdown. SQLite runs in WAL mode either way; false keeps SQLite's default checkpoint of 1000 frames.

=== "YAML"

    ```yaml
    database:
      sqlite:
        write_ahead_log: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_SQLITE_WRITE_AHEAD_LOG=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.sqlite.write_ahead_log = false;
    ```

#### `database.sqlite.wal_autocheckpoint` { #database.sqlite.wal_autocheckpoint data-toc-label="wal_autocheckpoint" }

- **Type:** [integer](#type-integer)
- **Default:** `1000`
- **Env:** `HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT`

The number of WAL frames after which the WAL is checkpointed automatically; zero disables automatic checkpoints. Applied only when [`database.sqlite.write_ahead_log`](#database.sqlite.write_ahead_log) is true.

=== "YAML"

    ```yaml
    database:
      sqlite:
        wal_autocheckpoint: 2000
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_SQLITE_WAL_AUTOCHECKPOINT=2000
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.sqlite.wal_autocheckpoint = 2000;
    ```

### `database.postgres` { #database.postgres data-toc-label="postgres" }

PostgreSQL, read only when [`database.type`](#database.type) is `postgres`.

??? example "All `database.postgres` keys and defaults"

    ```yaml
    database:
      postgres:
        host: ""
        port: 0
        name: ""
        user: ""
        pass: ""
        ssl: "false"
        max_open_conns: 10
        max_idle_conns: 10
        conn_max_idle_time_secs: 3600
    ```

#### `database.postgres.host` { #database.postgres.host data-toc-label="host" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_HOST`

The server's host name or IP, or the directory of its Unix socket (a path starting with `/`).

=== "YAML"

    ```yaml
    database:
      postgres:
        host: db.example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_HOST=db.example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.host = "db.example.com";
    ```

Replaces `db_host` ([removed](#db_host)).

#### `database.postgres.port` { #database.postgres.port data-toc-label="port" }

- **Type:** [integer](#type-integer)
- **Default:** `0`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_PORT`

The server's port or, with a Unix socket directory in [`database.postgres.host`](#database.postgres.host), the port in the socket's file name. Zero uses the driver's default.

=== "YAML"

    ```yaml
    database:
      postgres:
        port: 5432
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_PORT=5432
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.port = 5432;
    ```

Replaces `db_port` ([removed](#db_port)).

#### `database.postgres.name` { #database.postgres.name data-toc-label="name" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_NAME`

The database name.

=== "YAML"

    ```yaml
    database:
      postgres:
        name: headscale
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_NAME=headscale
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.name = "headscale";
    ```

Replaces `db_name` ([removed](#db_name)).

#### `database.postgres.user` { #database.postgres.user data-toc-label="user" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_USER`

The user to connect as.

=== "YAML"

    ```yaml
    database:
      postgres:
        user: headscale
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_USER=headscale
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.user = "headscale";
    ```

Replaces `db_user` ([removed](#db_user)).

#### `database.postgres.pass` { #database.postgres.pass data-toc-label="pass" }

- **Type:** [secret](#secrets)
- **Default:** `""`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_PASS`

The password, or `file:<path>` to read it from a file, read only when [`database.type`](#database.type) is `postgres`. `headscale generate config --running` and `/debug/config` show a literal password as `<redacted>` and a `file:` reference as written.

=== "YAML"

    ```yaml
    database:
      postgres:
        pass: file:/run/secrets/postgres_password
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_PASS=file:/run/secrets/postgres_password
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.pass = "file:\${CREDENTIALS_DIRECTORY}/database_postgres_pass";
    systemd.services.headscale.serviceConfig.LoadCredential = [ "database_postgres_pass:/run/secrets/postgres_password" ];
    ```

Replaces `db_pass` ([removed](#db_pass)).
Replaces `database.postgres.password_file` ([removed](#database.postgres.password_file)).

#### `database.postgres.ssl` { #database.postgres.ssl data-toc-label="ssl" }

- **Type:** [string](#type-string)
- **Default:** `"false"`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_SSL`

The TLS mode: `true` keeps the driver's default `sslmode`, `false` disables TLS, any other value is passed as `sslmode` (`require`, `verify-full`, ...).

=== "YAML"

    ```yaml
    database:
      postgres:
        ssl: verify-full
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_SSL=verify-full
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.ssl = "verify-full";
    ```

Replaces `db_ssl` ([removed](#db_ssl)).

#### `database.postgres.max_open_conns` { #database.postgres.max_open_conns data-toc-label="max_open_conns" }

- **Type:** [integer](#type-integer)
- **Default:** `10`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS`

Caps open connections to the database.

=== "YAML"

    ```yaml
    database:
      postgres:
        max_open_conns: 20
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_MAX_OPEN_CONNS=20
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.max_open_conns = 20;
    ```

#### `database.postgres.max_idle_conns` { #database.postgres.max_idle_conns data-toc-label="max_idle_conns" }

- **Type:** [integer](#type-integer)
- **Default:** `10`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_MAX_IDLE_CONNS`

Caps idle connections kept in the pool.

=== "YAML"

    ```yaml
    database:
      postgres:
        max_idle_conns: 5
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_MAX_IDLE_CONNS=5
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.max_idle_conns = 5;
    ```

#### `database.postgres.conn_max_idle_time_secs` { #database.postgres.conn_max_idle_time_secs data-toc-label="conn_max_idle_time_secs" }

- **Type:** [integer](#type-integer)
- **Default:** `3600`
- **Env:** `HEADSCALE_DATABASE_POSTGRES_CONN_MAX_IDLE_TIME_SECS`

How long, in seconds, a connection may stay idle before it is closed.

=== "YAML"

    ```yaml
    database:
      postgres:
        conn_max_idle_time_secs: 600
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DATABASE_POSTGRES_CONN_MAX_IDLE_TIME_SECS=600
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.database.postgres.conn_max_idle_time_secs = 600;
    ```

## `dns` { #dns data-toc-label="dns" }

The DNS configuration sent to clients, MagicDNS included, and TLS certificates for nodes. Clients apply it only with `--accept-dns`, their default. See [DNS](dns.md).

Replaces `dns_config` ([removed](#dns_config)).

??? example "All `dns` keys and defaults"

    ```yaml
    dns:
      magic_dns: true
      base_domain: ""
      override_local_dns: true
      nameservers:
        global: []
        split: {}
      search_domains: []
      extra_records: []
      extra_records_path: ""
      certificates:
        enabled: false
        zone: ""
      challenge:
        propagation_timeout: 2m
        resolvers:
          - 9.9.9.9:53
          - 149.112.112.112:53
        provider: {}
    ```

### `dns.magic_dns` { #dns.magic_dns data-toc-label="magic_dns" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_DNS_MAGIC_DNS`

Gives each node a name below [`dns.base_domain`](#dns.base_domain), e.g. `laptop.example.com`, resolved by the client. It requires [`dns.base_domain`](#dns.base_domain).

=== "YAML"

    ```yaml
    dns:
      magic_dns: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_MAGIC_DNS=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.magic_dns = false;
    ```

Replaces `dns_config.magic_dns` ([removed](#dns_config.magic_dns)).

### `dns.base_domain` { #dns.base_domain data-toc-label="base_domain" }

- **Type:** [string](#type-string)
- **Default:** `""`; required when [`dns.magic_dns`](#dns.magic_dns) is true
- **Env:** `HEADSCALE_DNS_BASE_DOMAIN`

The domain MagicDNS names live under, without a trailing dot, e.g. `example.com`. The host of [`server_url`](#server_url) must not be this domain or a name below it: clients take the domain over.

=== "YAML"

    ```yaml
    dns:
      base_domain: tailnet.example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_BASE_DOMAIN=tailnet.example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.base_domain = "tailnet.example.com";
    ```

Replaces `dns_config.base_domain` ([removed](#dns_config.base_domain)).

### `dns.override_local_dns` { #dns.override_local_dns data-toc-label="override_local_dns" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_DNS_OVERRIDE_LOCAL_DNS`

Makes clients use [`dns.nameservers.global`](#dns.nameservers.global) instead of their local DNS settings, which then requires at least one global nameserver. False sends them only as fallback resolvers.

=== "YAML"

    ```yaml
    dns:
      override_local_dns: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_OVERRIDE_LOCAL_DNS=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.override_local_dns = false;
    ```

Replaces `dns_config.override_local_dns` ([removed](#dns_config.override_local_dns)).

### `dns.nameservers` { #dns.nameservers data-toc-label="nameservers" }

The upstream DNS servers sent to clients. An entry that is neither an IP address nor a URL is skipped with a warning.

??? example "All `dns.nameservers` keys and defaults"

    ```yaml
    dns:
      nameservers:
        global: []
        split: {}
    ```

#### `dns.nameservers.global` { #dns.nameservers.global data-toc-label="global" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`; required when [`dns.override_local_dns`](#dns.override_local_dns) is true
- **Env:** `HEADSCALE_DNS_NAMESERVERS_GLOBAL` ([space-separated or JSON array](#env))

The nameservers for names [`dns.nameservers.split`](#dns.nameservers.split) does not cover: IP addresses, or DNS-over-HTTPS URLs such as `https://dns.nextdns.io/<id>`.

=== "YAML"

    ```yaml
    dns:
      nameservers:
        global:
          - 9.9.9.9
          - 149.112.112.112
          - 2620:fe::fe
          - 2620:fe::9
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_NAMESERVERS_GLOBAL='["9.9.9.9","149.112.112.112","2620:fe::fe","2620:fe::9"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.nameservers.global = [
      "9.9.9.9"
      "149.112.112.112"
      "2620:fe::fe"
      "2620:fe::9"
    ];
    ```

Replaces `dns_config.nameservers` ([removed](#dns_config.nameservers)).

#### `dns.nameservers.split` { #dns.nameservers.split data-toc-label="split" }

- **Type:** [map of `<domain>` → list of strings](#type-map)
- **Default:** `{}`
- **Env:** `HEADSCALE_DNS_NAMESERVERS_SPLIT` ([JSON object](#env))

Maps a domain to the nameservers that answer for it (split DNS). Domains are lowercased on load; two that differ only in case are an error.

=== "YAML"

    ```yaml
    dns:
      nameservers:
        split:
          corp.example.com:
            - 192.0.2.53
          lab.example.net:
            - 198.51.100.53
            - 2001:db8::53
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_NAMESERVERS_SPLIT='{"corp.example.com":["192.0.2.53"],"lab.example.net":["198.51.100.53","2001:db8::53"]}'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.nameservers.split = {
      "corp.example.com" = [
        "192.0.2.53"
      ];
      "lab.example.net" = [
        "198.51.100.53"
        "2001:db8::53"
      ];
    };
    ```

Replaces `dns_config.restricted_nameservers` ([removed](#dns_config.restricted_nameservers)).

### `dns.search_domains` { #dns.search_domains data-toc-label="search_domains" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_DNS_SEARCH_DOMAINS` ([space-separated or JSON array](#env))

DNS search domains sent to clients. With MagicDNS, [`dns.base_domain`](#dns.base_domain) comes first.

=== "YAML"

    ```yaml
    dns:
      search_domains:
        - corp.example.com
        - lab.example.net
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_SEARCH_DOMAINS='["corp.example.com","lab.example.net"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.search_domains = [
      "corp.example.com"
      "lab.example.net"
    ];
    ```

Replaces `dns_config.domains` ([removed](#dns_config.domains)).

### `dns.extra_records` { #dns.extra_records data-toc-label="extra_records" }

- **Type:** [list of DNS records](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_DNS_EXTRA_RECORDS` ([JSON array](#env))

DNS records served to clients, each with a `name`, `type` and `value`. Clients support `A` and `AAAA`. Mutually exclusive with [`dns.extra_records_path`](#dns.extra_records_path). See [Setting extra DNS records](dns.md#setting-extra-dns-records).

| Field   | Type                   | Description                                                                                |
| ------- | ---------------------- | ------------------------------------------------------------------------------------------ |
| `name`  | [string](#type-string) | The fully qualified domain name, e.g. `grafana.example.com`; the trailing dot is optional. |
| `type`  | [string](#type-string) | The record type, `A` or `AAAA`; empty picks it from `value`. Clients ignore other types.   |
| `value` | [string](#type-string) | The IP address the name resolves to.                                                       |

=== "YAML"

    ```yaml
    dns:
      extra_records:
        - name: grafana.tailnet.example.com
          type: A
          value: 100.64.0.3
        - name: grafana.tailnet.example.com
          type: AAAA
          value: fd7a:115c:a1e0::3
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_EXTRA_RECORDS='[{"name":"grafana.tailnet.example.com","type":"A","value":"100.64.0.3"},{"name":"grafana.tailnet.example.com","type":"AAAA","value":"fd7a:115c:a1e0::3"}]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.extra_records = [
      {
        name = "grafana.tailnet.example.com";
        type = "A";
        value = "100.64.0.3";
      }
      {
        name = "grafana.tailnet.example.com";
        type = "AAAA";
        value = "fd7a:115c:a1e0::3";
      }
    ];
    ```

Replaces `dns_config.extra_records` ([removed](#dns_config.extra_records)).

### `dns.extra_records_path` { #dns.extra_records_path data-toc-label="extra_records_path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DNS_EXTRA_RECORDS_PATH`

A file of extra records, reloaded when it changes. The extension picks the format: `.json`, `.hujson`, `.yaml` or `.yml`. Mutually exclusive with [`dns.extra_records`](#dns.extra_records).

=== "YAML"

    ```yaml
    dns:
      extra_records_path: /var/lib/headscale/extra-records.json
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_EXTRA_RECORDS_PATH=/var/lib/headscale/extra-records.json
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.extra_records_path = "/var/lib/headscale/extra-records.json";
    ```

### `dns.certificates` { #dns.certificates data-toc-label="certificates" }

Lets nodes get TLS certificates for their MagicDNS names with `tailscale cert`. The node runs ACME itself; headscale publishes its DNS-01 challenge through [`dns.challenge.provider`](#dns.challenge.provider).

??? example "All `dns.certificates` keys and defaults"

    ```yaml
    dns:
      certificates:
        enabled: false
        zone: ""
    ```

#### `dns.certificates.enabled` { #dns.certificates.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_DNS_CERTIFICATES_ENABLED`

Lets nodes run `tailscale cert`. It requires [`dns.magic_dns`](#dns.magic_dns), a lowercase [`dns.base_domain`](#dns.base_domain) and [`dns.challenge.provider`](#dns.challenge.provider).

=== "YAML"

    ```yaml
    dns:
      certificates:
        enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_CERTIFICATES_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.certificates.enabled = true;
    ```

#### `dns.certificates.zone` { #dns.certificates.zone data-toc-label="zone" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_DNS_CERTIFICATES_ZONE`

The public DNS zone challenge records are written to, when [`dns.base_domain`](#dns.base_domain) sits below the zone apex. It must contain [`dns.base_domain`](#dns.base_domain). Empty uses [`dns.base_domain`](#dns.base_domain).

=== "YAML"

    ```yaml
    dns:
      certificates:
        zone: example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_CERTIFICATES_ZONE=example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.certificates.zone = "example.com";
    ```

### `dns.challenge` { #dns.challenge data-toc-label="challenge" }

The DNS provider answering ACME DNS-01 challenges, for node certificates and for headscale's own certificate when [`tls.acme.challenge_type`](#tls.acme.challenge_type) is `DNS-01`. See [DNS-01 challenge provider](dns.md#dns-01-challenge-provider).

??? example "All `dns.challenge` keys and defaults"

    ```yaml
    dns:
      challenge:
        propagation_timeout: 2m
        resolvers:
          - 9.9.9.9:53
          - 149.112.112.112:53
        provider: {}
    ```

#### `dns.challenge.propagation_timeout` { #dns.challenge.propagation_timeout data-toc-label="propagation_timeout" }

- **Type:** [duration](#type-duration)
- **Default:** `2m`
- **Env:** `HEADSCALE_DNS_CHALLENGE_PROPAGATION_TIMEOUT`

How long to wait for a challenge record to show up on every authoritative nameserver. Zero skips the check.

=== "YAML"

    ```yaml
    dns:
      challenge:
        propagation_timeout: 5m
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_CHALLENGE_PROPAGATION_TIMEOUT=5m
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.challenge.propagation_timeout = "5m";
    ```

#### `dns.challenge.resolvers` { #dns.challenge.resolvers data-toc-label="resolvers" }

- **Type:** [list of strings](#type-list)
- **Default:** `['9.9.9.9:53', '149.112.112.112:53']`
- **Env:** `HEADSCALE_DNS_CHALLENGE_RESOLVERS` ([space-separated or JSON array](#env))

The servers asked for the zone's nameservers, each an IP or host with an optional port (53 if omitted). Empty uses the default public resolvers. The system resolver is never used: on a host running MagicDNS it answers for [`dns.base_domain`](#dns.base_domain) itself.

=== "YAML"

    ```yaml
    dns:
      challenge:
        resolvers:
          - 9.9.9.9:53
          - '[2620:fe::fe]:53'
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_CHALLENGE_RESOLVERS='["9.9.9.9:53","[2620:fe::fe]:53"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.challenge.resolvers = [
      "9.9.9.9:53"
      "[2620:fe::fe]:53"
    ];
    ```

#### `dns.challenge.provider` { #dns.challenge.provider data-toc-label="provider" }

- **Type:** [map of `<setting>` → value](#type-map)
- **Default:** `{}`
- **Env:** `HEADSCALE_DNS_CHALLENGE_PROVIDER` ([JSON object](#env))

The DNS provider that writes challenge records: `name` selects it, the other keys are its settings. Keys are lowercased on load, at every depth; two that differ only in case are an error. A string setting may be `file:<path>` to read it from a file. `headscale generate config --running` and `/debug/config` show `name` and `file:` references; every other setting is `<redacted>`, as any may be a credential. See [DNS-01 challenge provider](dns.md#dns-01-challenge-provider) to set a provider up, acme-dns included, and to set it from environment variables.

| Provider     | Settings                                                    |
| ------------ | ----------------------------------------------------------- |
| `acmedns`    | `config`, `password`, `server_url`, `subdomain`, `username` |
| `cloudflare` | `api_token`, `zone_token`                                   |
| `gigahost`   | `api_key`                                                   |
| `hetzner`    | `api_token`                                                 |
| `powerdns`   | `api_token`, `debug`, `server_id`, `server_url`             |
| `rfc2136`    | `key`, `key_alg`, `key_name`, `server`                      |

Each text setting can also be set on its own as `HEADSCALE_DNS_CHALLENGE_PROVIDER_<SETTING>`, e.g. `HEADSCALE_DNS_CHALLENGE_PROVIDER_API_TOKEN`, which wins over the same setting in `HEADSCALE_DNS_CHALLENGE_PROVIDER` and in the configuration file. An object setting, such as the `config` of `acmedns`, goes inside the JSON object of `HEADSCALE_DNS_CHALLENGE_PROVIDER`; see [Environment variables](dns.md#environment-variables).

=== "YAML"

    ```yaml
    dns:
      challenge:
        provider:
          api_token: file:/run/secrets/cloudflare
          name: cloudflare
    ```

=== "Environment"

    ```shell
    export HEADSCALE_DNS_CHALLENGE_PROVIDER='{"api_token":"file:/run/secrets/cloudflare","name":"cloudflare"}'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.dns.challenge.provider = {
      api_token = "file:\${CREDENTIALS_DIRECTORY}/dns_challenge_provider_api_token";
      name = "cloudflare";
    };
    systemd.services.headscale.serviceConfig.LoadCredential = [ "dns_challenge_provider_api_token:/run/secrets/cloudflare" ];
    ```

## `tls` { #tls data-toc-label="tls" }

Headscale's own HTTPS certificate on [`listen_addr`](#listen_addr): from the files [`tls.cert_path`](#tls.cert_path) and [`tls.key_path`](#tls.key_path), or from ACME in [`tls.acme`](#tls.acme), not both. Without either, the server speaks plain HTTP. See [TLS](tls.md).

??? example "All `tls` keys and defaults"

    ```yaml
    tls:
      cert_path: ""
      key_path: ""
      acme:
        hostname: ""
        challenge_type: HTTP-01
        http_listen: :http
        url: ""
        email: ""
        cache_dir: /var/lib/headscale/cache
    ```

### `tls.cert_path` { #tls.cert_path data-toc-label="cert_path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_TLS_CERT_PATH`

The PEM certificate file, relative to the configuration file. Setting it turns TLS on.

=== "YAML"

    ```yaml
    tls:
      cert_path: /etc/headscale/tls/cert.pem
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_CERT_PATH=/etc/headscale/tls/cert.pem
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.cert_path = "/etc/headscale/tls/cert.pem";
    ```

Replaces `tls_cert_path` ([removed](#tls_cert_path)).

### `tls.key_path` { #tls.key_path data-toc-label="key_path" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_TLS_KEY_PATH`

The PEM private key file of [`tls.cert_path`](#tls.cert_path), relative to the configuration file.

=== "YAML"

    ```yaml
    tls:
      key_path: /etc/headscale/tls/key.pem
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_KEY_PATH=/etc/headscale/tls/key.pem
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.key_path = "/etc/headscale/tls/key.pem";
    ```

Replaces `tls_key_path` ([removed](#tls_key_path)).

### `tls.acme` { #tls.acme data-toc-label="acme" }

Gets the certificate from an ACME CA such as Let's Encrypt, and renews it. Setting [`tls.acme.hostname`](#tls.acme.hostname) turns it on.

??? example "All `tls.acme` keys and defaults"

    ```yaml
    tls:
      acme:
        hostname: ""
        challenge_type: HTTP-01
        http_listen: :http
        url: ""
        email: ""
        cache_dir: /var/lib/headscale/cache
    ```

#### `tls.acme.hostname` { #tls.acme.hostname data-toc-label="hostname" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_TLS_ACME_HOSTNAME`

The domain to request a certificate for. Setting it turns ACME on.

=== "YAML"

    ```yaml
    tls:
      acme:
        hostname: headscale.example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_HOSTNAME=headscale.example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.hostname = "headscale.example.com";
    ```

Replaces `tls_letsencrypt_hostname` ([removed](#tls_letsencrypt_hostname)).

#### `tls.acme.challenge_type` { #tls.acme.challenge_type data-toc-label="challenge_type" }

- **Type:** [enum](#type-enum): `HTTP-01`, `TLS-ALPN-01`, `DNS-01`
- **Default:** `HTTP-01`
- **Env:** `HEADSCALE_TLS_ACME_CHALLENGE_TYPE`

How the CA verifies that headscale controls [`tls.acme.hostname`](#tls.acme.hostname).

| Value         | Meaning                                                                                                                                                                     |
| ------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `HTTP-01`     | Has the CA fetch a token over HTTP on port 80, answered on [`tls.acme.http_listen`](#tls.acme.http_listen). TLS-ALPN-01 on [`listen_addr`](#listen_addr) stays enabled too. |
| `TLS-ALPN-01` | Has the CA check a special certificate on port 443, answered on [`listen_addr`](#listen_addr), which must be reachable there.                                               |
| `DNS-01`      | Has the CA look up a TXT record, which headscale writes through [`dns.challenge.provider`](#dns.challenge.provider). It needs no open port.                                 |

=== "YAML"

    ```yaml
    tls:
      acme:
        challenge_type: TLS-ALPN-01
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_CHALLENGE_TYPE=TLS-ALPN-01
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.challenge_type = "TLS-ALPN-01";
    ```

Replaces `tls_letsencrypt_challenge_type` ([removed](#tls_letsencrypt_challenge_type)).

#### `tls.acme.http_listen` { #tls.acme.http_listen data-toc-label="http_listen" }

- **Type:** [listen address](#type-listen-address)
- **Default:** `:http`
- **Env:** `HEADSCALE_TLS_ACME_HTTP_LISTEN`

The host:port serving HTTP-01 challenges; the port may be a name, as in `:http` for port 80. Other requests to it are redirected to [`server_url`](#server_url).

=== "YAML"

    ```yaml
    tls:
      acme:
        http_listen: 0.0.0.0:80
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_HTTP_LISTEN=0.0.0.0:80
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.http_listen = "0.0.0.0:80";
    ```

Replaces `tls_letsencrypt_listen` ([removed](#tls_letsencrypt_listen)).

#### `tls.acme.url` { #tls.acme.url data-toc-label="url" }

- **Type:** [URL](#type-URL)
- **Default:** `""`
- **Env:** `HEADSCALE_TLS_ACME_URL`

The CA's ACME directory. Empty uses Let's Encrypt.

=== "YAML"

    ```yaml
    tls:
      acme:
        url: https://acme-staging-v02.api.letsencrypt.org/directory
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_URL=https://acme-staging-v02.api.letsencrypt.org/directory
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.url = "https://acme-staging-v02.api.letsencrypt.org/directory";
    ```

Replaces `acme_url` ([removed](#acme_url)).

#### `tls.acme.email` { #tls.acme.email data-toc-label="email" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_TLS_ACME_EMAIL`

The contact address registered with the CA.

=== "YAML"

    ```yaml
    tls:
      acme:
        email: admin@example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_EMAIL=admin@example.com
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.email = "admin@example.com";
    ```

Replaces `acme_email` ([removed](#acme_email)).

#### `tls.acme.cache_dir` { #tls.acme.cache_dir data-toc-label="cache_dir" }

- **Type:** [string](#type-string)
- **Default:** `/var/lib/headscale/cache`
- **Env:** `HEADSCALE_TLS_ACME_CACHE_DIR`

Where certificates and ACME account data are stored, relative to the configuration file.

=== "YAML"

    ```yaml
    tls:
      acme:
        cache_dir: /var/cache/headscale/acme
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TLS_ACME_CACHE_DIR=/var/cache/headscale/acme
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tls.acme.cache_dir = "/var/cache/headscale/acme";
    ```

Replaces `tls_letsencrypt_cache_dir` ([removed](#tls_letsencrypt_cache_dir)).

## `oidc` { #oidc data-toc-label="oidc" }

Login through an OpenID Connect provider. Setting [`oidc.issuer`](#oidc.issuer) turns it on and requires [`oidc.client_id`](#oidc.client_id) and [`oidc.client_secret`](#oidc.client_secret). See [OpenID Connect](oidc.md).

??? example "All `oidc` keys and defaults"

    ```yaml
    oidc:
      only_start_if_oidc_is_available: true
      issuer: ""
      client_id: ""
      client_secret: ""
      scope:
        - openid
        - profile
        - email
      extra_params: {}
      allowed_domains: []
      allowed_users: []
      allowed_groups: []
      email_verified_required: true
      use_expiry_from_token: false
      pkce:
        enabled: false
        method: S256
    ```

### `oidc.only_start_if_oidc_is_available` { #oidc.only_start_if_oidc_is_available data-toc-label="only_start_if_oidc_is_available" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_OIDC_ONLY_START_IF_OIDC_IS_AVAILABLE`

Stops startup when the provider cannot be reached. False starts without OIDC, with CLI-based registration.

=== "YAML"

    ```yaml
    oidc:
      only_start_if_oidc_is_available: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_ONLY_START_IF_OIDC_IS_AVAILABLE=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.only_start_if_oidc_is_available = false;
    ```

### `oidc.issuer` { #oidc.issuer data-toc-label="issuer" }

- **Type:** [URL](#type-URL)
- **Default:** `""`
- **Env:** `HEADSCALE_OIDC_ISSUER`

The provider's issuer URL. Setting it turns OIDC on.

=== "YAML"

    ```yaml
    oidc:
      issuer: https://idp.example.com/realms/headscale
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_ISSUER=https://idp.example.com/realms/headscale
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.issuer = "https://idp.example.com/realms/headscale";
    ```

### `oidc.client_id` { #oidc.client_id data-toc-label="client_id" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_OIDC_CLIENT_ID`

The client ID from the provider; required when [`oidc.issuer`](#oidc.issuer) is set.

=== "YAML"

    ```yaml
    oidc:
      client_id: headscale
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_CLIENT_ID=headscale
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.client_id = "headscale";
    ```

### `oidc.client_secret` { #oidc.client_secret data-toc-label="client_secret" }

- **Type:** [secret](#secrets)
- **Default:** `""`
- **Env:** `HEADSCALE_OIDC_CLIENT_SECRET`

The client secret from the provider, or `file:<path>` to read it from a file; required when [`oidc.issuer`](#oidc.issuer) is set. `headscale generate config --running` and `/debug/config` show a literal secret as `<redacted>` and a `file:` reference as written.

=== "YAML"

    ```yaml
    oidc:
      client_secret: file:/run/secrets/oidc_client_secret
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_CLIENT_SECRET=file:/run/secrets/oidc_client_secret
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.client_secret = "file:\${CREDENTIALS_DIRECTORY}/oidc_client_secret";
    systemd.services.headscale.serviceConfig.LoadCredential = [ "oidc_client_secret:/run/secrets/oidc_client_secret" ];
    ```

Replaces `oidc.client_secret_path` ([removed](#oidc.client_secret_path)).

### `oidc.scope` { #oidc.scope data-toc-label="scope" }

- **Type:** [list of strings](#type-list)
- **Default:** `[openid, profile, email]`
- **Env:** `HEADSCALE_OIDC_SCOPE` ([space-separated or JSON array](#env))

The scopes requested; include `openid`.

=== "YAML"

    ```yaml
    oidc:
      scope:
        - openid
        - profile
        - email
        - groups
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_SCOPE='["openid","profile","email","groups"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.scope = [
      "openid"
      "profile"
      "email"
      "groups"
    ];
    ```

### `oidc.extra_params` { #oidc.extra_params data-toc-label="extra_params" }

- **Type:** [map of `<param>` → string](#type-map)
- **Default:** `{}`
- **Env:** `HEADSCALE_OIDC_EXTRA_PARAMS` ([JSON object](#env))

Sent as is to the provider's authorization endpoint, e.g. `domain_hint`; names keep their case.

=== "YAML"

    ```yaml
    oidc:
      extra_params:
        domain_hint: example.com
        prompt: select_account
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_EXTRA_PARAMS='{"domain_hint":"example.com","prompt":"select_account"}'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.extra_params = {
      domain_hint = "example.com";
      prompt = "select_account";
    };
    ```

### `oidc.allowed_domains` { #oidc.allowed_domains data-toc-label="allowed_domains" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_OIDC_ALLOWED_DOMAINS` ([space-separated or JSON array](#env))

Admits only users whose email domain is listed. Empty admits any domain.

=== "YAML"

    ```yaml
    oidc:
      allowed_domains:
        - example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_ALLOWED_DOMAINS='["example.com"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.allowed_domains = [
      "example.com"
    ];
    ```

### `oidc.allowed_users` { #oidc.allowed_users data-toc-label="allowed_users" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_OIDC_ALLOWED_USERS` ([space-separated or JSON array](#env))

Admits only users whose email address is listed. Empty admits any user.

=== "YAML"

    ```yaml
    oidc:
      allowed_users:
        - alice@example.com
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_ALLOWED_USERS='["alice@example.com"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.allowed_users = [
      "alice@example.com"
    ];
    ```

### `oidc.allowed_groups` { #oidc.allowed_groups data-toc-label="allowed_groups" }

- **Type:** [list of strings](#type-list)
- **Default:** `[]`
- **Env:** `HEADSCALE_OIDC_ALLOWED_GROUPS` ([space-separated or JSON array](#env))

Admits only members of at least one listed group, from the provider's `groups` claim: UserInfo first, the ID token as fallback. Empty admits any group.

=== "YAML"

    ```yaml
    oidc:
      allowed_groups:
        - headscale-users
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_ALLOWED_GROUPS='["headscale-users"]'
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.allowed_groups = [
      "headscale-users"
    ];
    ```

### `oidc.email_verified_required` { #oidc.email_verified_required data-toc-label="email_verified_required" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED`

Trusts an email only when the provider marks it verified: an unverified one fails [`oidc.allowed_domains`](#oidc.allowed_domains) and [`oidc.allowed_users`](#oidc.allowed_users) and is not copied to the user. Turn it off for a provider that does not send `email_verified`.

=== "YAML"

    ```yaml
    oidc:
      email_verified_required: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_EMAIL_VERIFIED_REQUIRED=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.email_verified_required = false;
    ```

### `oidc.use_expiry_from_token` { #oidc.use_expiry_from_token data-toc-label="use_expiry_from_token" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN`

Expires an OIDC-registered node with its token, instead of [`node.expiry`](#node.expiry). Tokens are often short-lived, forcing frequent logins.

=== "YAML"

    ```yaml
    oidc:
      use_expiry_from_token: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_USE_EXPIRY_FROM_TOKEN=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.use_expiry_from_token = true;
    ```

### `oidc.pkce` { #oidc.pkce data-toc-label="pkce" }

Proof Key for Code Exchange (RFC 7636), which protects the authorization code from interception. See [Enable PKCE](oidc.md#enable-pkce-recommended).

??? example "All `oidc.pkce` keys and defaults"

    ```yaml
    oidc:
      pkce:
        enabled: false
        method: S256
    ```

#### `oidc.pkce.enabled` { #oidc.pkce.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_OIDC_PKCE_ENABLED`

Sends a PKCE challenge with each login.

=== "YAML"

    ```yaml
    oidc:
      pkce:
        enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_PKCE_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.pkce.enabled = true;
    ```

#### `oidc.pkce.method` { #oidc.pkce.method data-toc-label="method" }

- **Type:** [enum](#type-enum): `plain`, `S256`
- **Default:** `S256`
- **Env:** `HEADSCALE_OIDC_PKCE_METHOD`

How the code challenge is derived from the verifier. The verifier is sent as is in the token exchange.

| Value   | Meaning                                                                                               |
| ------- | ----------------------------------------------------------------------------------------------------- |
| `plain` | Sends the verifier itself as the challenge. Use it only with a provider that does not support `S256`. |
| `S256`  | Sends the base64url SHA-256 of the verifier as the challenge. Recommended.                            |

=== "YAML"

    ```yaml
    oidc:
      pkce:
        method: plain
    ```

=== "Environment"

    ```shell
    export HEADSCALE_OIDC_PKCE_METHOD=plain
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.oidc.pkce.method = "plain";
    ```

## `logtail` { #logtail data-toc-label="logtail" }

Whether nodes send their logs to Tailscale.

??? example "All `logtail` keys and defaults"

    ```yaml
    logtail:
      enabled: false
    ```

### `logtail.enabled` { #logtail.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_LOGTAIL_ENABLED`

Lets nodes send their logs to Tailscale Inc.; headscale cannot point them at another log server. False tells nodes not to.

=== "YAML"

    ```yaml
    logtail:
      enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_LOGTAIL_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.logtail.enabled = true;
    ```

## `taildrop` { #taildrop data-toc-label="taildrop" }

Taildrop, Tailscale's file sharing between nodes.

??? example "All `taildrop` keys and defaults"

    ```yaml
    taildrop:
      enabled: true
    ```

### `taildrop.enabled` { #taildrop.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `true`
- **Env:** `HEADSCALE_TAILDROP_ENABLED`

Gives every node the file-sharing capability. False omits it from the baseline; a policy `nodeAttrs` grant can still give it.

=== "YAML"

    ```yaml
    taildrop:
      enabled: false
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TAILDROP_ENABLED=false
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.taildrop.enabled = false;
    ```

## `auto_update` { #auto_update data-toc-label="auto_update" }

The tailnet-wide default for client auto-updates.

??? example "All `auto_update` keys and defaults"

    ```yaml
    auto_update:
      enabled: false
    ```

### `auto_update.enabled` { #auto_update.enabled data-toc-label="enabled" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_AUTO_UPDATE_ENABLED`

Makes auto-update the default for clients that have not chosen locally. Clients store the default they first see, so a later change reaches only new clients.

=== "YAML"

    ```yaml
    auto_update:
      enabled: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_AUTO_UPDATE_ENABLED=true
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.auto_update.enabled = true;
    ```

## `cli` { #cli data-toc-label="cli" }

How the headscale CLI reaches the server: the local [`unix_socket`](#unix_socket) without authentication, or a remote [`cli.address`](#cli.address) with [`cli.api_key`](#cli.api_key). The CLI reads these keys from its own configuration, such as `~/.config/headscale/config.yaml`, or from `HEADSCALE_CLI_*` variables; the server does not read them, so on NixOS they do not belong in `services.headscale.settings`. See [Remote control](api.md#remote-control).

??? example "All `cli` keys and defaults"

    ```yaml
    cli:
      address: ""
      api_key: ""
      timeout: 5s
      insecure: false
    ```

### `cli.address` { #cli.address data-toc-label="address" }

- **Type:** [string](#type-string)
- **Default:** `""`
- **Env:** `HEADSCALE_CLI_ADDRESS`

The remote server's host:port or URL; `https://` is assumed without a scheme. Empty uses [`unix_socket`](#unix_socket).

=== "YAML"

    ```yaml
    cli:
      address: headscale.example.com:443
    ```

=== "Environment"

    ```shell
    export HEADSCALE_CLI_ADDRESS=headscale.example.com:443
    ```

### `cli.api_key` { #cli.api_key data-toc-label="api_key" }

- **Type:** [secret](#secrets)
- **Default:** `""`
- **Env:** `HEADSCALE_CLI_API_KEY`

The API key the CLI sends to [`cli.address`](#cli.address), or `file:<path>` to read it from a file. Read only by the CLI.

=== "YAML"

    ```yaml
    cli:
      api_key: file:/run/secrets/headscale_api_key
    ```

=== "Environment"

    ```shell
    export HEADSCALE_CLI_API_KEY=file:/run/secrets/headscale_api_key
    ```

### `cli.timeout` { #cli.timeout data-toc-label="timeout" }

- **Type:** [duration](#type-duration)
- **Default:** `5s`
- **Env:** `HEADSCALE_CLI_TIMEOUT`

Bounds each CLI command's requests to the server.

=== "YAML"

    ```yaml
    cli:
      timeout: 30s
    ```

=== "Environment"

    ```shell
    export HEADSCALE_CLI_TIMEOUT=30s
    ```

### `cli.insecure` { #cli.insecure data-toc-label="insecure" }

- **Type:** [boolean](#type-boolean)
- **Default:** `false`
- **Env:** `HEADSCALE_CLI_INSECURE`

Skips TLS certificate verification of [`cli.address`](#cli.address).

=== "YAML"

    ```yaml
    cli:
      insecure: true
    ```

=== "Environment"

    ```shell
    export HEADSCALE_CLI_INSECURE=true
    ```

## `tuning` { #tuning data-toc-label="tuning" }

Holds performance settings that rarely need changing.

??? example "All `tuning` keys and defaults"

    ```yaml
    tuning:
      batch_change_delay: 800ms
      node_mapsession_buffered_chan_size: 30
      batcher_workers: 0
      register_cache_expiration: 15m
      register_cache_max_entries: 1024
      node_store_batch_size: 100
      node_store_batch_timeout: 500ms
    ```

### `tuning.batch_change_delay` { #tuning.batch_change_delay data-toc-label="batch_change_delay" }

- **Type:** [duration](#type-duration)
- **Default:** `800ms`
- **Env:** `HEADSCALE_TUNING_BATCH_CHANGE_DELAY`

How often queued changes are sent to clients as one update; must be positive.

=== "YAML"

    ```yaml
    tuning:
      batch_change_delay: 500ms
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_BATCH_CHANGE_DELAY=500ms
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.batch_change_delay = "500ms";
    ```

### `tuning.node_mapsession_buffered_chan_size` { #tuning.node_mapsession_buffered_chan_size data-toc-label="node_mapsession_buffered_chan_size" }

- **Type:** [integer](#type-integer)
- **Default:** `30`
- **Env:** `HEADSCALE_TUNING_NODE_MAPSESSION_BUFFERED_CHAN_SIZE`

How many map updates are queued per connected client.

=== "YAML"

    ```yaml
    tuning:
      node_mapsession_buffered_chan_size: 60
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_NODE_MAPSESSION_BUFFERED_CHAN_SIZE=60
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.node_mapsession_buffered_chan_size = 60;
    ```

### `tuning.batcher_workers` { #tuning.batcher_workers data-toc-label="batcher_workers" }

- **Type:** [integer](#type-integer)
- **Default:** `0` (three quarters of the CPU cores, at least one)
- **Env:** `HEADSCALE_TUNING_BATCHER_WORKERS`

The number of workers building map updates for connected clients. Zero picks the number from the CPU count.

=== "YAML"

    ```yaml
    tuning:
      batcher_workers: 8
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_BATCHER_WORKERS=8
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.batcher_workers = 8;
    ```

### `tuning.register_cache_expiration` { #tuning.register_cache_expiration data-toc-label="register_cache_expiration" }

- **Type:** [duration](#type-duration)
- **Default:** `15m`
- **Env:** `HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION`

How long a pending registration waits to be completed. Zero uses the default.

=== "YAML"

    ```yaml
    tuning:
      register_cache_expiration: 30m
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION=30m
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.register_cache_expiration = "30m";
    ```

### `tuning.register_cache_max_entries` { #tuning.register_cache_max_entries data-toc-label="register_cache_max_entries" }

- **Type:** [integer](#type-integer)
- **Default:** `1024`
- **Env:** `HEADSCALE_TUNING_REGISTER_CACHE_MAX_ENTRIES`

Bounds pending registrations. At capacity, new registrations are refused without evicting pending ones; SSH checks have a small reserve beyond it. Zero uses the default. See [Pending authentication limits](registration.md#pending-authentication-limits).

=== "YAML"

    ```yaml
    tuning:
      register_cache_max_entries: 4096
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_REGISTER_CACHE_MAX_ENTRIES=4096
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.register_cache_max_entries = 4096;
    ```

### `tuning.node_store_batch_size` { #tuning.node_store_batch_size data-toc-label="node_store_batch_size" }

- **Type:** [integer](#type-integer)
- **Default:** `100`
- **Env:** `HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE`

How many node changes are batched before the in-memory node state, peer relationships included, is rebuilt; must be positive. Higher values save CPU on bulk changes but delay each change until its batch is full or [`tuning.node_store_batch_timeout`](#tuning.node_store_batch_timeout) passes.

=== "YAML"

    ```yaml
    tuning:
      node_store_batch_size: 200
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_NODE_STORE_BATCH_SIZE=200
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.node_store_batch_size = 200;
    ```

### `tuning.node_store_batch_timeout` { #tuning.node_store_batch_timeout data-toc-label="node_store_batch_timeout" }

- **Type:** [duration](#type-duration)
- **Default:** `500ms`
- **Env:** `HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT`

The longest a partial batch of node changes waits before the rebuild; must be positive. Lower values answer single changes faster at the cost of more rebuilds.

=== "YAML"

    ```yaml
    tuning:
      node_store_batch_timeout: 1s
    ```

=== "Environment"

    ```shell
    export HEADSCALE_TUNING_NODE_STORE_BATCH_TIMEOUT=1s
    ```

=== "NixOS"

    ```nix
    services.headscale.settings.tuning.node_store_batch_timeout = "1s";
    ```

## Removed keys { #removed-keys }

Keys headscale no longer reads. One in the configuration file stops headscale with an error and a variable for
one logs a warning, each saying what to do instead, as the table does.

| Key                                                                                           | Removed in | What to do                                                                                                                                                                                                                                     |
| --------------------------------------------------------------------------------------------- | ---------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| <span id="acl_policy_path"></span>`acl_policy_path`                                           | 0.30       | use [`policy.path`](#policy.path)                                                                                                                                                                                                              |
| <span id="acme_email"></span>`acme_email`                                                     | 0.30       | use [`tls.acme.email`](#tls.acme.email)                                                                                                                                                                                                        |
| <span id="acme_url"></span>`acme_url`                                                         | 0.30       | use [`tls.acme.url`](#tls.acme.url)                                                                                                                                                                                                            |
| <span id="changes_check_interval"></span>`changes_check_interval`                             | 0.30       | remove `changes_check_interval`; see the CHANGELOG for context                                                                                                                                                                                 |
| <span id="database.gorm.prepare_stmt"></span>`database.gorm.prepare_stmt`                     | 0.30       | remove `database.gorm.prepare_stmt`; see the CHANGELOG for context                                                                                                                                                                             |
| <span id="database.postgres.password_file"></span>`database.postgres.password_file`           | 0.30       | use [`database.postgres.pass`](#database.postgres.pass): `file:<path>`                                                                                                                                                                         |
| <span id="db_host"></span>`db_host`                                                           | 0.30       | use [`database.postgres.host`](#database.postgres.host)                                                                                                                                                                                        |
| <span id="db_name"></span>`db_name`                                                           | 0.30       | use [`database.postgres.name`](#database.postgres.name)                                                                                                                                                                                        |
| <span id="db_pass"></span>`db_pass`                                                           | 0.30       | use [`database.postgres.pass`](#database.postgres.pass)                                                                                                                                                                                        |
| <span id="db_path"></span>`db_path`                                                           | 0.30       | use [`database.sqlite.path`](#database.sqlite.path)                                                                                                                                                                                            |
| <span id="db_port"></span>`db_port`                                                           | 0.30       | use [`database.postgres.port`](#database.postgres.port)                                                                                                                                                                                        |
| <span id="db_ssl"></span>`db_ssl`                                                             | 0.30       | use [`database.postgres.ssl`](#database.postgres.ssl)                                                                                                                                                                                          |
| <span id="db_type"></span>`db_type`                                                           | 0.30       | use [`database.type`](#database.type)                                                                                                                                                                                                          |
| <span id="db_user"></span>`db_user`                                                           | 0.30       | use [`database.postgres.user`](#database.postgres.user)                                                                                                                                                                                        |
| <span id="derp.server.stun.enabled"></span>`derp.server.stun.enabled`                         | 0.30       | remove it: headscale never read it; the embedded DERP server always serves STUN on [`derp.server.stun_listen_addr`](#derp.server.stun_listen_addr)                                                                                             |
| <span id="derp_map_path"></span>`derp_map_path`                                               | 0.30       | use [`derp.paths`](#derp.paths)                                                                                                                                                                                                                |
| <span id="dns.challenge.provider.setting_path"></span>`dns.challenge.provider.<setting>_path` | 0.30       | use [`dns.challenge.provider.<setting>`](#dns.challenge.provider): `file:<path>`                                                                                                                                                               |
| <span id="dns.use_username_in_magic_dns"></span>`dns.use_username_in_magic_dns`               | 0.24       | remove `dns.use_username_in_magic_dns`; see the CHANGELOG for context                                                                                                                                                                          |
| <span id="dns_config"></span>`dns_config`                                                     | 0.30       | move every `dns_config.*` key to dns (nameservers to [`dns.nameservers.global`](#dns.nameservers.global), restricted_nameservers to [`dns.nameservers.split`](#dns.nameservers.split), domains to [`dns.search_domains`](#dns.search_domains)) |
| <span id="dns_config.base_domain"></span>`dns_config.base_domain`                             | 0.30       | use [`dns.base_domain`](#dns.base_domain)                                                                                                                                                                                                      |
| <span id="dns_config.domains"></span>`dns_config.domains`                                     | 0.30       | use [`dns.search_domains`](#dns.search_domains)                                                                                                                                                                                                |
| <span id="dns_config.extra_records"></span>`dns_config.extra_records`                         | 0.30       | use [`dns.extra_records`](#dns.extra_records)                                                                                                                                                                                                  |
| <span id="dns_config.magic_dns"></span>`dns_config.magic_dns`                                 | 0.30       | use [`dns.magic_dns`](#dns.magic_dns)                                                                                                                                                                                                          |
| <span id="dns_config.nameservers"></span>`dns_config.nameservers`                             | 0.30       | use [`dns.nameservers.global`](#dns.nameservers.global)                                                                                                                                                                                        |
| <span id="dns_config.override_local_dns"></span>`dns_config.override_local_dns`               | 0.30       | use [`dns.override_local_dns`](#dns.override_local_dns)                                                                                                                                                                                        |
| <span id="dns_config.restricted_nameservers"></span>`dns_config.restricted_nameservers`       | 0.30       | use [`dns.nameservers.split`](#dns.nameservers.split)                                                                                                                                                                                          |
| <span id="dns_config.use_username_in_magic_dns"></span>`dns_config.use_username_in_magic_dns` | 0.24       | remove `dns_config.use_username_in_magic_dns`; see the CHANGELOG for context                                                                                                                                                                   |
| <span id="ephemeral_node_inactivity_timeout"></span>`ephemeral_node_inactivity_timeout`       | 0.30       | use [`node.ephemeral.inactivity_timeout`](#node.ephemeral.inactivity_timeout)                                                                                                                                                                  |
| <span id="grpc_allow_insecure"></span>`grpc_allow_insecure`                                   | 0.30       | remove `grpc_allow_insecure`; see the CHANGELOG for context                                                                                                                                                                                    |
| <span id="grpc_listen_addr"></span>`grpc_listen_addr`                                         | 0.30       | remove `grpc_listen_addr`; see the CHANGELOG for context                                                                                                                                                                                       |
| <span id="ip_prefixes"></span>`ip_prefixes`                                                   | 0.23       | use [`prefixes.v4`](#prefixes.v4) and [`prefixes.v6`](#prefixes.v6)                                                                                                                                                                            |
| <span id="json_logs"></span>`json_logs`                                                       | 0.30       | use [`log.format`](#log.format): `json`                                                                                                                                                                                                        |
| <span id="log_level"></span>`log_level`                                                       | 0.17       | use [`log.level`](#log.level)                                                                                                                                                                                                                  |
| <span id="metrics_enabled"></span>`metrics_enabled`                                           | 0.30       | remove `metrics_enabled`; see the CHANGELOG for context                                                                                                                                                                                        |
| <span id="node_update_check_interval"></span>`node_update_check_interval`                     | 0.30       | remove `node_update_check_interval`; see the CHANGELOG for context                                                                                                                                                                             |
| <span id="noise_private_key_path"></span>`noise_private_key_path`                             | 0.30       | use [`noise.private_key_path`](#noise.private_key_path)                                                                                                                                                                                        |
| <span id="oidc.client_secret_path"></span>`oidc.client_secret_path`                           | 0.30       | use [`oidc.client_secret`](#oidc.client_secret): `file:<path>`                                                                                                                                                                                 |
| <span id="oidc.domain_map"></span>`oidc.domain_map`                                           | 0.13       | remove `oidc.domain_map`; see the CHANGELOG for context                                                                                                                                                                                        |
| <span id="oidc.expiry"></span>`oidc.expiry`                                                   | 0.29       | use [`node.expiry`](#node.expiry)                                                                                                                                                                                                              |
| <span id="oidc.map_legacy_users"></span>`oidc.map_legacy_users`                               | 0.26       | remove `oidc.map_legacy_users`; see the CHANGELOG for context                                                                                                                                                                                  |
| <span id="oidc.namespace"></span>`oidc.namespace`                                             | 0.30       | remove `oidc.namespace`; see the CHANGELOG for context                                                                                                                                                                                         |
| <span id="oidc.strip_email_domain"></span>`oidc.strip_email_domain`                           | 0.26       | remove `oidc.strip_email_domain`; see the CHANGELOG for context                                                                                                                                                                                |
| <span id="oidc.user"></span>`oidc.user`                                                       | 0.30       | remove `oidc.user`; see the CHANGELOG for context                                                                                                                                                                                              |
| <span id="private_key_path"></span>`private_key_path`                                         | 0.23       | use [`noise.private_key_path`](#noise.private_key_path)                                                                                                                                                                                        |
| <span id="randomize_client_port"></span>`randomize_client_port`                               | 0.29       | set "randomizeClientPort": true at the top level of the policy file, or grant the cap per node via a "nodeAttrs" entry                                                                                                                         |
| <span id="tls_cert_path"></span>`tls_cert_path`                                               | 0.30       | use [`tls.cert_path`](#tls.cert_path)                                                                                                                                                                                                          |
| <span id="tls_client_auth_mode"></span>`tls_client_auth_mode`                                 | 0.30       | remove `tls_client_auth_mode`; see the CHANGELOG for context                                                                                                                                                                                   |
| <span id="tls_key_path"></span>`tls_key_path`                                                 | 0.30       | use [`tls.key_path`](#tls.key_path)                                                                                                                                                                                                            |
| <span id="tls_letsencrypt_cache_dir"></span>`tls_letsencrypt_cache_dir`                       | 0.30       | use [`tls.acme.cache_dir`](#tls.acme.cache_dir)                                                                                                                                                                                                |
| <span id="tls_letsencrypt_challenge_type"></span>`tls_letsencrypt_challenge_type`             | 0.30       | use [`tls.acme.challenge_type`](#tls.acme.challenge_type)                                                                                                                                                                                      |
| <span id="tls_letsencrypt_hostname"></span>`tls_letsencrypt_hostname`                         | 0.30       | use [`tls.acme.hostname`](#tls.acme.hostname)                                                                                                                                                                                                  |
| <span id="tls_letsencrypt_listen"></span>`tls_letsencrypt_listen`                             | 0.30       | use [`tls.acme.http_listen`](#tls.acme.http_listen)                                                                                                                                                                                            |
| <span id="tuning.notifier_send_timeout"></span>`tuning.notifier_send_timeout`                 | 0.30       | remove it: it had no effect                                                                                                                                                                                                                    |
