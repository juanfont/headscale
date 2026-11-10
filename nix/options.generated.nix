# Generated from hscontrol/types/config.go by `headscale generate nixos-options`; do not edit.
# headscale development tree, not a release
# Options for services.headscale.settings, not a module: import ./options.generated.nix { inherit lib; }
{ lib, ... }:
let
  o4 = "(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])";
  ip4 = "${o4}(\\.${o4}){3}";
  # Two colons at least, so host:port is not taken for one.
  ip6 = "[0-9A-Fa-f.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*";
  shape = description: pattern: lib.types.strMatching pattern // { inherit description; };
  t = {
    ip = shape "IP address" "(${ip4}|${ip6}(%[^%]+)?)?";
    prefix = shape "IP prefix in CIDR notation" "(${ip4}/([0-9]|[12][0-9]|3[0-2])|${ip6}/([0-9]|[1-9][0-9]|1[01][0-9]|12[0-8]))?";
    listenAddr = shape "host:port address" "((\\[[^]]*]|[^]:[]*):([0-9]+|https?))?";
    httpURL = shape "http:// or https:// URL" "(https?://[^/?#]+([/?#].*)?)?";
    duration = shape "duration such as 1h30m" "[-+]?(0|(([0-9]+(\\.[0-9]*)?|\\.[0-9]+)(ns|us|µs|μs|ms|s|m|h|d|w|y))+)";
    fileMode = shape "quoted octal file mode" "(0[oO])?0*[0-7]{1,3}";
    secretFile = shape "file: reference to a secret" "(file:.+)?";
    readFile = lib.types.either lib.types.path (lib.types.enum [ "" ]);
    stateFile = lib.types.either lib.types.externalPath (lib.types.enum [ "" ]);
  };
in
{
  server_url = lib.mkOption {
    type = lib.types.str;
    description = ''
      The URL clients connect to, with its `http://` or `https://` scheme, e.g. `https://headscale.example.com:443`. A trailing slash is trimmed on load. Its host must not be `dns.base_domain` or a name below it.

      Required.
    '';
    example = "https://headscale.example.com";
  };
  listen_addr = lib.mkOption {
    type = t.listenAddr;
    default = "0.0.0.0:8080";
    description = ''
      The host:port the server listens on for clients, the API and the web pages. It serves HTTPS when `tls.cert_path` or `tls.acme.hostname` is set, plain HTTP otherwise. The default listens on every address, IPv4 and IPv6 alike.
    '';
    example = "127.0.0.1:8080";
  };
  metrics_listen_addr = lib.mkOption {
    type = t.listenAddr;
    default = "";
    description = ''
      The host:port serving `/metrics` and `/debug`; keep it private. Empty disables this listener.
    '';
    example = "127.0.0.1:9090";
  };
  unix_socket = lib.mkOption {
    type = t.stateFile;
    default = "/var/run/headscale/headscale.sock";
    description = ''
      Where the server serves the API without authentication, for the CLI on the same host. The CLI connects to it when `cli.address` is empty.

      On NixOS, paths must be absolute and outside the Nix store.
    '';
    example = "/run/headscale/headscale.sock";
  };
  unix_socket_permission = lib.mkOption {
    type = t.fileMode;
    default = "0770";
    description = ''
      The file mode of `unix_socket`, in quoted octal (`"0770"`): unquoted, YAML reads `0770` as the number 504.
    '';
    example = "0660";
  };
  trusted_proxies = lib.mkOption {
    type = lib.types.listOf t.prefix;
    default = [ ];
    description = ''
      The CIDRs of reverse proxies whose `True-Client-IP`, `X-Real-IP` and `X-Forwarded-For` headers are honoured. Empty ignores those headers. Set without a proxy in front, clients can spoof their source IP in logs and the v2 API.
    '';
    example = [
      "192.0.2.10/32"
      "2001:db8::10/128"
    ];
  };
  disable_check_updates = lib.mkOption {
    type = lib.types.bool;
    default = false;
    description = ''
      Skips the check for a newer headscale release that commands make at start.
    '';
    example = true;
  };
  noise = {
    private_key_path = lib.mkOption {
      type = t.stateFile;
      default = "/var/lib/headscale/noise_private.key";
      description = ''
        The file holding the Noise private key, which encrypts traffic between headscale and clients, relative to the configuration file. A missing file is created with a new key.

        On NixOS, paths must be absolute and outside the Nix store.
      '';
      example = "/opt/headscale/noise_private.key";
    };
  };
  prefixes = {
    v4 = lib.mkOption {
      type = t.prefix;
      default = "100.64.0.0/10";
      description = ''
        The IPv4 range, e.g. `100.64.0.0/10`. Empty gives nodes no IPv4 address.
      '';
      example = "100.64.0.0/24";
    };
    v6 = lib.mkOption {
      type = t.prefix;
      default = "fd7a:115c:a1e0::/48";
      description = ''
        The IPv6 range, e.g. `fd7a:115c:a1e0::/48`. Empty gives nodes no IPv6 address.
      '';
      example = "fd7a:115c:a1e0::/64";
    };
    allocation = lib.mkOption {
      type = lib.types.enum [
        "sequential"
        "random"
        ""
      ];
      default = "sequential";
      description = ''
        How a new node's addresses are picked.

        One of:

        - `sequential`: Takes the next free address after the last one handed out, and wraps around to reuse freed addresses.
        - `random`: Picks a free address at random.
      '';
      example = "random";
    };
  };
  policy = {
    path = lib.mkOption {
      type = t.readFile;
      default = "";
      description = ''
        The HuJSON policy file read when `policy.mode` is `file`, relative to the configuration file. Empty starts without a policy, which allows all traffic.

        On NixOS, paths must be absolute.
      '';
      example = "/etc/headscale/policy.hujson";
    };
    mode = lib.mkOption {
      type = lib.types.enum [
        "file"
        "database"
        ""
      ];
      default = "file";
      description = ''
        Where the policy is kept: in the file `policy.path`, or in the database, edited through the CLI or API.

        One of:

        - `file`: Reads the policy from `policy.path`. Send headscale `SIGHUP` to reload it after an edit.
        - `database`: Keeps the policy in the database, set with `headscale policy set` or the API. `policy.path` is not read.
      '';
      example = "database";
    };
  };
  log = {
    level = lib.mkOption {
      type = lib.types.enum [
        "trace"
        "debug"
        "info"
        "warn"
        "error"
        "fatal"
        "panic"
        "disabled"
        ""
      ];
      default = "info";
      description = ''
        The lowest level logged.

        One of:

        - `trace`
        - `debug`
        - `info`
        - `warn`
        - `error`
        - `fatal`
        - `panic`
        - `disabled`
      '';
      example = "debug";
    };
    format = lib.mkOption {
      type = lib.types.enum [
        "text"
        "json"
        ""
      ];
      default = "text";
      description = ''
        How log lines are written.

        One of:

        - `text`: Writes human-readable lines, coloured when stderr is a terminal and `NO_COLOR` is unset.
        - `json`: Writes one JSON object per line, for log collectors.
      '';
      example = "json";
    };
  };
  node = {
    expiry = lib.mkOption {
      type = t.duration;
      default = "0s";
      description = ''
        The key expiry given to a non-tagged node that registers without one, whatever the method (auth key, CLI, web, OIDC). An expiry the client asks for, `oidc.use_expiry_from_token` and an admin's `headscale nodes expire` still apply. Tagged nodes never get this default. Zero or negative disables the default.
      '';
      example = "2160h";
    };
    ephemeral = {
      inactivity_timeout = lib.mkOption {
        type = t.duration;
        default = "30m";
        description = ''
          How long an ephemeral node can be offline before it is automatically deleted. It must exceed 65s, the client keepalive plus a margin.
        '';
        example = "1h";
      };
    };
    routes = {
      ha = {
        probe_interval = lib.mkOption {
          type = t.duration;
          default = "10s";
          description = ''
            How often HA subnet routers are probed; a positive interval must be at least 2s. Zero or negative disables probing, and with it the `node.routes.ha.probe_timeout` rules.
          '';
          example = "30s";
        };
        probe_timeout = lib.mkOption {
          type = t.duration;
          default = "5s";
          description = ''
            The maximum time to wait for a probe response before declaring a node unhealthy; at least 1s and less than `node.routes.ha.probe_interval`.
          '';
          example = "3s";
        };
      };
    };
  };
  preauth_keys = {
    revoked_retention = lib.mkOption {
      type = t.duration;
      default = "168h";
      description = ''
        How long a soft-revoked pre-auth key (revoked via the v2 API's DELETE) is kept retrievable before the background collector hard-deletes it. Keys still backing a node are kept until the node is deleted. A zero or negative duration disables the collector.
      '';
      example = "720h";
    };
  };
  derp = {
    server = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Runs the embedded DERP server. DERP needs TLS, so `server_url` must be `https://`.
        '';
        example = true;
      };
      region_id = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = ''
          The embedded server's region ID. It replaces a region with the same ID from the other sources.
        '';
        example = 999;
      };
      region_code = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The region's short code, shown by Tailscale clients.
        '';
        example = "headscale";
      };
      region_name = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The region's name, shown by Tailscale clients.
        '';
        example = "Headscale Embedded DERP";
      };
      verify_clients = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Admits only nodes registered with this server.
        '';
        example = false;
      };
      stun_listen_addr = lib.mkOption {
        type = t.listenAddr;
        default = "";
        description = ''
          The UDP host:port of the STUN server, which helps clients with NAT traversal; required when `derp.server.enabled` is true.
        '';
        example = "0.0.0.0:3478";
      };
      private_key_path = lib.mkOption {
        type = t.stateFile;
        default = "";
        description = ''
          The file holding the DERP server's private key, relative to the configuration file; required when `derp.server.enabled` is true. A missing file is created with a new key. It must differ from `noise.private_key_path`.

          On NixOS, paths must be absolute and outside the Nix store.
        '';
        example = "/var/lib/headscale/derp_server_private.key";
      };
      ipv4 = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The server's public IPv4 address, published in the DERP map so clients reach it without DNS. Empty publishes none.
        '';
        example = "198.51.100.1";
      };
      ipv6 = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The server's public IPv6 address, published in the DERP map so clients reach it without DNS. Empty publishes none.
        '';
        example = "2001:db8::1";
      };
      automatically_add_embedded_derp_region = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Adds the embedded server's region to the DERP map. When it is false and `derp.server.enabled` is true, `derp.paths` is required: write the region there yourself.
        '';
        example = false;
      };
    };
    urls = lib.mkOption {
      type = lib.types.listOf t.httpURL;
      default = [
        "https://controlplane.tailscale.com/derpmap/default"
      ];
      description = ''
        DERP maps in JSON to fetch. One that fails to load is logged and skipped; startup fails only when no region remains. The default is Tailscale's map: headscale fetches it from Tailscale and clients relay through Tailscale's servers. `[]` keeps to your own.
      '';
      example = [
        "https://derp.example.com/derpmap.json"
      ];
    };
    paths = lib.mkOption {
      type = lib.types.listOf lib.types.path;
      default = [ ];
      description = ''
        DERP map files. The extension picks the format: `.yaml` or `.yml`, or Tailscale JSON as `.json` or `.hujson`, both accepting comments and trailing commas.

        On NixOS, paths must be absolute.
      '';
      example = [
        "/etc/headscale/derp.yaml"
      ];
    };
    auto_update_enabled = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Reloads `derp.urls` and `derp.paths` every `derp.update_frequency`.
      '';
      example = false;
    };
    update_frequency = lib.mkOption {
      type = t.duration;
      default = "3h";
      description = ''
        How often `derp.auto_update_enabled` reloads the DERP map. Zero disables reloading.
      '';
      example = "24h";
    };
  };
  database = {
    type = lib.mkOption {
      type = lib.types.enum [
        "sqlite"
        "sqlite3"
        "postgres"
        ""
      ];
      default = "sqlite";
      description = ''
        The database backend. SQLite is recommended; PostgreSQL is supported for legacy deployments only.

        One of:

        - `sqlite`: SQLite, in the file `database.sqlite.path`.
        - `sqlite3`: The same as `sqlite`.
        - `postgres`: PostgreSQL, at `database.postgres.host`.
      '';
      example = "sqlite";
    };
    debug = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Turns on query logging: ordinary queries at log level debug, shown only when `log.level` is `debug` or `trace`, slow ones at warn and failed ones at error. Off, no query is logged. `database.gorm` shapes the query log. See [Database logging](https://headscale.net/stable/ref/debug/#database-logging).
      '';
      example = true;
    };
    gorm = {
      slow_threshold = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = ''
          The query time, in milliseconds, above which a query is logged as a warning. Zero disables the warning.
        '';
        example = 1000;
      };
      skip_err_record_not_found = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Logs a query that finds no record as an ordinary query, not as an error.
        '';
        example = true;
      };
      parameterized_queries = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Logs queries without their parameter values.
        '';
        example = true;
      };
    };
    sqlite = {
      path = lib.mkOption {
        type = t.stateFile;
        default = "/var/lib/headscale/db.sqlite";
        description = ''
          The database file, relative to the configuration file; `:memory:` keeps the database in memory.

          On NixOS, paths must be absolute and outside the Nix store.
        '';
        example = "/opt/headscale/db.sqlite";
      };
      write_ahead_log = lib.mkOption {
        type = lib.types.bool;
        default = true;
        description = ''
          Runs SQLite in write-ahead log (WAL) mode, applies `database.sqlite.wal_autocheckpoint` and compacts the database (`VACUUM`) on shutdown. False uses SQLite's rollback journal (`DELETE`) with `synchronous=FULL`, and converts a database left in WAL mode when headscale opens it.
        '';
        example = false;
      };
      wal_autocheckpoint = lib.mkOption {
        type = lib.types.int;
        default = 1000;
        description = ''
          The number of WAL frames after which the WAL is checkpointed automatically; zero disables automatic checkpoints. Applied only when `database.sqlite.write_ahead_log` is true.
        '';
        example = 2000;
      };
    };
    postgres = {
      host = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The server's host name or IP, or the directory of its Unix socket (a path starting with `/`).
        '';
        example = "db.example.com";
      };
      port = lib.mkOption {
        type = lib.types.int;
        default = 0;
        description = ''
          The server's port or, with a Unix socket directory in `database.postgres.host`, the port in the socket's file name. Zero uses the driver's default.
        '';
        example = 5432;
      };
      name = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The database name.
        '';
        example = "headscale";
      };
      user = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The user to connect as.
        '';
        example = "headscale";
      };
      pass = lib.mkOption {
        type = t.secretFile;
        default = "";
        description = ''
          The password, or `file:<path>` to read it from a file, read only when `database.type` is `postgres`. `headscale generate config --running` and `/debug/config` show a literal password as `<redacted>` and a `file:` reference as written.

          On NixOS, the value must be `""` or `file:<path>`: load the secret as a systemd credential with `systemd.services.headscale.serviceConfig.LoadCredential = [ "database_postgres_pass:/run/secrets/database_postgres_pass" ];` and set this option to `"file:\''${CREDENTIALS_DIRECTORY}/database_postgres_pass"`.
        '';
        example = "file:/run/secrets/postgres_password";
      };
      ssl = lib.mkOption {
        type = lib.types.str;
        default = "false";
        description = ''
          The TLS mode: `true` keeps the driver's default `sslmode`, `false` disables TLS, any other value is passed as `sslmode` (`require`, `verify-full`, ...).
        '';
        example = "verify-full";
      };
      max_open_conns = lib.mkOption {
        type = lib.types.int;
        default = 10;
        description = ''
          Caps open connections to the database.
        '';
        example = 20;
      };
      max_idle_conns = lib.mkOption {
        type = lib.types.int;
        default = 10;
        description = ''
          Caps idle connections kept in the pool.
        '';
        example = 5;
      };
      conn_max_idle_time_secs = lib.mkOption {
        type = lib.types.int;
        default = 3600;
        description = ''
          How long, in seconds, a connection may stay idle before it is closed.
        '';
        example = 600;
      };
    };
  };
  dns = {
    magic_dns = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Gives each node a name below `dns.base_domain`, e.g. `laptop.example.com`, resolved by the client. It requires `dns.base_domain`.
      '';
      example = false;
    };
    base_domain = lib.mkOption {
      type = lib.types.str;
      default = "tailnet.internal";
      description = ''
        The domain MagicDNS names live under, without a trailing dot, e.g. `example.com`. The host of `server_url` must not be this domain or a name below it: clients take the domain over. The default is a private-use name, so `dns.certificates` needs a public domain you control.
      '';
      example = "tailnet.example.com";
    };
    override_local_dns = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Makes clients use `dns.nameservers.global` instead of their local DNS settings; with no global nameserver there is nothing to override with, and clients keep their own. False sends them only as fallback resolvers.
      '';
      example = false;
    };
    nameservers = {
      global = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [ ];
        description = ''
          The nameservers for names `dns.nameservers.split` does not cover: IP addresses, or DNS-over-HTTPS URLs such as `https://dns.nextdns.io/<id>`. Empty by default, so clients keep their own DNS: headscale points them at no resolver you did not list.
        '';
        example = [
          "9.9.9.9"
          "149.112.112.112"
          "2620:fe::fe"
          "2620:fe::9"
        ];
      };
      split = lib.mkOption {
        type = lib.types.attrsOf (lib.types.listOf lib.types.str);
        default = { };
        description = ''
          Maps a domain to the nameservers that answer for it (split DNS). Domains are lowercased on load; two that differ only in case are an error.
        '';
        example = {
          "corp.example.com" = [
            "192.0.2.53"
          ];
          "lab.example.net" = [
            "198.51.100.53"
            "2001:db8::53"
          ];
        };
      };
    };
    search_domains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        DNS search domains sent to clients. With MagicDNS, `dns.base_domain` comes first.
      '';
      example = [
        "corp.example.com"
        "lab.example.net"
      ];
    };
    extra_records = lib.mkOption {
      type = lib.types.listOf (
        lib.types.submodule {
          freeformType = lib.types.attrsOf lib.types.anything;
          options = {
            name = lib.mkOption {
              type = lib.types.str;
              description = ''
                The fully qualified domain name, e.g. `grafana.example.com`; the trailing dot is optional.
              '';
              example = "grafana.tailnet.example.com";
            };
            type = lib.mkOption {
              type = lib.types.enum [
                ""
                "A"
                "AAAA"
              ];
              default = "";
              description = ''
                The record type, `A` or `AAAA`; empty picks it from `value`. Clients ignore other types.
              '';
              example = "A";
            };
            value = lib.mkOption {
              type = t.ip;
              description = ''
                The IP address the name resolves to.
              '';
              example = "100.64.0.3";
            };
          };
        }
      );
      default = [ ];
      description = ''
        DNS records served to clients, each with a `name`, `type` and `value`. Clients support `A` and `AAAA`. Mutually exclusive with `dns.extra_records_path`. See [Setting extra DNS records](https://headscale.net/stable/ref/dns/#setting-extra-dns-records).
      '';
      example = [
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
    };
    extra_records_path = lib.mkOption {
      type = t.readFile;
      default = "";
      description = ''
        A file of extra records, reloaded when it changes. The extension picks the format: `.json`, `.hujson`, `.yaml` or `.yml`. Mutually exclusive with `dns.extra_records`.

        On NixOS, paths must be absolute.
      '';
      example = "/var/lib/headscale/extra-records.json";
    };
    certificates = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Lets nodes run `tailscale cert`. It requires `dns.magic_dns`, a lowercase `dns.base_domain` and `dns.challenge.provider`.
        '';
        example = true;
      };
      zone = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The public DNS zone challenge records are written to, when `dns.base_domain` sits below the zone apex. It must contain `dns.base_domain`. Empty uses `dns.base_domain`.
        '';
        example = "example.com";
      };
    };
    challenge = {
      propagation_timeout = lib.mkOption {
        type = t.duration;
        default = "2m";
        description = ''
          How long to wait for a challenge record to show up on every authoritative nameserver. Zero skips the check.
        '';
        example = "5m";
      };
      resolvers = lib.mkOption {
        type = lib.types.listOf lib.types.str;
        default = [
          "9.9.9.9:53"
          "149.112.112.112:53"
        ];
        description = ''
          The servers asked for the zone's nameservers, each an IP or host with an optional port (53 if omitted). Empty uses the default public resolvers. The system resolver is never used: on a host running MagicDNS it answers for `dns.base_domain` itself.
        '';
        example = [
          "9.9.9.9:53"
          "[2620:fe::fe]:53"
        ];
      };
      provider = lib.mkOption {
        type = lib.types.attrsOf lib.types.anything;
        default = { };
        description = ''
          The DNS provider that writes challenge records: `name` selects it, the other keys are its settings. Keys are lowercased on load, at every depth; two that differ only in case are an error. A string setting may be `file:<path>` to read it from a file. `headscale generate config --running` and `/debug/config` show `name` and `file:` references; every other setting is `<redacted>`, as any may be a credential. See [DNS-01 challenge provider](https://headscale.net/stable/ref/dns/#dns-01-challenge-provider) to set a provider up, acme-dns included, and to set it from environment variables.

          On NixOS, keep a secret setting out of the Nix store: load it as a systemd credential with `systemd.services.headscale.serviceConfig.LoadCredential = [ "dns_challenge_provider_<setting>:/run/secrets/dns_challenge_provider_<setting>" ];` and set the setting to `"file:\''${CREDENTIALS_DIRECTORY}/dns_challenge_provider_<setting>"`. `name` is not a secret.
        '';
        example = {
          api_token = "file:/run/secrets/cloudflare";
          name = "cloudflare";
        };
      };
    };
  };
  tls = {
    cert_path = lib.mkOption {
      type = t.readFile;
      default = "";
      description = ''
        The PEM certificate file, relative to the configuration file. Setting it turns TLS on.

        On NixOS, paths must be absolute.
      '';
      example = "/etc/headscale/tls/cert.pem";
    };
    key_path = lib.mkOption {
      type = t.stateFile;
      default = "";
      description = ''
        The PEM private key file of `tls.cert_path`, relative to the configuration file.

        On NixOS, paths must be absolute and outside the Nix store.
      '';
      example = "/etc/headscale/tls/key.pem";
    };
    acme = {
      hostname = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The domain to request a certificate for. Setting it turns ACME on.
        '';
        example = "headscale.example.com";
      };
      challenge_type = lib.mkOption {
        type = lib.types.enum [
          "HTTP-01"
          "TLS-ALPN-01"
          "DNS-01"
          ""
        ];
        default = "HTTP-01";
        description = ''
          How the CA verifies that headscale controls `tls.acme.hostname`.

          One of:

          - `HTTP-01`: Has the CA fetch a token over HTTP on port 80, answered on `tls.acme.http_listen`. TLS-ALPN-01 on `listen_addr` stays enabled too.
          - `TLS-ALPN-01`: Has the CA check a special certificate on port 443, answered on `listen_addr`, which must be reachable there.
          - `DNS-01`: Has the CA look up a TXT record, which headscale writes through `dns.challenge.provider`. It needs no open port.
        '';
        example = "TLS-ALPN-01";
      };
      http_listen = lib.mkOption {
        type = t.listenAddr;
        default = ":http";
        description = ''
          The host:port serving HTTP-01 challenges; the port may be a name, as in `:http` for port 80. Other requests to it are redirected to `server_url`.
        '';
        example = "0.0.0.0:80";
      };
      url = lib.mkOption {
        type = t.httpURL;
        default = "";
        description = ''
          The CA's ACME directory. Empty uses Let's Encrypt.
        '';
        example = "https://acme-staging-v02.api.letsencrypt.org/directory";
      };
      email = lib.mkOption {
        type = lib.types.str;
        default = "";
        description = ''
          The contact address registered with the CA.
        '';
        example = "admin@example.com";
      };
      cache_dir = lib.mkOption {
        type = t.stateFile;
        default = "/var/lib/headscale/cache";
        description = ''
          Where certificates and ACME account data are stored, relative to the configuration file.

          On NixOS, paths must be absolute and outside the Nix store.
        '';
        example = "/var/cache/headscale/acme";
      };
    };
  };
  oidc = {
    only_start_if_oidc_is_available = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Stops startup when the provider cannot be reached. False starts without OIDC, with CLI-based registration.
      '';
      example = false;
    };
    issuer = lib.mkOption {
      type = t.httpURL;
      default = "";
      description = ''
        The provider's issuer URL. Setting it turns OIDC on.
      '';
      example = "https://idp.example.com/realms/headscale";
    };
    client_id = lib.mkOption {
      type = lib.types.str;
      default = "";
      description = ''
        The client ID from the provider; required when `oidc.issuer` is set.
      '';
      example = "headscale";
    };
    client_secret = lib.mkOption {
      type = t.secretFile;
      default = "";
      description = ''
        The client secret from the provider, or `file:<path>` to read it from a file; required when `oidc.issuer` is set. `headscale generate config --running` and `/debug/config` show a literal secret as `<redacted>` and a `file:` reference as written.

        On NixOS, the value must be `""` or `file:<path>`: load the secret as a systemd credential with `systemd.services.headscale.serviceConfig.LoadCredential = [ "oidc_client_secret:/run/secrets/oidc_client_secret" ];` and set this option to `"file:\''${CREDENTIALS_DIRECTORY}/oidc_client_secret"`.
      '';
      example = "file:/run/secrets/oidc_client_secret";
    };
    scope = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [
        "openid"
        "profile"
        "email"
      ];
      description = ''
        The scopes requested; include `openid`.
      '';
      example = [
        "openid"
        "profile"
        "email"
        "groups"
      ];
    };
    extra_params = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = ''
        Sent as is to the provider's authorization endpoint, e.g. `domain_hint`; names keep their case.
      '';
      example = {
        domain_hint = "example.com";
        prompt = "select_account";
      };
    };
    allowed_domains = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Admits only users whose email domain is listed. Empty admits any domain.
      '';
      example = [
        "example.com"
      ];
    };
    allowed_users = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Admits only users whose email address is listed. Empty admits any user.
      '';
      example = [
        "alice@example.com"
      ];
    };
    allowed_groups = lib.mkOption {
      type = lib.types.listOf lib.types.str;
      default = [ ];
      description = ''
        Admits only members of at least one listed group, from the provider's `groups` claim: UserInfo first, the ID token as fallback. Empty admits any group.
      '';
      example = [
        "headscale-users"
      ];
    };
    email_verified_required = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Trusts an email only when the provider marks it verified: an unverified one fails `oidc.allowed_domains` and `oidc.allowed_users` and is not copied to the user. Turn it off for a provider that does not send `email_verified`.
      '';
      example = false;
    };
    use_expiry_from_token = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Expires an OIDC-registered node with its token, instead of `node.expiry`. Tokens are often short-lived, forcing frequent logins.
      '';
      example = true;
    };
    pkce = {
      enabled = lib.mkOption {
        type = lib.types.bool;
        default = false;
        description = ''
          Sends a PKCE challenge with each login.
        '';
        example = true;
      };
      method = lib.mkOption {
        type = lib.types.enum [
          "plain"
          "S256"
          ""
        ];
        default = "S256";
        description = ''
          How the code challenge is derived from the verifier. The verifier is sent as is in the token exchange.

          One of:

          - `plain`: Sends the verifier itself as the challenge. Use it only with a provider that does not support `S256`.
          - `S256`: Sends the base64url SHA-256 of the verifier as the challenge. Recommended.
        '';
        example = "plain";
      };
    };
  };
  logtail = {
    enabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Lets nodes send their logs to Tailscale Inc.; headscale cannot point them at another log server. False tells nodes not to.
      '';
      example = true;
    };
  };
  taildrop = {
    enabled = lib.mkOption {
      type = lib.types.bool;
      default = true;
      description = ''
        Gives every node the file-sharing capability. False omits it from the baseline; a policy `nodeAttrs` grant can still give it.
      '';
      example = false;
    };
  };
  auto_update = {
    enabled = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Makes auto-update the default for clients that have not chosen locally. Clients store the default they first see, so a later change reaches only new clients.
      '';
      example = true;
    };
  };
  tuning = {
    batch_change_delay = lib.mkOption {
      type = t.duration;
      default = "800ms";
      description = ''
        How often queued changes are sent to clients as one update; must be positive.
      '';
      example = "500ms";
    };
    node_mapsession_buffered_chan_size = lib.mkOption {
      type = lib.types.int;
      default = 30;
      description = ''
        How many map updates are queued per connected client.
      '';
      example = 60;
    };
    batcher_workers = lib.mkOption {
      type = lib.types.int;
      default = 0;
      defaultText = lib.literalMD "three quarters of the CPU cores, at least one";
      description = ''
        The number of workers building map updates for connected clients. Zero picks the number from the CPU count.
      '';
      example = 8;
    };
    register_cache_expiration = lib.mkOption {
      type = t.duration;
      default = "15m";
      description = ''
        How long a pending registration waits to be completed. Zero uses the default.
      '';
      example = "30m";
    };
    register_cache_max_entries = lib.mkOption {
      type = lib.types.int;
      default = 1024;
      description = ''
        Bounds pending registrations. At capacity, new registrations are refused without evicting pending ones; SSH checks have a small reserve beyond it. Zero uses the default. See [Pending authentication limits](https://headscale.net/stable/ref/registration/#pending-authentication-limits).
      '';
      example = 4096;
    };
    node_store_batch_size = lib.mkOption {
      type = lib.types.int;
      default = 100;
      description = ''
        How many node changes are batched before the in-memory node state, peer relationships included, is rebuilt; must be positive. Higher values save CPU on bulk changes but delay each change until its batch is full or `tuning.node_store_batch_timeout` passes.
      '';
      example = 200;
    };
    node_store_batch_timeout = lib.mkOption {
      type = t.duration;
      default = "500ms";
      description = ''
        The longest a partial batch of node changes waits before the rebuild; must be positive. Lower values answer single changes faster at the cost of more rebuilds.
      '';
      example = "1s";
    };
  };
}
