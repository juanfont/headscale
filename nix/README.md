# Headscale NixOS Module

This directory contains the NixOS module for Headscale.

## Rationale

The module is maintained in this repository to keep the code and module
synchronized at the same commit. This allows faster iteration and ensures the
module stays compatible with the latest Headscale changes. All changes should
aim to be upstreamed to nixpkgs.

## Files

- **[`module.nix`](./module.nix)** - The NixOS module implementation
- **[`options.generated.nix`](./options.generated.nix)** - The
  `services.headscale.settings` options, generated from headscale by
  `go generate ./hscontrol/types/`; do not edit
- **[`testkit.nix`](./testkit.nix)**,
  **[`testkit-peer.nix`](./testkit-peer.nix)** - Test kit: a control node for
  NixOS VM tests of Tailscale clients, and a peer that joins it (see below)
- **[`tests/`](./tests/)** - NixOS integration tests

## Usage

Add to your flake inputs:

```nix
inputs.headscale.url = "github:juanfont/headscale";
```

Then import the module:

```nix
imports = [ inputs.headscale.nixosModules.default ];
```

The flake's module defaults `services.headscale.package` to the flake's
headscale. Another package must provide `headscale check` while the checks
below are on.

See [Configuration options](https://headscale.net/stable/ref/configuration-options/)
for every setting, with its default and a NixOS example.

### Secrets

Load each secret as a systemd credential and point the setting at it with
`file:`. headscale expands `${CREDENTIALS_DIRECTORY}` itself, and the secret
never reaches the Nix store.

```nix
systemd.services.headscale.serviceConfig.LoadCredential = [
  "oidc-client-secret:/run/secrets/oidc-client-secret"
];

services.headscale.settings.oidc.client_secret = "file:\${CREDENTIALS_DIRECTORY}/oidc-client-secret";
```

`oidc.client_secret` and `database.postgres.pass` take only `""` or a `file:`
reference: a literal secret fails evaluation. `dns.challenge.provider` settings
are not type-checked: every text setting there takes `file:` too, and a literal
is accepted but lands in the Nix store. It needs this flake's package (see
Usage): an older headscale takes the string as the secret itself.

## Settings

`services.headscale.settings` has one option per key of headscale's
configuration, with headscale's own type, default and documentation. A key
without an option, such as a typo or a removed key, is still written to the
configuration, and headscale's checks reject it, naming what replaces a
removed key. With `check.config` on, that fails a native build (see Checks).
`settings.server_url` has no default: set it. Write keys nested and in lower
case, as the options are named. headscale rejects `LISTEN_ADDR` as an unknown
key, and a dotted `"policy.path"` as set twice, since the module also writes
`policy.path`.

Each option has headscale's type, so a value of the wrong shape fails
evaluation and names the option: a listen address without a port, a duration
without a unit, a bad prefix, file mode or URL, or an extra DNS record whose
`value` is not an IP address.

Paths on NixOS are absolute. Where an option's description says a path is
relative to the configuration file, or allows `:memory:`, that does not apply
here.

- Read-only files (`policy.path`, `tls.cert_path`, `derp.paths`,
  `dns.extra_records_path`) take a Nix path, a package or an absolute path.
- Key and state paths (`noise.private_key_path`,
  `derp.server.private_key_path`, `database.sqlite.path`, `unix_socket`,
  `tls.key_path`, `tls.acme.cache_dir`) take an absolute path outside the Nix
  store, so a key never lands in it.

The module sets only where NixOS keeps headscale's state and socket, and turns
off the update check, since Nix pins the package and an update notice cannot be
acted on. Every other setting but `server_url` takes headscale's own default.
The module's values are set at `lib.mkOverride 1200`, below `lib.mkDefault`, so
a plain assignment or a `lib.mkDefault` of your own replaces them:

- `noise.private_key_path = "/var/lib/headscale/noise_private.key"`
- `derp.server.private_key_path = "/var/lib/headscale/derp_server_private.key"`
- `database.sqlite.path = "/var/lib/headscale/db.sqlite"`
- `unix_socket = "/run/headscale/headscale.sock"`
- `disable_check_updates = true`

`headscale generate config --running` prints the configuration the running
server uses.

## CLI

The module writes no CLI configuration file. Run `headscale` on the server as
root or as a member of the `headscale` group; it reaches the server through
`settings.unix_socket`, without authentication.

- With the default socket the CLI needs nothing: it is the CLI's default too.
- The module sets `HEADSCALE_UNIX_SOCKET` and
  `HEADSCALE_DISABLE_CHECK_UPDATES` from `settings.unix_socket` and
  `settings.disable_check_updates` in `environment.sessionVariables`, so a
  moved socket and the update-check setting reach the CLI in login shells and
  through `sudo`, which sets them again with PAM. System services and cron jobs
  do not get them: one that runs the CLI, `hs-authkey` from a unit included,
  sets `HEADSCALE_DISABLE_CHECK_UPDATES=true` itself, or each command without
  `-o` asks GitHub for a newer release, and sets `HEADSCALE_UNIX_SOCKET` if the
  socket moved.
- Without the module, e.g. with `nix run`, the CLI asks GitHub for a newer
  release on each command without `-o`: set
  `HEADSCALE_DISABLE_CHECK_UPDATES=true`.
- A `settings.cli` key, nested or dotted (`"cli.api_key"`), fails evaluation:
  `serve` does not read it, and `cli.api_key` would land in the world-readable
  Nix store.
- For a remote server, give the CLI `cli.address` and `cli.api_key` in
  `~/.config/headscale/config.yaml`, or as `HEADSCALE_CLI_*` variables. See
  [Remote control](https://headscale.net/stable/ref/api/#remote-control).

## Checks

The module checks what headscale would reject before it can stop a running
headscale.

- **Policy** (`check.policy`): a file policy goes through the new package's
  `headscale check policy -f`, which runs its `tests` and `sshTests` against
  one node for each user and tag the policy names. A policy in the Nix store is
  checked while building: a bad one fails `nixos-rebuild build`, before the
  system profile changes. Native builds only. A policy outside the Nix store,
  or from a cross build, is checked before a switch instead.
- **Configuration while building** (`check.config`): `headscale check config -f`
  runs on the generated `configFile` with the unit's `environment`, without its
  `EnvironmentFile`. A configuration headscale rejects fails
  `nixos-rebuild build`. Native builds only; a cross build leaves it to the
  switch check.
- **Configuration before a switch** (`check.config`): a
  [`system.preSwitchChecks`](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/system/activation/pre-switch-check.nix)
  entry runs `headscale check all` on the new config as the `headscale` user,
  with the unit's groups and environment, and aborts the switch before any
  unit restarts. It checks the config and every file it names (policy and its
  tests, DERP maps, extra records, TLS pair, existing keys), so turning off
  only `check.policy` does not skip the policy here; turn off both. It runs
  only when headscale's unit changes. nixpkgs runs pre-switch checks for every
  `switch-to-configuration` action, so `boot`, `test` and `dry-activate` run it
  too: a deploy that calls `dry-activate` first fails there.

Both options default to `true`. `NIXOS_NO_CHECK=1 nixos-rebuild switch` skips
the switch check once, not the build checks; a failed switch check prints this
hint. Limits:

- The switch check runs before activation, so it sees files as they were:
  `/etc` entries, sops-nix or agenix secrets and new users arrive after it. A
  `headscale` user or group that does not exist yet skips the check, and a
  supplementary group that does not exist yet is left out of it. With userborn,
  whose record of earlier declarations the check does not read, a group the
  configuration drops can still count for the check.
- The configuration checks run outside the unit. They see its `environment` as
  written, before systemd expands specifiers such as `%H`, and not its
  `EnvironmentFile`, `serviceConfig.Environment` or credentials. They never read
  a `file:` secret: `check all` lists each one as skipped, so credentials
  referenced with `file:` pass. A required setting given only where they do not
  look, such as `HEADSCALE_OIDC_CLIENT_SECRET` or `LIBDNS_HETZNER_TOKEN` from an
  `EnvironmentFile`, or a value valid only once systemd expands it, fails every
  switch and, on a native build with `check.config` on, every build. Move a
  secret to a `file:` secret (see Secrets), write a literal or Nix-resolved
  value, or turn off `check.config`.
- The flake's overlay builds headscale for the host on the host platform, so a
  cross system build needs a builder for the host platform.
- `nixos-rebuild switch` sets the system profile before the switch check, and
  does not undo it. The boot menu is not updated, so a reboot starts the old
  generation. `nixos-rebuild switch --rollback` resets the profile.
- A pass does not prove that migrations, the network, an OIDC provider or the
  listeners work.

## Migrating from the previous module

Every option below is under `services.headscale`.

| Before                                                                         | Now                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address` and `port`                                                           | `settings.listen_addr`, e.g. `"0.0.0.0:8080"`; an IPv6 address goes in brackets, `"[::]:443"`                                                                                                                                                                             |
| `port`, read by another module                                                 | It fails evaluation; for nixpkgs' `services.headplane`, set `services.headplane.settings.headscale.url`                                                                                                                                                                   |
| `serverUrl`                                                                    | `settings.server_url`                                                                                                                                                                                                                                                     |
| `logLevel`                                                                     | `settings.log.level`                                                                                                                                                                                                                                                      |
| `ephemeralNodeInactivityTimeout`                                               | `settings.node.ephemeral.inactivity_timeout`                                                                                                                                                                                                                              |
| `derp.autoUpdate`, `derp.auto_update_enable`                                   | `settings.derp.auto_update_enabled`                                                                                                                                                                                                                                       |
| `derp.paths`                                                                   | `settings.derp.paths`                                                                                                                                                                                                                                                     |
| `derp.urls`                                                                    | `settings.derp.urls`                                                                                                                                                                                                                                                      |
| `derp.updateFrequency`                                                         | `settings.derp.update_frequency`                                                                                                                                                                                                                                          |
| `openIdConnect.clientId`                                                       | `settings.oidc.client_id`                                                                                                                                                                                                                                                 |
| `openIdConnect.issuer`                                                         | `settings.oidc.issuer`                                                                                                                                                                                                                                                    |
| `openIdConnect.clientSecretFile`                                               | `settings.oidc.client_secret = "file:\${CREDENTIALS_DIRECTORY}/<name>"` with `LoadCredential`, as in [Secrets](#secrets)                                                                                                                                                  |
| `openIdConnect.domainMap`                                                      | Nothing: headscale no longer uses it                                                                                                                                                                                                                                      |
| `tls.certFile`                                                                 | `settings.tls.cert_path`                                                                                                                                                                                                                                                  |
| `tls.keyFile`                                                                  | `settings.tls.key_path`                                                                                                                                                                                                                                                   |
| `tls.letsencrypt.challengeType`                                                | `settings.tls.acme.challenge_type`                                                                                                                                                                                                                                        |
| `tls.letsencrypt.hostname`                                                     | `settings.tls.acme.hostname`                                                                                                                                                                                                                                              |
| `tls.letsencrypt.httpListen`                                                   | `settings.tls.acme.http_listen`                                                                                                                                                                                                                                           |
| `user`, `group`                                                                | Nothing: both are read-only, and headscale runs as `headscale:headscale`. Give `headscale` access to files elsewhere with `users.users.headscale.extraGroups` or the file's group. If a separate `headscale` account already existed, switch once with `NIXOS_NO_CHECK=1` |
| `settings.cli`, `settings."cli.api_key"`                                       | `cli.address` and `cli.api_key` in `~/.config/headscale/config.yaml`, or `HEADSCALE_CLI_*` variables; the CLI on the server needs neither                                                                                                                                 |
| A literal `settings.oidc.client_secret` or `settings.database.postgres.pass`   | `"file:\${CREDENTIALS_DIRECTORY}/<name>"` with `LoadCredential`, as in [Secrets](#secrets)                                                                                                                                                                                |
| `settings.database.postgres.password_file`, `settings.oidc.client_secret_path` | `settings.database.postgres.pass`, `settings.oidc.client_secret`: `"file:<the same path>"`, or `LoadCredential` as in [Secrets](#secrets)                                                                                                                                 |
| A key or state path given as a Nix path or a relative path                     | An absolute path outside the Nix store, e.g. `"/var/lib/headscale/noise_private.key"`                                                                                                                                                                                     |
| A listen address without a port, a duration without a unit                     | A port and a unit: `"0.0.0.0:8080"`, `"30s"`                                                                                                                                                                                                                              |

A removed `settings` key, such as `settings.db_host` or `settings.dns_config`,
reaches headscale, whose checks name its replacement.

## Test kit

`nixosModules.testkit` turns a node of a NixOS VM test into a headscale control
server. Projects that implement or embed Tailscale (tailscaled, tsnet,
tailscale-rs, …) use it to test against a real control server without writing
one. Go clients join without a CA, a hosts entry or an env var.
`nixosModules.testkit-peer` is an optional tailscaled peer that joins it in one
line.

```nix
pkgs.testers.runNixOSTest {
  name = "my-app";
  nodes.headscale.imports = [ inputs.headscale.nixosModules.testkit ];
  nodes.peer.imports = [ inputs.headscale.nixosModules.testkit-peer ];
  testScript = ''
    start_all()
    key = headscale.succeed("hs-authkey alice").strip()
    peer.succeed(f"hs-join {key}")
  '';
}
```

It works with `nixosTest`, `runNixOSTest` and `runTest`. The headscale package
must come from the same release or newer: the kit relies on its
`preauthkeys create --user NAME` and `HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR`.

### Contract

Breaking changes to anything below get a "NixOS test kit" BREAKING entry in the
CHANGELOG.

- Control: `http://<node hostname>`, so `http://headscale` for a node named
  `headscale`. Use it for `tailscale up --login-server`,
  `tsnet.Server.ControlURL` and tailscale-rs `TS_CONTROL_URL`.
- The same router is also served on TLS :443 with a throwaway self-signed
  certificate. DERP is region 999 (`headscale`) on :443, marked
  `InsecureForTests`, with STUN on UDP 3478.
- `hs-authkey USER [headscale preauthkeys create flags]`, on the control node:
  - waits for headscale for up to `HEADSCALE_CLI_TIMEOUT` (default `60s`);
  - creates `USER` if missing;
  - prints one reusable 24h key.

  Extra flags pass through, e.g. `--ephemeral` or `--tags tag:ci`. In a policy,
  refer to these users as `USER@`, because they have no email.

- `hs-join KEY [tailscale up flags]`, on a `testkit-peer` node, waits for
  tailscaled, then joins the control node named `headscale` with a 60s
  `tailscale up --timeout`, so a broken control plane fails the test instead of
  hanging it. A trailing `--login-server` overrides the URL.
- Defaults you can override:
  - `policy.mode = "database"`: nothing stored allows all, and
    `headscale policy set -f FILE` applies live. For a fixed policy, set
    `settings.policy = { mode = "file"; path = pkgs.writeText "policy.json" (builtins.toJSON { … }); }`.
    A policy may name users before `hs-authkey` creates them.
  - MagicDNS with `dns.base_domain = "tailnet"`.
  - `dns.override_local_dns = false`.
- Everything else is plain `services.headscale.*` on that node.
  - Override the package with a plain assignment, e.g. to carry a patch:
    `services.headscale.package = inputs.headscale.packages.${system}.headscale.overrideAttrs (o: { patches = (o.patches or [ ]) ++ [ ./fix.patch ]; });`
  - Don't bind :80 or :443 on that node yourself.

### Clients

- **tailscaled**: import `testkit-peer` and use `hs-join`, or run
  `tailscale up --login-server http://headscale --auth-key KEY` yourself. Its
  log warns that it "could not establish an encrypted connection": that is the
  untrusted certificate on :443, and it is expected.
- **tsnet**: set `ControlURL` to `http://headscale` and hand it the key,
  e.g. `TS_AUTHKEY` in an `EnvironmentFile` that the test writes before it
  starts the unit.
- **tailscale-rs**: build with its `ts_control/insecure-keyfetch` and
  `ts_control/insecure-derp` features, which allow plain-HTTP `/key` and
  honour `InsecureForTests`. See its examples for the control URL, auth key and
  hostname flags.
- **Proving relay**: set `TS_DEBUG_ALWAYS_USE_DERP=1` on a Go peer.
  - Between Go peers, `tailscale ping --until-direct=false PEER` reports
    `via DERP(headscale)`.
  - A non-Go peer may not answer pings over DERP. Check its home DERP from a Go
    peer with
    `tailscale status --json | jq -e '.Peer[] | select(.HostName == "NAME") | .Relay == "headscale"'`
    and send application traffic.
- **Logs**: `testkit-peer` turns off tailscaled's log uploads. Inside the Nix
  build sandbox other clients' uploads just fail; set `TS_NO_LOGS_NO_SUPPORT=1`
  for tsnet if interactive runs should not upload either.
- **Unprivileged tsnet**: without `CAP_NET_ADMIN`, tsnet binds its sockets to
  the default-route interface. In a test VM that is the user-net NIC, not the
  VLAN, so control is unreachable. The same thing happens on multi-homed
  production hosts, so fix it in the service: grant `CAP_NET_ADMIN`, or call
  `netns.SetEnabled(false)`.
- **Versions**: headscale supports the Tailscale client versions named at the
  top of each CHANGELOG release, with no upper bound. Pin a headscale release
  that accepts your client.

### Without Nix

A harness that runs the headscale binary itself, such as an Android emulator
test, can use the same shape:

- Serve plain HTTP.
- Set `HEADSCALE_DEBUG_INSECURE_TLS_LISTEN_ADDR` to serve the router and DERP
  over a throwaway TLS certificate.
- Mint keys:

  ```sh
  headscale -c CONFIG users create NAME
  headscale -c CONFIG preauthkeys create --user NAME --reusable --expiration 24h
  ```

A minimal config:

```yaml
# Clients dial this host for DERP and STUN too, so all of them must reach it.
server_url: http://127.0.0.1:8080
listen_addr: 127.0.0.1:8080
noise: { private_key_path: /tmp/hs/noise.key }
database: { type: sqlite, sqlite: { path: /tmp/hs/db.sqlite } }
prefixes: { v4: 100.64.0.0/10, v6: "fd7a:115c:a1e0::/48" }
dns:
  magic_dns: false
  base_domain: ""
  override_local_dns: false
unix_socket: /tmp/hs/headscale.sock
disable_check_updates: true
derp:
  urls: []
  server:
    enabled: true
    region_id: 999
    region_code: headscale
    stun_listen_addr: 127.0.0.1:3478
    private_key_path: /tmp/hs/derp.key
```

- Wait for `HEADSCALE_CLI_TIMEOUT=60s headscale -c CONFIG health`.
- If `server_url` is a hostname rather than an IP, Go clients redial noise only
  on :443 after a recent dial. Put the TLS listener on :443 then.
- If clients reach headscale at different addresses, e.g. an emulator behind
  NAT, set `derp.server.enabled: false`. Instead, list a DERP map of your own
  in `derp.paths`, as `.yaml`, `.json` or `.hujson`.

### Migrating a hand-rolled control node

Delete these and import the kit:

- the self-signed cert, `security.pki.certificateFiles` and the nginx TLS proxy;
- the embedded DERP block (`region_id = 999`, `urls = [ ]`) and its firewall
  ports;
- `ip_prefixes`, which headscale rejects;
- `/etc/hosts` pins for the control node;
- jq lookups of the user ID before `preauthkeys create`.

### Cost

- headscale builds from source with its own pinned nixpkgs and Go.
- Setting `inputs.headscale.inputs.nixpkgs.follows` works only if your nixpkgs
  has the Go version `go.mod` requires. Compare
  `nix eval --raw nixpkgs#go_latest.version` against it.
- The input also brings headscale's development inputs into your lock file. If
  you already depend on them, `follows` them.

## Upstream

- [nixpkgs module](https://github.com/NixOS/nixpkgs/blob/master/nixos/modules/services/networking/headscale.nix)
- [nixpkgs package](https://github.com/NixOS/nixpkgs/blob/master/pkgs/by-name/he/headscale/package.nix)

The module in this repository may be newer than the nixpkgs version.
