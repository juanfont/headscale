# Headscale NixOS Module

This directory contains the NixOS module for Headscale.

## Rationale

The module is maintained in this repository to keep the code and module
synchronized at the same commit. This allows faster iteration and ensures the
module stays compatible with the latest Headscale changes. All changes should
aim to be upstreamed to nixpkgs.

## Files

- **[`module.nix`](./module.nix)** - The NixOS module implementation
- **[`example-configuration.nix`](./example-configuration.nix)** - Example
  configuration demonstrating all major features
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

See [`example-configuration.nix`](./example-configuration.nix) for configuration
options.

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
dns: { magic_dns: false, override_local_dns: false }
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
- `ip_prefixes`, which headscale no longer reads;
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
