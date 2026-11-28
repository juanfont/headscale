# CHANGELOG

## 0.30.0 (202x-xx-xx)

**Minimum supported Tailscale client version: v1.84.0**

### v1 REST API replaced; gRPC and Protobuf removed

The v1 REST API now provides an OpenAPI 3.1 specification at
`/api/v1/openapi.yaml`, with interactive documentation at `/api/v1/docs`. This
replaces the Swagger 2.0 document and the `/swagger` UI. The Protobuf, gRPC and
grpc-gateway stack behind it is gone, and the `headscale` CLI now talks to the
HTTP API directly.

[#3324](https://github.com/juanfont/headscale/pull/3324)

### OAuth clients and scopes for the v2 API

The v2 API now authenticates with OAuth 2.0 client-credentials, the way the
Tailscale ecosystem does. An OAuth client mints short-lived access tokens whose
scopes limit which operations they may perform and whose tags limit the devices
they may create, so a credential can be issued with only the access it needs.
The `headscale oauth-clients` command manages them. This lets the Tailscale
Terraform provider and Kubernetes operator drive Headscale unchanged; admin API
keys remain all-access.

[#3334](https://github.com/juanfont/headscale/pull/3334)

An OAuth client secret joins nodes with `tskey-client-…?baseURL=<headscale>`.
Use it with `tailscale up`, containers, `tsnet`, or the Tailscale GitHub Action.
Each join creates a tagged key. `--advertise-tags` leaves assigned tags unchanged
when it requests a subset of the key's tags. Other requests replace tags only
when the key's tags or user directly own every requested tag. See
[the API docs](https://headscale.net/stable/ref/api/).

[#3351](https://github.com/juanfont/headscale/pull/3351)

### Credentials stored in one table, hashed with SHA-256

API keys, pre-auth keys, OAuth clients and OAuth access tokens now live in a
single `credentials` table and are verified by one shared code path. Their
secrets are 256 bits of server-generated randomness, never user-chosen, so they
are stored as a SHA-256 digest: recovering one means searching the whole secret
space, and password stretching would only add latency to every request.

A credential is accepted only when it starts with its prefix (`hskey-api-`,
`hskey-auth-`, `hskey-oauthtok-`). Text before the prefix, such as a second
space after `Bearer`, is now refused.

Keys created by older releases keep working on 0.30. Support for them is
removed on this schedule:

- **0.31** drops the upgrade from the 0.29 tables: upgrade to 0.30 first, as
  the one-minor-version-at-a-time rule already requires.
- **0.32** drops bcrypt verification. A bcrypt-hashed key is rehashed to SHA-256
  the first time it authenticates, so use every API key and pre-auth key you
  still need at least once on 0.30 or 0.31. Keys not used by then stop working
  and must be reissued.
- **0.32** drops the legacy key formats: API keys of the form `prefix.secret`
  (shown with a 7-character prefix in `headscale apikeys list`) and pre-auth
  keys from before 0.28.0 (shown as `hskey-auth-legacy-…` in
  `headscale preauthkeys list`). Using them does not help; reissue them before
  upgrading to 0.32.

[#3352](https://github.com/juanfont/headscale/pull/3352)

### NixOS test kit

Projects built on Tailscale, such as tsnet services, tailscaled integrations or
Tailscale client implementations, can now test against a real control server
in their NixOS VM tests. Import `nixosModules.testkit` on a node named
`headscale`. Clients join `http://headscale` with no certificates or other
setup, and `hs-authkey USER` on that node mints their auth keys.
`nixosModules.testkit-peer` adds a tailscaled peer that joins with `hs-join KEY`:

```nix
nodes.headscale.imports = [ inputs.headscale.nixosModules.testkit ];
nodes.peer.imports = [ inputs.headscale.nixosModules.testkit-peer ];
# testScript: peer.succeed(f"hs-join {headscale.succeed('hs-authkey alice').strip()}")
```

See `nix/README.md` for the full contract, recipes for tsnet and non-Go
clients, and how to run the same setup without Nix.

### TLS certificates for nodes

`tailscale cert` and HTTPS with `tailscale serve` now work. Headscale publishes
the ACME DNS-01 challenge through a built-in DNS provider: `acmedns`,
`cloudflare`, `gigahost`, `hetzner`, `powerdns` or `rfc2136`. `dns.base_domain` must be a public domain you control. [#3554](https://github.com/juanfont/headscale/pull/3554)

### Update clients remotely

`headscale nodes update-client` and `POST /api/v2/device/{id}/update-client` ask a
connected node to update its Tailscale client, like the "Start update" button of
the Tailscale admin console. `GET /api/v2/device/{id}/update-status` reports the
update. Both answer as Tailscale does: a node that does not allow remote updates,
is not connected, or refuses is "not found". See [the client docs](https://headscale.net/stable/about/clients/#update-clients). [#3632](https://github.com/juanfont/headscale/pull/3632)

### TailSQL on your own tailnet

`tailsql.enabled` runs [TailSQL](https://github.com/tailscale/tailsql), a
read-only SQL web UI over the headscale SQLite database, as the node `tailsql`
with `tag:tailsql` on headscale's own tailnet. Headscale mints its credential
and joins it in memory, keeps its identity in `tailsql.state_dir`, and re-joins
it if the node is deleted. Only a grant giving `tag:tailsql` network access and
the `tailscale.com/cap/tailsql` app capability lets a user query it; see
[`tailsql`](https://headscale.net/stable/ref/configuration-options/#tailsql). With
`dns.certificates` it serves HTTPS.

### Check configuration and policy files

The new `headscale check` commands check a file before you deploy it, and say
what to fix:

```shell
headscale check config -f /etc/headscale/config.yaml
headscale check policy -f policy.hujson
headscale check all
```

- `check config` checks the syntax, keys and values of the configuration.
  Omitting `-f` uses the documented
  [search path](https://headscale.net/stable/ref/configuration/).
- `check policy` checks a policy file and runs its `tests` and `sshTests`. It
  needs `-f`.
- `check all` checks the configuration and then every file it names:
  - the policy
  - DERP maps
  - extra records
  - TLS certificate and key
  - private keys
- `check derp-map` and `check extra-records` check a single file.

[#3668](https://github.com/juanfont/headscale/pull/3668)
[#3669](https://github.com/juanfont/headscale/pull/3669)

### Strict configuration

Headscale used to ignore a key it did not know and read a bad value as a
default. With a typo, the server quietly did not do what you expected.

It now stops on an unknown or removed key, or on a value that does not fit its
key. The error names the key, where it was set and, for a removed key, what
replaces it.

Run the new version's `headscale check config` on your configuration before you
upgrade.

Secrets can now have a `file:` prefix to load them from a file instead of the
configuration file or the environment:

```yaml
oidc:
  client_secret: "file:${CREDENTIALS_DIRECTORY}/oidc_client_secret"
```

The configuration file can now also be JSON or HuJSON.

[#3674](https://github.com/juanfont/headscale/pull/3674)
[#3677](https://github.com/juanfont/headscale/pull/3677)

### Every option has a default

Every configuration option now has a default. This allows a configuration with
only `server_url`:

```yaml
server_url: https://headscale.example.com
```

It also means that an option you did not set before now has a value. Check the
new and changed defaults under BREAKING, and the
[configuration options](https://headscale.net/stable/ref/configuration-options/)
for every default, so you do not get a setting you did not ask for.

[#3683](https://github.com/juanfont/headscale/pull/3683)

### Generated configuration and reference

The Headscale binary can now generate a complete configuration with all
options, their defaults and their documentation. You always have a correct and
fully documented configuration for your version of Headscale:

```shell
headscale generate config > /etc/headscale/config.yaml
```

We have removed the old example configuration file, `config-example.yaml`, as
it easily fell out of sync. The configuration now has a single source of truth,
[`hscontrol/types/config.go`](https://github.com/juanfont/headscale/blob/main/hscontrol/types/config.go).

This means we can also generate documentation from the same source, so the docs
are always correct for their version:

- [Configuration options](https://headscale.net/stable/ref/configuration-options/)
  lists every option with its type, default, environment variable and examples
- [Removed keys](https://headscale.net/stable/ref/configuration-options/#removed-keys)
  lists what replaced each removed option
- The options of the NixOS module

[#3680](https://github.com/juanfont/headscale/pull/3680)

### NixOS module

The NixOS module in this repository now uses the same options as Headscale,
fully typed. A wrong value fails evaluation, and a configuration that works in
the module works in Headscale.

Secrets are kept out of the Nix store. Load them as systemd credentials and
reference them with `file:`:

```nix
imports = [ inputs.headscale.nixosModules.default ];

services.headscale = {
  enable = true;
  settings = {
    server_url = "https://headscale.example.com";
    oidc = {
      issuer = "https://sso.example.com";
      client_id = "headscale";
      client_secret = "file:\${CREDENTIALS_DIRECTORY}/oidc-client-secret";
    };
  };
};
systemd.services.headscale.serviceConfig.LoadCredential = [
  "oidc-client-secret:/run/secrets/oidc-client-secret"
];
```

A configuration or policy that Headscale rejects fails `nixos-rebuild build`,
and a switch stops before it restarts Headscale. This prevents the system from
going into a bad state.

Many options are removed or renamed. The NixOS module section under BREAKING
maps each one to its replacement.

[#3682](https://github.com/juanfont/headscale/pull/3682)

### BREAKING

#### Database

- Headscale upgrades only from 0.29.x. Migrations for older releases are removed, and headscale refuses to start on an older database. Upgrade one minor release at a time to the latest 0.29.x first. [#3352](https://github.com/juanfont/headscale/pull/3352) [#3650](https://github.com/juanfont/headscale/pull/3650)
- The `pre_auth_keys`, `api_keys`, `oauth_clients` and `oauth_access_tokens` tables are merged into `credentials` and dropped. The migration cannot be reversed. Take a backup before upgrading, as downgrading means restoring it. [#3352](https://github.com/juanfont/headscale/pull/3352)
- API key IDs are renumbered, as all credential kinds now share one ID sequence. Scripts using `headscale apikeys expire|delete --id` should look IDs up again or use `--prefix`. [#3352](https://github.com/juanfont/headscale/pull/3352)
- Deleting a user now clears the owner of its API keys and OAuth clients instead of leaving a dangling reference. [#3352](https://github.com/juanfont/headscale/pull/3352)

- Policy writes delete older policies. Export history before the next write. Keep policy files in version control. Back up the database before upgrading. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Migrations add `nodes.auto_approved_routes`, `nodes.ephemeral`, and `credentials.created_by_token`. Existing route approvals count as manual. Nodes copy the ephemeral flag from their key. Migration cannot recover the flag if the key was already deleted. [#3619](https://github.com/juanfont/headscale/pull/3619)

#### Policy

- Tag ownership is direct. List each permitted user, group, or tag in the target's `tagOwners`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Each grant `ip` entry accepts one port or range. Replace `"tcp:80,443"` with `"tcp:80", "tcp:443"`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Simplify policies above 100,000 destination/port-range combinations. Headscale rejects them on load and write. Count each `autogroup:internet` prefix. [#3619](https://github.com/juanfont/headscale/pull/3619)
- SSH `check` rejects tag or `autogroup:tagged` sources. Use user-owned sources or `accept`. Login `0` no longer means `root`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- `tests.accept` checks every resolved destination node. Narrow assertions where needed. Remove source address ranges from `tests` and `sshTests`. Replace `autogroup:member` in `sshTests` destinations. Offline `policy set` checks user references, `tests`, and `sshTests`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- User references prefer provider identifier, then email, then username. Email owners win username conflicts. Ambiguous references fail writes, including grants and `nodeAttrs`. Startup and user updates log them and match nobody. Bare `@` matches nobody. Use stable provider identifiers. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Headscale rejects empty policy writes. Use `{}` to allow all. [#3619](https://github.com/juanfont/headscale/pull/3619)
- A policy without `acls` or `grants` allows only tailnet addresses and approved routes. Hosts outside the tailnet cannot connect to nodes. Use `autogroup:danger-all` to allow all addresses. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A user's devices are always peers of each other. The packet filter still controls access. [#3649](https://github.com/juanfont/headscale/pull/3649)
- SSH `dst` rejects `autogroup:member`, as Tailscale does. Use `autogroup:self`, tags, or the source's own user. A policy file that still uses it stops headscale at startup. [#3343](https://github.com/juanfont/headscale/pull/3343)
- A grant with `via` accepts only prefixes, hosts and `autogroup:internet` as `dst`, as Tailscale does. A `dst` inside the Tailscale address ranges is rejected too, except the 4via6 range. Write a prefix the router serves, or `autogroup:internet`. A stored policy that validation refuses stops headscale at startup in `file` and `database` mode alike, with the error in the log. A reload of one logs the error and keeps the policy in force, and the API and CLI refuse to set one. In database mode, while the server will not start, store a corrected policy with `headscale policy set --file <path> --bypass-server-and-access-database-directly`. [#3757](https://github.com/juanfont/headscale/pull/3757)
- `tagOwners` and `groups` reject `user:*@domain`, as Tailscale does. List the users. A stored policy that uses one stops headscale at startup in either mode, and a reload logs the error and keeps the policy in force. In database mode, store a corrected policy with `headscale policy set --file <path> --bypass-server-and-access-database-directly` while the server is stopped. [#3757](https://github.com/juanfont/headscale/pull/3757)
- An `app` grant that names a destination twice grants the capability once, as on Tailscale SaaS. [#3757](https://github.com/juanfont/headscale/pull/3757)

#### Nodes and routes

- A pre-auth key is refused at registration once the policy no longer defines one of its tags, as on Tailscale SaaS. The client reports `key tagged with non-existent tag: <tag>`. The key stays valid, and nodes that already hold the tag keep it. Define the tag in `tagOwners` again or make a new key. Without a policy configured, tags are not checked. With a policy configured whose `tagOwners` lacks `"tag:tailsql"`, a fresh registration of TailSQL's node is refused: at startup with a new `tailsql.state_dir`, or with a node deleted while headscale was down. headscale then logs `tailsql stopped` and serves no TailSQL, and adding the tag with a policy reload does not bring it back. Add `"tag:tailsql": []` to `tagOwners` and restart headscale. A node already registered keeps working, and one deleted while headscale runs joins again once the tag is listed. [#3755](https://github.com/juanfont/headscale/pull/3755)
- A user who takes back a tagged node with a key of their own keeps its key expiry off, as on Tailscale SaaS. It keeps no expiry time either, also as on Tailscale. Before, it got the configured `node.expiry` from now. Turn key expiry on with the node's key expiry setting. [#3756](https://github.com/juanfont/headscale/pull/3756)
- Deleting a user keeps tagged pre-auth keys they created. Revoke them separately. Headscale clears only their creator reference. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Nodes keep their creation key's ephemeral flag across key changes and key deletion. A user claim that removes tags makes the node permanent. Otherwise, delete and register the node again to change its lifetime. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Clients can shorten expiry, including on tagged nodes. Logout expires tagged nodes. Reusing a node key keeps its expiry. Expired nodes must rotate node keys before login. Spent, expired, or revoked pre-auth keys can only wake existing live nodes. They cannot change ownership, tags, keys, or expiry. Expiry or source-owner changes clear SSH check approvals. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Withdrawal removes routes granted only by auto-approval. Manual approvals and approvals made before this upgrade stay. Reapproval needs current policy or administrator approval. Registration rechecks auto-approval only after key rotation or route advertisement changes. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Route APIs and `autoApprovers.routes` reject host bits. Mask prefixes: `10.0.0.1/24` becomes `10.0.0.0/24`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Exit routes need access to an internet address. Private-only rules no longer offer exit routes. [#3619](https://github.com/juanfont/headscale/pull/3619)
- A router approved for the address of another user's device gets that user's `autogroup:self` rule for it, and the two are peers, as on Tailscale SaaS. The other devices of the router's user list that device as a peer too. It does not list them. [#3757](https://github.com/juanfont/headscale/pull/3757)
- An `app` grant to `*` gives its sources the approved subnet routes, as on Tailscale SaaS. [#3757](https://github.com/juanfont/headscale/pull/3757)
- A node approved for only one of `0.0.0.0/0` and `::/0` is not offered as an exit node, as on Tailscale SaaS. Approve both. The routers of a `via` grant list it as a peer when the route covers a source of the grant. It does not list them. [#3757](https://github.com/juanfont/headscale/pull/3757)
- A `via` grant to `autogroup:internet` steers subnet routes to public prefixes too: sources get them only from routers with the `via` tag, as on Tailscale SaaS. [#3757](https://github.com/juanfont/headscale/pull/3757)
- An approved exit route covers the `dst` of a `via` grant: an exit node with the `via` tag gets the grant's rule, and for a public `dst` its sources get the exit routes, as on Tailscale SaaS. [#3757](https://github.com/juanfont/headscale/pull/3757)
- A node approved for a route over the address of a `via` router is no longer its peer for that alone. [#3757](https://github.com/juanfont/headscale/pull/3757)
- `app` grants never offer exit routes. Exit nodes list the sources of an `app` grant to an internet address, as on Tailscale SaaS. [#3656](https://github.com/juanfont/headscale/pull/3656)
- HA and `via` groups choose the healthy, online router with the oldest control session. Reconnecting routers become standby. Routers that keep their session can regain routes. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Startup adds suffixes to duplicate names. The lowest node ID keeps its name. These changes stay in memory. Check MagicDNS names. Registrations and renames avoid extra DNS record names. Collision names fit 63 bytes. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Startup refuses a node that has no address, or whose address another node also holds. Peers got an ambiguous address. Give each node an unused address from the configured prefixes in the nodes table. [#3757](https://github.com/juanfont/headscale/pull/3757)
- Peers see a disconnected node as offline after 15 seconds, not 10. HA failover starts 5 seconds later. [#3649](https://github.com/juanfont/headscale/pull/3649)

#### OIDC

- Logins replace stored email. Missing, malformed, or unverified email clears it. `oidc.email_verified_required: false` permits unverified email. Review email-based policies. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Headscale rejects subjects changed by identifier cleanup. Avoid repeated or trailing slashes and surrounding whitespace. Use stable subjects. [#3619](https://github.com/juanfont/headscale/pull/3619)
- OIDC SSH checks are approved on the confirmation page. The provider callback no longer approves them. [#3619](https://github.com/juanfont/headscale/pull/3619)
- User names are checked by character, not byte. Newly accepted: an otherwise valid name whose first letter is one of the 31 Hebrew letters U+05D0-U+05F2, which were refused as initials before. An OIDC user whose `preferred_username` is such a name gets it as its stored name at the next login. The login name clients show changes from its provider identifier to that name only if it has no usable email, and otherwise stays the email. Newly refused: a one-character name outside ASCII (`李`) and a name that starts with a non-ASCII digit (`٠x`). Renaming to one returns 400 and a new OIDC user with one gets no stored name. A user that already has such a name keeps it. A policy reference by name can newly match a user, stop matching when the user takes a new valid name, or match nobody if a local user has the same name. References by email or provider identifier are unaffected. [#3752](https://github.com/juanfont/headscale/pull/3752)

#### Control protocol

- Peer `Hostinfo` contains hostname, OS, services except `peerapi-dns-proxy`, SSH host keys, and AppConnector. Self `Hostinfo` contains hostname, requested tags, advertised routes, and services. Other fields, including `ExitNodeID` and location, stay server-side. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Connected expired peers can appear online. They have no endpoints or DERP. Self entries stay authorized. Check `KeyExpiry`. `Expired` stays false. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Each node supports four map streams. A fifth stream closes the oldest. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Map entries carry no machine keys. Peer entries leave `MachineAuthorized` unset. Self entries have no `Cap`, `Online` or `LastSeen`. [#3636](https://github.com/juanfont/headscale/pull/3636)
- Without MagicDNS, `dns.base_domain` is not a search domain. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A deleted node's map requests get a 404, as from Tailscale. Its client no longer polls `/machine/map` in a tight loop. Tailscale 1.106 and later show "Device removed" and need a new login. Older clients keep retrying until `tailscale up --force-reauth`. [#3688](https://github.com/juanfont/headscale/issues/3688)
- A tagged node sees itself as its own user, with the node name. `tailscale status` shows this name, not `tagged-devices`. Tagged nodes are not devices of one owner for Taildrop. [#3649](https://github.com/juanfont/headscale/pull/3649)

#### API

- The gRPC API is removed. All programmatic access goes through the HTTP API at `/api/v1`. [#3324](https://github.com/juanfont/headscale/pull/3324)
- Errors for unknown users or nodes, malformed input and duplicate names return the correct 404, 400 or 409 instead of HTTP 500. [#3324](https://github.com/juanfont/headscale/pull/3324)
- The OpenAPI document is OpenAPI 3.1 at `/api/v1/openapi.yaml`, with docs at `/api/v1/docs`. It replaces Swagger 2.0 at `/swagger`. [#3324](https://github.com/juanfont/headscale/pull/3324)
- Renaming a user (`headscale users rename`, `POST /api/v1/user/{id}/rename/{name}`) returns 400 for an OIDC user, whose name comes from the identity provider, and for an invalid user name. Both used to be accepted.

- V2 hides spent, expired, and revoked auth keys. OAuth key lists need `all=true` for keys created without tokens. Tags do not limit lists. V1 and `headscale preauthkeys list` hide revoked keys. Deleting referenced ephemeral keys revokes them. Referenced rows stay. [#3619](https://github.com/juanfont/headscale/pull/3619)
- Tagged OAuth clients with `all` cannot issue tokens outside their tags. OAuth retagging requires permission for all current and requested tags. It replaces the set. Disallowed tags return HTTP 400. [#3619](https://github.com/juanfont/headscale/pull/3619)
- OAuth clients keep their newest 1,000 tokens. At the limit, new tokens invalidate the oldest, even before expiry. Use separate clients for long-lived integrations. [#3619](https://github.com/juanfont/headscale/pull/3619)
- V2 device `name` contains the MagicDNS FQDN without its trailing dot. Tagged device `user` shows its join-key creator, when known. Admin-created tagged keys include `userId`. `fields=all` returns empty route lists as `[]`. [#3619](https://github.com/juanfont/headscale/pull/3619)
- V2 limits schema-validated bodies to 64 KiB. ACL writes and validation allow 1 MiB. Body reads stop after five seconds. Unknown `keyType` returns HTTP 400. Schema-validation details omit submitted values and list at most 20 entries. [#3619](https://github.com/juanfont/headscale/pull/3619)

#### Configuration keys

- An unknown configuration key prevents Headscale from starting. An unknown `HEADSCALE_*` variable logs a warning. [#3674](https://github.com/juanfont/headscale/pull/3674)
- A removed key prevents Headscale from starting, and the error names its replacement. See the removed and renamed options below. [#3674](https://github.com/juanfont/headscale/pull/3674)
- Configuration keys are lower case: `Server_URL` is an unknown key. A key written both dotted and nested, such as `log.level` next to `log: {level: …}`, is an error. [#3674](https://github.com/juanfont/headscale/pull/3674) [#3677](https://github.com/juanfont/headscale/pull/3677)
- A key with no value, such as `v6:`, takes its default and logs a warning. Write `""` or `[]` to clear a key. [#3683](https://github.com/juanfont/headscale/pull/3683)
- A `HEADSCALE_*` variable set to `""` clears a key, as `""` does in the file. An empty variable still counts as unset. [#3683](https://github.com/juanfont/headscale/pull/3683)

#### Configuration values

- Configuration values are strongly typed. A value of the wrong type prevents Headscale from starting, also for a feature that is turned off. A duration needs a unit (`30s`, not `30`), and `log.level` must be a level name. [#3677](https://github.com/juanfont/headscale/pull/3677)
- Booleans must be `true` or `false`. Headscale reads YAML 1.2, where `yes`, `no`, `on` and `off` are text. They now prevent Headscale and the CLI from starting. [#3619](https://github.com/juanfont/headscale/pull/3619)
- `policy.mode` must be `file` or `database`. Another value used to start Headscale with no policy, allowing all traffic. [#3669](https://github.com/juanfont/headscale/pull/3669)
- `unix_socket_permission` must be a quoted octal string no higher than `"0777"`, e.g. `"0770"`. An unquoted number or an invalid value used to fall back to `0700` silently. [#3540](https://github.com/juanfont/headscale/pull/3540)
- `database.sqlite.write_ahead_log: false` turns WAL off again. Since 0.27.0 it only skipped `wal_autocheckpoint`. SQLite now uses its rollback journal with `synchronous=FULL`, and a database left in WAL mode is converted when Headscale opens it. [#3689](https://github.com/juanfont/headscale/pull/3689)
- `derp.server.region_id` is required and positive when `derp.server.enabled` is true. Unset, it was 0, a region clients never connect to. [#3691](https://github.com/juanfont/headscale/pull/3691)
- An empty value is rejected where Headscale cannot run with it: `unix_socket`, `log.level`, `log.format`, an item in a list, one half of `tls.cert_path` and `tls.key_path`, and ACME without `tls.acme.http_listen` or `tls.acme.cache_dir`. [#3687](https://github.com/juanfont/headscale/pull/3687) [#3691](https://github.com/juanfont/headscale/pull/3691)
- `prefixes.v4` must lie inside `100.64.0.0/10` and outside `100.115.92.0/23`, which Tailscale reserves for ChromeOS VMs. `prefixes.v6` must lie inside `fd7a:115c:a1e0::/48`. Any other prefix is refused. headscale also refuses to start while a node holds an address outside these ranges. Other prefixes were unsupported, and the policy's `*` did not treat their addresses the same everywhere. A deployment with custom prefixes must give its nodes new addresses before upgrading. See [How can I migrate back to the recommended IP prefixes?](https://headscale.net/stable/about/faq/#how-can-i-migrate-back-to-the-recommended-ip-prefixes) [#3757](https://github.com/juanfont/headscale/pull/3757)

#### Configuration files

- The configuration file must end in `.yaml`, `.yml`, `.json` or `.hujson`. [#3674](https://github.com/juanfont/headscale/pull/3674)
- `derp.paths` and `dns.extra_records_path` files must end in `.yaml`, `.yml`, `.json` or `.hujson`. The extension picks the format.
- A `derp.paths` file fails to load when it has neither regions nor `homeparams`, or a key that `tailcfg.DERPMap` does not have, e.g. a misspelt `regionscore`. [#2932](https://github.com/juanfont/headscale/pull/2932)
- A `derp.paths` entry must be a regular file or a link to one. A pipe, a device or a directory fails to load, at startup, on every refresh and in `headscale check`. [#3763](https://github.com/juanfont/headscale/pull/3763)
- A DERP map from `derp.paths` or `derp.urls` must meet the region rules Tailscale SaaS applies to a policy `derpMap`: each region's `regionid` matches its key, each node's `regionid` matches its region, and a region has at least one node. [#2932](https://github.com/juanfont/headscale/pull/2932)
- `database.sqlite.path` names the file literally. Before, SQLite cut the path at `?` or `#` and decoded `%XX`, so headscale opened another file. A path with `%`, `?` or `#` now opens a different file than before: move the database to the configured path before upgrading, or headscale starts with an empty one.

#### Server and packaging

- Headscale's own ACME certificate is managed by CertMagic instead of autocert. The first start registers a new ACME account and obtains a new certificate in `tls.acme.cache_dir`. [#3554](https://github.com/juanfont/headscale/pull/3554)
- Debug hosts must be localhost, an IP, or the configured `server_url` or `metrics_listen_addr` host. `/metrics` accepts other hosts. [#3619](https://github.com/juanfont/headscale/pull/3619)
- `/debug/config` prints the configuration in JSON with the file's key names, such as `server_url` instead of Go field names such as `ServerURL`, and durations as text such as `3h` instead of nanoseconds. Update scripts that read it. [#3677](https://github.com/juanfont/headscale/pull/3677)
- `headscale serve` exits with status 78 when it rejects the configuration file it loaded. The deb package and the NixOS module leave it stopped instead of restarting it. The deb package starts or restarts Headscale only when `headscale check config` passes. [#3683](https://github.com/juanfont/headscale/pull/3683)
- The root `config-example.yaml` is removed. `headscale generate config` prints it, and packagers can run it at build time. [#3680](https://github.com/juanfont/headscale/pull/3680)
- `HEADSCALE_DEBUG_TAILSQL_ENABLED`, `HEADSCALE_DEBUG_TAILSQL_STATE_DIR` and `TS_AUTHKEY` no longer start TailSQL on an external tailnet. Use `tailsql.enabled` and `tailsql.state_dir`, which join headscale's own tailnet.
- The flake's `overlays.default` builds Headscale with your nixpkgs and Headscale's pinned Go, and adds only `headscale` and `hi`. It no longer replaces `go_latest`, `gotestsum`, `gotests`, `gofumpt`, `gotools` or `golangci-lint-langserver`.

#### Removed and renamed configuration options

The [removed keys](https://headscale.net/stable/ref/configuration-options/#removed-keys) reference has the full list, with older releases.

| What                                                                                                                             | Why                                                                  | Now                                 | PR                                                                                                                |
| -------------------------------------------------------------------------------------------------------------------------------- | -------------------------------------------------------------------- | ----------------------------------- | ----------------------------------------------------------------------------------------------------------------- |
| `tls_cert_path`, `tls_key_path`                                                                                                  | Moved under `tls`                                                    | `tls.cert_path`, `tls.key_path`     | [#3554](https://github.com/juanfont/headscale/pull/3554) [#3674](https://github.com/juanfont/headscale/pull/3674) |
| `tls_letsencrypt_*`                                                                                                              | Moved under `tls.acme`                                               | `tls.acme.*`                        | [#3554](https://github.com/juanfont/headscale/pull/3554) [#3674](https://github.com/juanfont/headscale/pull/3674) |
| `acme_url`, `acme_email`                                                                                                         | Moved under `tls.acme`                                               | `tls.acme.url`, `tls.acme.email`    | [#3554](https://github.com/juanfont/headscale/pull/3554) [#3674](https://github.com/juanfont/headscale/pull/3674) |
| `oidc.client_secret_path`                                                                                                        | Replaced by `file:` secrets                                          | `oidc.client_secret: "file:<path>"` | [#3674](https://github.com/juanfont/headscale/pull/3674)                                                          |
| `grpc_listen_addr`, `grpc_allow_insecure`                                                                                        | gRPC is removed                                                      | Remove                              | [#3674](https://github.com/juanfont/headscale/pull/3674)                                                          |
| `derp.server.stun.enabled`                                                                                                       | Never read. STUN is always served.                                   | Remove                              | [#3677](https://github.com/juanfont/headscale/pull/3677)                                                          |
| `tuning.notifier_send_timeout`                                                                                                   | Had no effect                                                        | Remove                              | [#3677](https://github.com/juanfont/headscale/pull/3677)                                                          |
| `changes_check_interval`, `node_update_check_interval`, `metrics_enabled`, `oidc.namespace`, `oidc.user`, `tls_client_auth_mode` | Not read by 0.29 either. They were ignored until now.                | Remove                              | [#3674](https://github.com/juanfont/headscale/pull/3674)                                                          |
| `database.gorm.prepare_stmt`                                                                                                     | The prepared statement cache is always off: it could block on SQLite | Remove                              | [#3674](https://github.com/juanfont/headscale/pull/3674)                                                          |

#### New and changed configuration defaults

| Option                              | Before                 | Now                                       | Effect                                                                                                                    |
| ----------------------------------- | ---------------------- | ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------- |
| `listen_addr`                       | None, a random port    | `0.0.0.0:8080`                            | Listens on every IPv4 and IPv6 address. A firewall that covers only IPv4 leaves the port open on IPv6.                    |
| `prefixes.v4`, `prefixes.v6`        | None, one was required | `100.64.0.0/10`, `fd7a:115c:a1e0::/48`    | A configuration with one family now gives new nodes both. `headscale nodes backfillips` adds the other to existing nodes. |
| `derp.urls`                         | None                   | Tailscale's DERP map                      | Clients can use Tailscale's relays.                                                                                       |
| `derp.auto_update_enabled`          | `false`                | `true`                                    | The DERP map is refreshed every `derp.update_frequency`.                                                                  |
| `dns.base_domain`                   | `""`                   | `tailnet.internal`                        | MagicDNS stays on by default, now under this name. With `dns.magic_dns: false`, node names become FQDNs under it.         |
| `node.ephemeral.inactivity_timeout` | `120s`                 | `30m`                                     | The value of every shipped example since 0.23.                                                                            |
| `tls.acme.cache_dir`                | `/var/www/.cache`      | `/var/lib/headscale/cache`                | The ACME account and certificates are stored here.                                                                        |
| `dns.challenge.resolvers`           | New option             | Quad9: `9.9.9.9:53`, `149.112.112.112:53` | Only used for DNS-01 challenges, when `dns.challenge.provider` is set.                                                    |
| `noise.private_key_path`            | Required               | `/var/lib/headscale/noise_private.key`    | No longer has to be set.                                                                                                  |
| `database.type`                     | Required               | `sqlite`                                  | No longer has to be set.                                                                                                  |
| `database.sqlite.path`              | Required for SQLite    | `/var/lib/headscale/db.sqlite`            | No longer has to be set.                                                                                                  |

[#3683](https://github.com/juanfont/headscale/pull/3683), except `tls.acme.cache_dir` ([#3554](https://github.com/juanfont/headscale/pull/3554)) and `dns.challenge.resolvers` ([#3680](https://github.com/juanfont/headscale/pull/3680)).

#### CLI

| Before                                                        | Now                                                                                                                | PR                                                       |
| ------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------ | -------------------------------------------------------- |
| `headscale configtest`                                        | `headscale check config`. It checks only the configuration; `headscale check all` also checks every file it names. | [#3669](https://github.com/juanfont/headscale/pull/3669) |
| `headscale policy check`                                      | `headscale check policy`. Like `headscale policy set`, it refuses an empty file: use `{}` to allow all.            | [#3668](https://github.com/juanfont/headscale/pull/3668) |
| `headscale dumpConfig` (hidden)                               | `/debug/config`, or `HEADSCALE_DEBUG_DUMP_CONFIG=1` when starting                                                  | [#3680](https://github.com/juanfont/headscale/pull/3680) |
| `headscale policy --bypass-grpc-and-access-database-directly` | `--bypass-server-and-access-database-directly`                                                                     | [#3324](https://github.com/juanfont/headscale/pull/3324) |
| `--output json` and `--output yaml` in the Protobuf encoding  | The shape of the API: camelCase fields, string-encoded IDs, RFC3339 timestamps                                     | [#3324](https://github.com/juanfont/headscale/pull/3324) |

#### NixOS module

- The module now uses Headscale's own options, strongly typed and in sync with Headscale: a configuration that evaluates also works in Headscale. `settings.server_url` has no default: set it. [#3680](https://github.com/juanfont/headscale/pull/3680) [#3682](https://github.com/juanfont/headscale/pull/3682)
- Secrets are kept out of the Nix store: a secret option only accepts a `file:` reference, not a literal value. Load the secret with `LoadCredential`, as `nix/README.md` shows. [#3680](https://github.com/juanfont/headscale/pull/3680) [#3682](https://github.com/juanfont/headscale/pull/3682)
- A configuration or policy that Headscale rejects fails `nixos-rebuild build` and stops a switch, to prevent the system from going into a bad state. Disable the checks with `check.config = false` and `check.policy = false`. See `nix/README.md`. [#3682](https://github.com/juanfont/headscale/pull/3682)
- The CLI on the server works without configuration. `/etc/headscale/config.yaml` is no longer written: drop `-c /etc/headscale/config.yaml` from scripts. [#3682](https://github.com/juanfont/headscale/pull/3682)
- `settings.cli` fails evaluation. A CLI for a remote server is configured per user, in `~/.config/headscale/config.yaml` or with `HEADSCALE_CLI_*` variables. [#3682](https://github.com/juanfont/headscale/pull/3682)
- `services.headscale.user` and `services.headscale.group` are read-only: the module creates the `headscale` account, and the service and the pre-switch check both run as it. Remove both settings. [#3682](https://github.com/juanfont/headscale/pull/3682)
- `services.headscale.package` defaults to this flake's Headscale, as the checks need `headscale check`. [#3682](https://github.com/juanfont/headscale/pull/3682)

These options now take Headscale's defaults: [#3683](https://github.com/juanfont/headscale/pull/3683)

| Option                           | Before           | Now                |
| -------------------------------- | ---------------- | ------------------ |
| `settings.listen_addr`           | `127.0.0.1:8080` | `0.0.0.0:8080`     |
| `settings.derp.update_frequency` | `24h`            | `3h`               |
| `settings.dns.base_domain`       | `""`             | `tailnet.internal` |

<details>

<summary>Removed and renamed options of the NixOS module</summary>

Every option below is under `services.headscale`.

| Before                                                                         | Now                                                                                                                                                                                                                                                                       |
| ------------------------------------------------------------------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `address` and `port`                                                           | `settings.listen_addr`, e.g. `"0.0.0.0:8080"`; an IPv6 address goes in brackets, `"[::]:443"`                                                                                                                                                                             |
| `port`, read by another module                                                 | It fails evaluation; for nixpkgs' `services.headplane`, set `services.headplane.settings.headscale.url`                                                                                                                                                                   |
| `serverUrl`                                                                    | `settings.server_url`                                                                                                                                                                                                                                                     |
| `logLevel`                                                                     | `settings.log.level`                                                                                                                                                                                                                                                      |
| `ephemeralNodeInactivityTimeout`, `settings.ephemeral_node_inactivity_timeout` | `settings.node.ephemeral.inactivity_timeout`                                                                                                                                                                                                                              |
| `derp.autoUpdate`, `derp.auto_update_enable`                                   | `settings.derp.auto_update_enabled`                                                                                                                                                                                                                                       |
| `derp.paths`                                                                   | `settings.derp.paths`                                                                                                                                                                                                                                                     |
| `derp.urls`                                                                    | `settings.derp.urls`                                                                                                                                                                                                                                                      |
| `derp.updateFrequency`                                                         | `settings.derp.update_frequency`                                                                                                                                                                                                                                          |
| `openIdConnect.clientId`                                                       | `settings.oidc.client_id`                                                                                                                                                                                                                                                 |
| `openIdConnect.issuer`                                                         | `settings.oidc.issuer`                                                                                                                                                                                                                                                    |
| `openIdConnect.clientSecretFile`                                               | `settings.oidc.client_secret = "file:\${CREDENTIALS_DIRECTORY}/<name>"` with `LoadCredential`, as in `nix/README.md`                                                                                                                                                      |
| `openIdConnect.domainMap`                                                      | Nothing: Headscale no longer uses it                                                                                                                                                                                                                                      |
| `tls.certFile`                                                                 | `settings.tls.cert_path`                                                                                                                                                                                                                                                  |
| `tls.keyFile`                                                                  | `settings.tls.key_path`                                                                                                                                                                                                                                                   |
| `tls.letsencrypt.challengeType`                                                | `settings.tls.acme.challenge_type`                                                                                                                                                                                                                                        |
| `tls.letsencrypt.hostname`                                                     | `settings.tls.acme.hostname`                                                                                                                                                                                                                                              |
| `tls.letsencrypt.httpListen`                                                   | `settings.tls.acme.http_listen`                                                                                                                                                                                                                                           |
| `settings.tls_*`                                                               | `settings.tls.*`                                                                                                                                                                                                                                                          |
| `settings.dns.split`                                                           | `settings.dns.nameservers.split`                                                                                                                                                                                                                                          |
| `user`, `group`                                                                | Nothing: both are read-only, and Headscale runs as `headscale:headscale`. Give `headscale` access to files elsewhere with `users.users.headscale.extraGroups` or the file's group. If a separate `headscale` account already existed, switch once with `NIXOS_NO_CHECK=1` |
| `settings.cli`, `settings."cli.api_key"`                                       | `cli.address` and `cli.api_key` in `~/.config/headscale/config.yaml`, or `HEADSCALE_CLI_*` variables; the CLI on the server needs neither                                                                                                                                 |
| A literal `settings.oidc.client_secret` or `settings.database.postgres.pass`   | `"file:\${CREDENTIALS_DIRECTORY}/<name>"` with `LoadCredential`, as in `nix/README.md`                                                                                                                                                                                    |
| `settings.database.postgres.password_file`, `settings.oidc.client_secret_path` | `settings.database.postgres.pass`, `settings.oidc.client_secret`: `"file:<the same path>"`, or `LoadCredential` as in `nix/README.md`                                                                                                                                     |
| A key or state path given as a Nix path or a relative path                     | An absolute path outside the Nix store, e.g. `"/var/lib/headscale/noise_private.key"`                                                                                                                                                                                     |
| A listen address without a port, a duration without a unit                     | A port and a unit: `"0.0.0.0:8080"`, `"30s"`                                                                                                                                                                                                                              |

</details>

### Changes

- A SIGHUP reloads the certificate from `tls.cert_path` and `tls.key_path` without a restart. A certificate that cannot be loaded or is not valid is logged as an error, and the previous one keeps serving. [#3027](https://github.com/juanfont/headscale/issues/3027)
- The NixOS module's `headscale` service supports `systemctl reload`.
- Peers carry their own capability version, not the version of the node that receives the map. Newer clients use it to pick per-peer features such as hybrid WireGuard handshakes. With the wrong version, a newer client could not connect to an older one.
- DERP map refreshes keep the node order. Clients keep their home relay. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A `derp.urls` or `derp.paths` source that fails to load (unreachable, an HTTP status other than 200, or an invalid map) is logged as a warning and skipped instead of stopping headscale from starting. Headscale still refuses to start when no DERP region remains. A refresh with a failing source keeps the previous map. [#3142](https://github.com/juanfont/headscale/issues/3142)
- The embedded STUN server uses Tailscale's STUN server implementation. It used to return IPv4 addresses as IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`). [#3573](https://github.com/juanfont/headscale/issues/3573)
- A STUN listen address that cannot be bound stops headscale after a graceful shutdown, with the same error and hint as the other listeners. A server component that fails while running shuts headscale down instead of leaving it half running. [#3499](https://github.com/juanfont/headscale/issues/3499)
- Nodes with `disable-ipv4` get their peers over IPv6 only. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A node name follows a new hostname at login, unless an administrator set the name. [#3649](https://github.com/juanfont/headscale/pull/3649)
- `AllowedIPs` list the node's own addresses first. `tailscale whois` reads them in this order. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A logout from a deleted device does not register the device again. [#3649](https://github.com/juanfont/headscale/pull/3649)
- SSH `localpart:` rules ignore email local parts that are only digits. `0@domain` no longer maps to `root`. [#3649](https://github.com/juanfont/headscale/pull/3649)
- `user:*@domain` matches the users of that email domain. [#3649](https://github.com/juanfont/headscale/pull/3649)
- Tagged nodes do not get `is-admin`. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A policy write that changes nothing sends no map and keeps SSH check approvals. [#3649](https://github.com/juanfont/headscale/pull/3649)
- An offline router moves its routes in one map update. [#3649](https://github.com/juanfont/headscale/pull/3649)
- A relogin that removes the key expiry updates peers. [#3649](https://github.com/juanfont/headscale/pull/3649)
- Approved routes that a node withdraws stay in wildcard sources. [#3649](https://github.com/juanfont/headscale/pull/3649)
- Refused requested tags return the error text without a prefix. [#3649](https://github.com/juanfont/headscale/pull/3649)
- Policy `tests` reject `autogroup:member` as a source. [#3649](https://github.com/juanfont/headscale/pull/3649)
- `ssh-behavior-v1` is documented. Headscale does not set it. [#3649](https://github.com/juanfont/headscale/pull/3649)
- The v2 API sorts device lists by name. Devices report `connectedToControl`, `lastSeen` and `blocksIncomingConnections`. `fields=all` adds `sshEnabled`, `distro` and `clientConnectivity`. The API adds `POST /device/{id}/expire`. Settings report `routeSelection`. Errors use Tailscale's text and content types. A JSON policy read returns valid JSON. [#3649](https://github.com/juanfont/headscale/pull/3649)
- The v2 API reports `connectedToControl: true` for an expired device that still polls control, as Tailscale does. [#3364](https://github.com/juanfont/headscale/issues/3364)
- A key expiry write that leaves what peers see unchanged sends them no update: the switch set to the value it has, `POST /device/{id}/expire` while key expiry is off, or turning key expiry off on a node whose expiry is the zero time. The time is still stored. [#3364](https://github.com/juanfont/headscale/issues/3364)
- Key expiry is a switch beside the expiry time, as on Tailscale. Tagged nodes register with it off and keep a time. The v2 `POST /device/{id}/key` turns it on or off and keeps the time. The v2 `POST /device/{id}/expire` writes the time only, so a node with expiry off stays logged in. The v1 expire and a client logout turn it on and log the node out. [#3707](https://github.com/juanfont/headscale/pull/3707)
- An upgrade from 0.29.3 or later keeps in force an expiry a tagged node got there (from `headscale nodes expire` or a logout). A tagged node without one gets key expiry off. An upgrade from 0.29.0 to 0.29.2 first clears the expiry of every tagged node, as the upgrade to 0.29.3 does. A login with a tagged key turns key expiry off and keeps the time. `headscale nodes expire --disable` turns key expiry off and keeps the time, which counts again once key expiry is turned on. [#3364](https://github.com/juanfont/headscale/issues/3364)
- The v2 API adds `GET /device/{id}/attributes`, scoped `devices:posture_attributes:read`. It reports `ip:publicAddress`: the source IP of the node's latest control connection, stored on the node. Behind a reverse proxy, set `trusted_proxies` or it reports the proxy. [#3419](https://github.com/juanfont/headscale/pull/3419)
- Headscale assembles PostgreSQL connection settings into a `postgres://` URL with proper escaping. A password, host, user or database name containing spaces, quotes or other reserved characters no longer truncates the DSN. [#3477](https://github.com/juanfont/headscale/pull/3477)
- Expiring or deleting a non-existent pre-auth key returns an error instead of silently succeeding. [#3324](https://github.com/juanfont/headscale/pull/3324)
- The systemd service file is hardened further. [#3341](https://github.com/juanfont/headscale/pull/3341)
- Errors in SSH rules start with `[ssh]` and use Tailscale's wording, for example `[ssh] users must be specified`. An undefined group reads `group not found`. [#3343](https://github.com/juanfont/headscale/pull/3343)
- An SSH rule may target a user from a group whose only member is that user, as on Tailscale. [#3343](https://github.com/juanfont/headscale/pull/3343)
- `headscale users destroy`/`rename` no longer report "multiple users match query" when no user matches. An ambiguous match lists the matching users. [#3476](https://github.com/juanfont/headscale/pull/3476)
- Deleting a user that still owns nodes lists the nodes (ID and hostname) that must be deleted first. [#3475](https://github.com/juanfont/headscale/pull/3475)
- `headscale preauthkeys create --user` accepts a user name as well as an ID.
- `derp.paths` files may be Tailscale JSON or HuJSON DERP maps as well as YAML.
- `dns.extra_records_path` files may be HuJSON or YAML as well as JSON.
- A `derp.paths` region set to `null` removes that region again, as documented.
- `derp.paths` files may set `homeparams.regionscore` to make clients prefer or avoid DERP regions. [#2932](https://github.com/juanfont/headscale/pull/2932)
- The policy accepts a `derpMap` that adds or removes DERP regions, with the rules and error messages of Tailscale SaaS. [#2932](https://github.com/juanfont/headscale/pull/2932)
- Headscale uses less CPU on large tailnets when node tags, owners, IPs or routes change. [#3501](https://github.com/juanfont/headscale/pull/3501)
- `headscale nodes backfillips` sends the new IPs to connected clients. [#3501](https://github.com/juanfont/headscale/pull/3501)
- A registration request from a client below the minimum supported version is rejected before it can log a node out, use a pre-auth key or start a login. [#3519](https://github.com/juanfont/headscale/pull/3519)

- A node re-registering with a spent, expired or revoked pre-auth key is rejected if it expired or changed node key while the re-registration was in flight. [#3525](https://github.com/juanfont/headscale/pull/3525)
- DERP client verification (the embedded DERP server and the `/verify` endpoint) looks up the node key directly instead of scanning every node on each connection. [#3520](https://github.com/juanfont/headscale/pull/3520)
- A node keeps its `via` exit nodes when it also matches an `app` grant to `*`, as on Tailscale SaaS. [#3566](https://github.com/juanfont/headscale/pull/3566)
- Packet filters are written as on Tailscale SaaS: node addresses one by one, the internet as address ranges, and `via` rules never merged with other rules. Rules naming many nodes send longer filters, and every node gets one full filter update after upgrading. [#3566](https://github.com/juanfont/headscale/pull/3566)
- Renaming a node stores the name in lowercase. A node renamed with uppercase letters before gets no certificate name until it is renamed again. [#3554](https://github.com/juanfont/headscale/pull/3554)
- `dns.certificates.enabled` and `dns.certificates.zone` let nodes get TLS certificates. [#3554](https://github.com/juanfont/headscale/pull/3554)
- The new `dns.challenge.provider`, `dns.challenge.propagation_timeout` and `dns.challenge.resolvers` options configure ACME DNS-01 challenges. [#3554](https://github.com/juanfont/headscale/pull/3554)
- A non-string `dns.challenge.provider` setting, such as acme-dns `config`, takes `file:<path>` to a file holding its JSON value. [#3588](https://github.com/juanfont/headscale/issues/3588)
- The v2 tailnet setting `httpsEnabled` reports `dns.certificates.enabled`. [#3554](https://github.com/juanfont/headscale/pull/3554)
- `tls.acme.challenge_type` accepts `DNS-01`, using `dns.challenge.provider`. [#3554](https://github.com/juanfont/headscale/pull/3554)
- The unix socket is created `0770`, as documented, when `unix_socket_permission` is unset. It used to be created `0700`. The socket grants full admin access without authentication, so members of its group gain that access. Check who is in it before upgrading. [#3540](https://github.com/juanfont/headscale/pull/3540)
- Map sessions that fall behind during update bursts are no longer dropped. A session is only closed once it stops reading or a newer session of the same node replaces it. [#3575](https://github.com/juanfont/headscale/pull/3575)
- Node joins and deletions under churn, especially in tailnets with many tags, no longer stall registrations, map updates and API requests. Ephemeral nodes are cleaned up within seconds instead of minutes. [#3575](https://github.com/juanfont/headscale/pull/3575)
- Shutdown keeps the LastSeen of connected nodes. It waits for their map sessions to close before closing the database. [#3575](https://github.com/juanfont/headscale/pull/3575)
- Deleting an ephemeral node no longer logs a spurious `ephemeral node deletion failed` error later. [#3575](https://github.com/juanfont/headscale/pull/3575)
- The v2 API adds the `acl/validate` endpoint, which Terraform provider 0.29.3 and newer call to check `tailscale_acl` at plan time. Before it, those releases failed with `invalid character 'p' after top-level value`.
- Headscale rejects overlapping TCP listener bindings, e.g. `listen_addr` and ACME HTTP-01 on port 80, at config load. [#3236](https://github.com/juanfont/headscale/pull/3236)
- Config and bind-failure errors report every violation in one pass, name YAML keys and give actionable operator hints. [#3236](https://github.com/juanfont/headscale/pull/3236)
- Ephemeral nodes that register but never connect are removed after `node.ephemeral.inactivity_timeout` instead of staying until restart. [#3545](https://github.com/juanfont/headscale/pull/3545)
- Cleanup timers spare tagged nodes claimed by users. [#3545](https://github.com/juanfont/headscale/pull/3545) [#3619](https://github.com/juanfont/headscale/pull/3619)

- Nodes stay ephemeral after key deletion. [#3640](https://github.com/juanfont/headscale/issues/3640) [#3619](https://github.com/juanfont/headscale/pull/3619)
- User renames and OIDC updates refresh node users and clients without restarting Headscale. [#3471](https://github.com/juanfont/headscale/issues/3471) [#3619](https://github.com/juanfont/headscale/pull/3619)
- Routers receive their own approved routes regardless of policy. [#3626](https://github.com/juanfont/headscale/issues/3626) [#3619](https://github.com/juanfont/headscale/pull/3619)
- `.json` files in `dns.extra_records_path` and `derp.paths` may contain comments and trailing commas, like `.hujson` files. [#3627](https://github.com/juanfont/headscale/issues/3627)
- `via` applies only to the `ip` part of a grant, as on Tailscale SaaS. `app` peers its sources with every node serving the destination, and its routes follow the primary router, also beside an `ip` part with `via`. [#3637](https://github.com/juanfont/headscale/pull/3637)
- Headscale no longer sends a subnet router a capability for its subnet, as on Tailscale SaaS. [#3637](https://github.com/juanfont/headscale/pull/3637)
- A `via` router that is also a source no longer peers with others serving the route. A router inside a subnet source no longer misses `via` routes. [#3637](https://github.com/juanfont/headscale/pull/3637)
- With MagicDNS on, exit nodes refuse DNS queries for names under `dns.base_domain`, as on Tailscale SaaS. Clients cannot read the tailnet's names through an exit node. Reverse lookups still pass. [#3636](https://github.com/juanfont/headscale/pull/3636)
- Peers get a node's last seen time when it goes offline, not at the next full map. [#3636](https://github.com/juanfont/headscale/pull/3636)
- With MagicDNS on, headscale no longer sends reverse DNS routes for `prefixes` inside 100.64.0.0/10 and fd7a:115c:a1e0::/48, as on Tailscale SaaS. Clients add them. A `prefixes.v4` subset such as 100.64.0.0/24 sent 256, which overflowed systemd-resolved's domain limit and dropped reverse DNS. An octet-aligned prefix outside the ranges gets one route instead of 256. [#3482](https://github.com/juanfont/headscale/pull/3482)
- The v1 API stores an API key or pre-auth key created without `expiration` as one that never expires, and reports its expiration as `null`. It was stored as already expired and rejected on first use. The CLI always sends an expiration and was not affected. Keys created this way before stay expired. Create new ones. [#3254](https://github.com/juanfont/headscale/pull/3254)
- The v2 API accepts an auth key create that leaves out `tags`, as Tailscale does. [#3254](https://github.com/juanfont/headscale/pull/3254)
- The v2 API refuses an auth key `expirySeconds` below 0 or above 90 days, as Tailscale does. A negative value used to mean 90 days. [#3254](https://github.com/juanfont/headscale/pull/3254)
- The v1 API returns `409 Conflict`, not `500`, when a user create or rename asks for a name another user already has. A rename to a taken name always returned `500`. A rename to a name that only OIDC users hold is allowed and answers `200`. [#3717](https://github.com/juanfont/headscale/pull/3717) [#3736](https://github.com/juanfont/headscale/pull/3736)
- The v1 API reads requests and answers as 0.29 did where web UIs depend on it. Errors keep the body `{"code", "message", "details"}`, with the gRPC code that matches the HTTP status. A missing or bad API key gets a plain-text `Unauthorized`, also for a path or method the API does not serve. `POST /api/v1/node/{id}/expire` reads `expiry` and `disableExpiry` from the query again, by the same names and forms as 0.29, so a UI that sets a node's expiry no longer logs the node out at once. The body form the CLI sends still works, and a query and body that disagree are refused. Query parameters follow 0.29's rules: a bare `?name` is an empty value, and a parameter given twice, an empty typed value, or a dotted or bracketed key into a plain parameter is refused, as is an unknown parameter on expire. A body member is read by its JSON or its proto name (`aclTags` or `acl_tags`), a member the API does not declare is ignored again, and one member given twice is refused. As in 0.29, a misspelled member is therefore ignored, not refused. An ID in a body is read by protobuf's JSON rules again, as a number or a string (`1`, `1.0` or `"1e0"` is 1; `"01"` is refused; `null` means none; `""` also means none for `user` in pre-auth key create, which the CLI sends for a tags-only key, and for `id` in the two expire bodies, as `main` already read it), and a node ID repeated in a body must be the one in the path. There `""` is refused, while leaving the member out is fine. `GET /api/v1/policy` in file mode reports `updatedAt` as `null`, so a UI shows the policy as not editable. `POST /api/v1/policy/check` accepts an empty policy, or no body, again; writing one is still refused. A path ID with a leading zero, such as `/node/010`, is refused: 0.29 read it as octal. Not restored: a body sent with a form Content-Type such as `curl -d`'s default (now 415; send `Content-Type: application/json`), a missing body on other writes (now 400; 0.29 read it as empty, so an empty `approve_routes` cleared the node's routes), a form `POST` to a read (now 501), hexadecimal and other prefixed IDs such as `0x1f`, the `Grpc-Metadata-*` response headers, and a body whose read failed with the JSON already complete (now 500 with nothing written; 0.29 could still write it). [#3364](https://github.com/juanfont/headscale/issues/3364)
- The v1 OpenAPI document declares `409 Conflict` for user create and rename. The generated Go client `gen/client/v1` decodes it into `JSON409`. A caller that read the default response for a 409 gets `nil` there. [#3364](https://github.com/juanfont/headscale/issues/3364)
- The fix hint for a node whose name cannot form a valid FQDN, in the startup check and the map log, reads `headscale nodes rename --identifier <id> <name>`. The printed `headscale nodes rename <id> <name>` was a usage error. [#3364](https://github.com/juanfont/headscale/issues/3364)
- The v1 API returns `409 Conflict`, not `500`, when a user create or rename asks for a name another user already has. A rename to a taken name always returned `500`. This also holds for a name that only users from an identity provider hold: a create succeeded and a rename returned `500`. [#3757](https://github.com/juanfont/headscale/pull/3757)
- Exit nodes get the subnet routes behind the sources of a rule to `autogroup:internet`, as on Tailscale SaaS. Traffic to a source's own subnet also goes through the exit node. [#3757](https://github.com/juanfont/headscale/pull/3757)
- `/api/v1/auth/approve` approves only an SSH check. It returns `400` for a pending node registration. Approving one finished the login without creating its node, so its client started over. [#3757](https://github.com/juanfont/headscale/pull/3757)
- An approval of a login that another approval already decided is refused. Two approvals can no longer both register one login. [#3757](https://github.com/juanfont/headscale/pull/3757)
- A late or repeated follow-up of a login gets the verdict the login already reached, instead of starting over. A follow-up whose node is gone starts the login over. [#3757](https://github.com/juanfont/headscale/pull/3757)
- The IP allocators never hand out an address in `fd7a:115c:a1e0:b1a::/64`. The Tailscale client reads that range as IPv4 routes mapped into IPv6 (4via6). The random strategy could draw one, and a node with that address did not work. [#3757](https://github.com/juanfont/headscale/pull/3757)
- Peers drop a node's old disco key when the node reports none. The cleared key went out as a patch, which the wire leaves out, so peers kept the old key. [#3757](https://github.com/juanfont/headscale/pull/3757)

- The configuration search path now also includes `$XDG_CONFIG_HOME/headscale` and `$XDG_CONFIG_DIRS`, and the files `config.json` and `config.hujson`. [#3674](https://github.com/juanfont/headscale/pull/3674)
- `HEADSCALE_DEBUG_DUMP_CONFIG` prints the configuration as YAML, with secrets redacted. [#3677](https://github.com/juanfont/headscale/pull/3677)
- Embedding Headscale is now easier: start from `config.Default()`, set `server_url` and pass it to `hscontrol.NewHeadscale`, which validates it. [#3677](https://github.com/juanfont/headscale/pull/3677) [#3683](https://github.com/juanfont/headscale/pull/3683)
- `headscale generate nixos-options` is new. Each release attaches its output as `headscale-nixos-options.nix`. [#3680](https://github.com/juanfont/headscale/pull/3680)
- The NixOS unit no longer has `CAP_CHOWN`: its capability set is empty unless `listen_addr` needs `CAP_NET_BIND_SERVICE`. [#3682](https://github.com/juanfont/headscale/pull/3682)
- `dns.override_local_dns: true` no longer requires `dns.nameservers.global`. Headscale used to refuse to start without one. Clients now keep their own DNS servers until a global nameserver is set. [#3683](https://github.com/juanfont/headscale/pull/3683)
- A DERP map refresh that retries an unreachable source no longer delays node expiry and other scheduled tasks. [#3683](https://github.com/juanfont/headscale/pull/3683)
- The flake's `headscale-docker` image carries CA certificates, so it can fetch HTTPS DERP maps. [#3683](https://github.com/juanfont/headscale/pull/3683)

## 0.29.8 (2026-11-26)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- Peers carry their own capability version, not the version of the node that receives the map. Tailscale v1.106 and newer use it to pick per-peer features such as hybrid WireGuard handshakes. With the wrong version, a v1.106 client could not connect to an older one. [#3724](https://github.com/juanfont/headscale/pull/3724)

## 0.29.7 (2026-10-30)

**Minimum supported Tailscale client version: v1.80.0**

### Security

This is a security release. It fixes findings from Anthropic's oss-scanner project and
the Tailworm report. None are critical, but some can cause denial of service in
Headscale. We recommend that all users upgrade to Headscale 0.29.7 **and** Tailscale
v1.104.4 or newer as soon as possible, especially those using Tailscale SSH.

Tailscale v1.104.4 fixes vulnerabilities in SSH forwarding, SSH session handling and
Serve. These fixes run in `tailscaled` on your nodes; upgrading Headscale alone does
not apply them.

See Tailscale's
[security bulletins](https://tailscale.com/security-bulletins#ts-2026-014) and
[Tailscale SSH: Findings and fixes](https://tailscale.com/blog/tailscale-ssh-findings-fixes).

To disable SSH agent and port forwarding on a node, set
`TS_SSH_DISABLE_FORWARDING=1` in the `tailscaled` service environment and restart
the service. This setting applies to all Tailscale SSH sessions on that node and
is also available in older clients. [#3624](https://github.com/juanfont/headscale/pull/3624)

This release also fixes the issues that [oss-scanner](https://github.com/anthropics/oss-scanner/tree/main/projects/headscale)
reported in Headscale: ANT-2026-MLP8ZR5T, ANT-2026-LYVGXVSW, ANT-2026-AWGRB7O1, ANT-2026-QMCAFJ1Q, ANT-2026-RQS7JAPP, ANT-2026-5B6KE87K, ANT-2026-KFCFFM34, ANT-2026-K903ZEUA, ANT-2026-NM50ZP4N, ANT-2026-ZC18AF82, ANT-2026-NWTIBB02, ANT-2026-MX8FKG4K. [#3603](https://github.com/juanfont/headscale/pull/3603)

### Changes

- Metrics are no longer exposed to unregistered clients through the Noise protocol. They remain available only on the configured metrics listener. An empty `metrics_listen_addr` disables that listener. [#3623](https://github.com/juanfont/headscale/pull/3623)
- The Tailscale dependency is updated to v1.104.4, which bounds how much of an unexpected DERP HTTP response is read. [#3577](https://github.com/juanfont/headscale/pull/3577)
- At capacity, pending registrations and OIDC logins awaiting approval are kept instead of evicted. New requests get a retry response, and registered nodes keep capacity for SSH checks. [#3586](https://github.com/juanfont/headscale/pull/3586)
- Stored pending registration data is capped at 64 KiB, keeping tags and expiry. Oversized interactive registrations are rejected. [#3586](https://github.com/juanfont/headscale/pull/3586)
- headscale checks the OIDC login type before storing anything, accepts each OIDC callback only once, and frees an SSH check's slot once the client has read its result. [#3586](https://github.com/juanfont/headscale/pull/3586)
- headscale no longer serves a route that is a single address inside the node IP ranges, such as `100.64.0.11/32` or `::ffff:100.64.0.11/128`, because it names a node, not a subnet. The route stays approved and listed, and wider routes are still served. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Re-registering an expired tagged node requires a valid pre-auth key. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Another user's key or login on a tagged machine now creates a new device for that user instead of re-authenticating the tagged node. [#3603](https://github.com/juanfont/headscale/pull/3603)
- One node with a stored key expiry outside the years 0 to 9999 in UTC no longer fails the map of every node that can see it. It is now left out of its peers' maps, and the startup check names it with the fix command. [#3603](https://github.com/juanfont/headscale/pull/3603)
- headscale refuses a key expiry outside the years 0 to 9999 in UTC on registration, on the OIDC token-expiry path and in `headscale nodes expire` / `POST /api/v1/node/{node_id}/expire` (HTTP 400). The latest accepted expiry no longer fails node listings on PostgreSQL in a zone east of UTC. [#3603](https://github.com/juanfont/headscale/pull/3603)
- headscale keeps the first 256 endpoints and 4096 announced routes from client reports. Oversized hostnames, requested tags or other metadata return a registration error or HTTP 413 on map updates. Zoned IPv6 endpoints are refused. [#3603](https://github.com/juanfont/headscale/pull/3603)
- At startup, headscale trims stored hostnames, endpoints and routes to the client-report limits and removes zoned endpoints. Hostinfo exceeding its size or tag limit is dropped until the next valid report. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Pending interactive registrations and follow-up waits keep only the hostname, OS and requested tags. Other device details arrive with the first map request. Reauthentication preserves routes, services and endpoints. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Web reauthentication no longer drops the discovery key, which left peers unable to reach the device. [#3603](https://github.com/juanfont/headscale/pull/3603)
- A stalled request body, or a Noise tunnel with no open request, is closed after 30 seconds. [#3603](https://github.com/juanfont/headscale/pull/3603)
- A registration follow-up from a machine other than the one that started the registration is refused before it waits. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Only the newest follow-up waits on a pending registration or SSH check. Older ones are answered at once. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Registration locks no longer stay in memory after the registration ends. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Concurrent deletes of one node no longer free its addresses and announce its removal more than once. [#3603](https://github.com/juanfont/headscale/pull/3603)
- OIDC verifies an email against the document supplying it. An `email_verified` flag without an address no longer verifies another document's email. [#3603](https://github.com/juanfont/headscale/pull/3603)
- Release builds no longer report their version with a `+dirty` suffix. [#3584](https://github.com/juanfont/headscale/pull/3584)
- SSH policy `acceptEnv` used to have no effect. Now allowed environment variables reach SSH sessions. Upgrade SSH destination nodes to Tailscale v1.104.4 or newer before using `acceptEnv`, because older clients can disclose forwarded values. [#3569](https://github.com/juanfont/headscale/pull/3569)

## 0.29.6 (2026-10-24)

**Minimum supported Tailscale client version: v1.80.0**

### Security

- headscale is built with Go 1.27.3, which rejects certificate chains containing the compromised eMudhra intermediate keys (CVE-2026-111943). [Go #82345](https://github.com/golang/go/issues/82345)
- The normal and debug container bases are updated and pinned to images whose CA bundles no longer include `emSign ECC Root CA - G3`. [#3579](https://github.com/juanfont/headscale/issues/3579)
- `golang.org/x/net` is updated to v0.60.0, `golang.org/x/text` to v0.42.0 and gRPC to v1.83.2, addressing HTTP/2 denial-of-service and text-processing vulnerabilities ([x/net](https://pkg.go.dev/vuln/GO-2026-6617), [x/text](https://pkg.go.dev/vuln/GO-2026-6629), [gRPC](https://pkg.go.dev/vuln/GO-2026-6348)).

Custom builds must be rebuilt with Go 1.27.3 or newer to receive the certificate-chain protection.

### Changes

- Peer-map construction is faster on large tailnets: headscale finds each node's matching rules once, instead of checking every pair of nodes against every rule. [#3556](https://github.com/juanfont/headscale/pull/3556)
- headscale builds the peer map once per policy write instead of twice, and skips the rebuild when reloading an unchanged policy. [#3557](https://github.com/juanfont/headscale/pull/3557)
- Broadcasting map updates does less work by avoiding repeated recipient filtering. [#3568](https://github.com/juanfont/headscale/pull/3568)
- `INTERNAL_ERROR` stream errors no longer occur when a node logs out or is deleted, or when Headscale shuts down. Writes already in progress have a short grace period to finish, while clients that stop reading are still disconnected. [#3575](https://github.com/juanfont/headscale/pull/3575)
- Database-open errors are returned instead of risking a panic or returning a partially initialized database handle. [#3496](https://github.com/juanfont/headscale/pull/3496)
- The Tailscale dependency is updated to v1.102.0 for Go 1.27 JSON compatibility in SSH check responses.

## 0.29.5 (2026-10-13)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- An unrelated ACL or grant rule that matches the viewer no longer undoes `via` exit-node steering. [#3495](https://github.com/juanfont/headscale/pull/3495)
- `via` grants offer exit nodes and subnet routes to a group that names an unknown user. [#3516](https://github.com/juanfont/headscale/pull/3516)
- SSH `check` periods and app grants no longer drop a group that names an unknown user. [#3516](https://github.com/juanfont/headscale/pull/3516)
- Policy `tests` and `sshTests` no longer fail for a group that names an unknown user. [#3516](https://github.com/juanfont/headscale/pull/3516)
- An unknown user in `nodeAttrs` no longer rejects the policy. [#3516](https://github.com/juanfont/headscale/pull/3516)
- When the policy has no `via` grants, grants are no longer fully resolved as if they had `via`, which slowed map generation on large tailnets. [#3538](https://github.com/juanfont/headscale/pull/3538)
- `via` route resolution no longer has a data race when the policy has both `via` grants and ACLs. [#3515](https://github.com/juanfont/headscale/pull/3515)
- Packet filters under `autogroup:self` update after a user is added or renamed. [#3501](https://github.com/juanfont/headscale/pull/3501)
- A rejected policy no longer leaves its packet filter active. [#3501](https://github.com/juanfont/headscale/pull/3501)
- An exit node or subnet router sees its own approved routes without reconnecting. Before, `tailscale status` did not show it offering an exit node. [#3518](https://github.com/juanfont/headscale/pull/3518)
- Deleted nodes, and peers hidden by a policy change, no longer stay listed in the Tailscale Android app. Removed peers are now sent as their own incremental map update. [#3492](https://github.com/juanfont/headscale/pull/3492) [#3527](https://github.com/juanfont/headscale/pull/3527)
- Policy changes no longer resend DNS configuration to every node, sparing clients a full netmap rebuild. A node gets its DNS configuration when its own NextDNS nodeAttrs, tags or hostname change. This also fixes NextDNS device metadata going stale after a hostname change. [#3492](https://github.com/juanfont/headscale/pull/3492)
- SSH access no longer survives the removal of its policy rules. Clients used to keep their last SSH rules, and a pending SSH check could still be approved. [#3517](https://github.com/juanfont/headscale/pull/3517)
- SSH check periods come from the rule for the login user instead of the first check rule for a node pair. [#3517](https://github.com/juanfont/headscale/pull/3517)
- Policy changes resend a node's SSH policy only when it changed, sparing clients a full netmap rebuild. [#3517](https://github.com/juanfont/headscale/pull/3517)
- SSH check no longer accepts a repeated follow-up for an already-decided session, even after a rejection. [#3526](https://github.com/juanfont/headscale/pull/3526)
- An ephemeral node is no longer deleted while online when it reconnects while its previous session is being marked offline. [#3539](https://github.com/juanfont/headscale/pull/3539)
- Peers no longer drop traffic from a node that re-authenticates after its key expired. [#3541](https://github.com/juanfont/headscale/pull/3541)
- Clients no longer upload logs to Tailscale Inc. while `logtail.enabled` is `false`. Clients also granted the `data-plane-audit-logs` node attribute now go down until `tailscale up`. [#3522](https://github.com/juanfont/headscale/pull/3522)
- A node ping is no longer lost when a full map update is queued at the same time. [#3523](https://github.com/juanfont/headscale/pull/3523)

## 0.29.4 (2026-09-23)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- A node is no longer listed among its own peers in an incremental map update, which crashes the Tailscale Android app on the device list. [#3459](https://github.com/juanfont/headscale/pull/3459)
- Deleting a node closes its long poll, so the client asks for a new login instead of staying connected. [#3449](https://github.com/juanfont/headscale/pull/3449)
- Interactive OIDC login works when the confirmation page is reloaded by an ad blocker, back navigation, or pull-to-refresh. The confirmation page now has its own URL, keeping single-use authorization codes out of reloads. [#3448](https://github.com/juanfont/headscale/pull/3448)
- The OIDC callback is hardened. State and nonce cookies take their Secure flag from `server_url`, so they survive a TLS-terminating proxy. A callback state is single-use. An invalid `oidc.issuer` or a missing `oidc.client_id`/`oidc.client_secret` now fails at startup. [#3334](https://github.com/juanfont/headscale/pull/3334)
- HTTP metrics no longer count only `OPTIONS` requests. `http_requests_total` and `http_request_duration_seconds` now cover regular traffic. [#3414](https://github.com/juanfont/headscale/pull/3414)
- The extra-records filewatcher no longer hangs on shutdown after the watched file is deleted, or leaks the watcher when setup fails. [#3437](https://github.com/juanfont/headscale/pull/3437)
- DNS extra record names are lowercased so mixed-case records resolve. [#3366](https://github.com/juanfont/headscale/pull/3366)
- `headscale users rename` sends the matched user's identifier instead of the raw `--identifier` flag value, so renaming by name works again. [#3442](https://github.com/juanfont/headscale/pull/3442)
- tailsql shuts down with headscale instead of leaving the process hanging on graceful shutdown. [#3400](https://github.com/juanfont/headscale/pull/3400)
- The tvOS setup instructions say to install the VPN configuration before setting the coordination server URL. [#3431](https://github.com/juanfont/headscale/pull/3431)
- Map requests that only bump LastSeen, endpoints or DERP region no longer resend the whole node to every peer, and health probes that change nothing no longer write. New metrics: `headscale_mapper_changes_dropped_total` and `headscale_ha_health_updates_total`. [#3417](https://github.com/juanfont/headscale/issues/3417) [#3450](https://github.com/juanfont/headscale/pull/3450)
- The peer map is keyed by node ID and reused for writes that cannot change peer visibility, so a routine map request no longer rebuilds it. New metric: `headscale_nodestore_snapshot_builds_total`. [#3417](https://github.com/juanfont/headscale/issues/3417) [#3450](https://github.com/juanfont/headscale/pull/3450)
- An expired node no longer stays online forever. Expiring it used to update the key deadline without ending its map session. [#3472](https://github.com/juanfont/headscale/pull/3472)
- ACME renewal no longer stops permanently after a `badNonce` reply. The error logging middleware used to drain the response body the acme client needs to detect it. [#3461](https://github.com/juanfont/headscale/pull/3461)
- `#`-prefixed metadata fields are accepted outside `acls`, so policy editors can store metadata in grants, SSH rules and `nodeAttrs`. [#3481](https://github.com/juanfont/headscale/pull/3481)
- Exit nodes are offered to recent macOS and iOS clients, which read the `suggest-exit-node` peer attribute rather than the advertised `0.0.0.0/0` routes. [#3487](https://github.com/juanfont/headscale/pull/3487)
- An exit node is offered to viewers whose only matching rule is a `via` grant. Peer visibility now comes from the peer map alone. [#3409](https://github.com/juanfont/headscale/pull/3409)
- Nodes no longer go offline on restart when they send a pre-auth key other than the one they joined with. [#3681](https://github.com/juanfont/headscale/pull/3681)

## 0.29.3 (2026-07-29)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- A tagged node no longer gets stuck expired after `tailscale logout`, unable to re-authenticate. [#3394](https://github.com/juanfont/headscale/pull/3394)
- Re-registering a tagged node with a different pre-auth key now applies the new key's tags instead of silently keeping the old ones. [#3394](https://github.com/juanfont/headscale/pull/3394)
- Re-authenticating an already-tagged node with `--advertise-tags` is accepted when the authenticating user owns the tags. [#3394](https://github.com/juanfont/headscale/pull/3394)
- Ephemeral nodes no longer linger as disconnected after reconnect churn. [#3383](https://github.com/juanfont/headscale/pull/3383)
- Node registration no longer falsely returns `401 registration timed out` when auth completes as the request context expires. [#3392](https://github.com/juanfont/headscale/pull/3392)
- The followup registration poll checks the machine key, so a leaked auth ID cannot return the registering user's identity. [#3393](https://github.com/juanfont/headscale/pull/3393)
- `/key` requests below the supported capability version floor are rejected, matching `/ts2021`. [#3391](https://github.com/juanfont/headscale/pull/3391)

## 0.29.2 (2026-07-01)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- Map generation no longer serializes on the policy lock, so a mass reconnect on `autogroup:self`, via or relay policies no longer stalls clients into `unexpected EOF` retry loops. [#3358](https://github.com/juanfont/headscale/pull/3358)
- `/ts2021` no longer rejects the WebSocket `GET` upgrade with 405, which prevented Tailscale JS/WASM control clients from connecting. [#3359](https://github.com/juanfont/headscale/pull/3359)
- Nodes with an invalid FQDN (empty or too long) are handled gracefully instead of failing map delivery. Offending names are logged at startup with the fix command. [#3349](https://github.com/juanfont/headscale/pull/3349)

## 0.29.1 (2026-06-18)

**Minimum supported Tailscale client version: v1.80.0**

### Changes

- Nodes with `tags='null'` no longer lose their assigned user on upgrade. [#3325](https://github.com/juanfont/headscale/pull/3325)

## 0.29.0 (2026-06-17)

**Minimum supported Tailscale client version: v1.80.0**

### Tailscale ACL compatibility improvements

Extensive test cases were systematically generated using Tailscale clients and the official SaaS
to understand how the packet filter should be generated. We discovered a few differences, but
overall our implementation was very close.
[#3036](https://github.com/juanfont/headscale/pull/3036)

### SSH check action

SSH rules with `"action": "check"` are now supported. When a client initiates a SSH connection to a node
with a `check` action policy, the user is prompted to authenticate via OIDC or CLI approval before access
is granted. OIDC approval requires the authenticated user to own the source node; tagged source nodes
cannot use SSH check-mode.

A new `headscale auth` CLI command group supports the approval flow:

- `headscale auth approve --auth-id <id>` approves a pending authentication request (SSH check or web auth).
- `headscale auth reject --auth-id <id>` rejects a pending authentication request.
- `headscale auth register --auth-id <id> --user <user>` registers a node (replaces deprecated `headscale nodes register`).

[#1850](https://github.com/juanfont/headscale/pull/1850)
[#3180](https://github.com/juanfont/headscale/pull/3180)

### Policy tests (beta)

Headscale now evaluates the `tests` block in a policy file. Tests assert reachability between
named sources and destinations and cover the whole policy — both `acls` and `grants` rules
contribute. They run on user-initiated writes via `headscale policy set`, on SIGHUP reload
(`systemctl reload headscale` / `kill -HUP $(pidof headscale)`), and on `headscale policy check`.
A failing test rejects the write before it is applied, with the same error message Tailscale SaaS
would return for the same policy.

At boot a stored policy whose tests no longer pass — for example because a referenced user was
deleted while the server was offline — logs a warning and the server keeps running. Fix the
policy and reload.

This feature is **beta** while behavioural coverage against Tailscale SaaS broadens.

[#3229](https://github.com/juanfont/headscale/pull/3229)

### SSH policy tests (beta)

Headscale now evaluates the `sshTests` block in a policy file. Each entry names a source, one or
more destination hosts, and three optional user lists: `accept` asserts the listed login users
reach every destination via an accept- or check-action SSH rule, `deny` asserts none of them
reach any destination, and `check` requires reachability specifically through a check-action
rule. Tests run on `headscale policy set`, on SIGHUP reload (`systemctl reload headscale` /
`kill -HUP $(pidof headscale)`), and on `headscale policy check`. A failing test rejects the
write before it is applied, with the same error message Tailscale SaaS would return for the same
policy.

At boot a stored policy whose sshTests no longer pass — for example because a referenced user was
deleted while the server was offline — logs a warning and the server keeps running. Fix the
policy and reload.

This feature is **beta** while behavioural coverage against Tailscale SaaS broadens.

[#3263](https://github.com/juanfont/headscale/pull/3263)

### SSH rule validation

SSH rule parsing now trims surrounding whitespace on `action`, `users`, `src`, and `dst`,
rejects empty or wildcard entries in `users`, rejects empty `acceptEnv`, and rejects negative
`checkPeriod`. `hosts:` aliases are rejected as SSH destinations, non-ASCII tag names are
rejected at parse time, and the wording for group-nesting cycles matches Tailscale SaaS.
[#3263](https://github.com/juanfont/headscale/pull/3263)

### Grants

We now support [Tailscale grants](https://tailscale.com/docs/features/access-control/grants)
alongside ACLs. Grants extend what you can express in a policy beyond packet filtering: the `app`
field controls application-level features like Taildrive file sharing and peer relay, and the `via`
field steers traffic through specific tagged subnet routers or exit nodes. The `ip` field works like
an ACL rule. Grants can be mixed with ACLs in the same policy file.
[#2180](https://github.com/juanfont/headscale/pull/2180)

As part of this, we added `autogroup:danger-all`. It resolves to `0.0.0.0/0` and `::/0`, all IP
addresses, including those outside the tailnet. This replaces the old behaviour where `*` matched
all IPs (see BREAKING below). The name is intentional: accepting traffic from the entire
internet is a security-sensitive choice. `autogroup:danger-all` can only be used as a source.

### Node attributes (`nodeAttrs`)

ACL policies now accept a `nodeAttrs` block. Each entry hands a list of
Tailscale node capabilities to every node matching `target`. The accepted
target forms are the same as `acls.src` and `grants.src`: users, groups,
tags, hosts, prefixes, `autogroup:member`, `autogroup:tagged`, and `*`.

```jsonc
{
  "randomizeClientPort": true,
  "nodeAttrs": [
    { "target": ["autogroup:tagged"], "attr": ["disable-captive-portal-detection"] },
    { "target": ["alice@example.com"], "attr": ["nextdns:abc123"] },
  ],
}
```

Frequently requested capabilities this unlocks include `magicdns-aaaa`,
`disable-relay-server`, `disable-captive-portal-detection`,
`nextdns:<profile>` / `nextdns:no-device-info`, `randomize-client-port`,
and the Taildrive `drive:share` / `drive:access` pair. The set is not
limited to these. Any string-only cap an operator places in policy
reaches clients unchanged.

`randomizeClientPort` also lands as a top-level policy field that toggles
the default for every node, replacing the old server-config knob.

A new `auto_update.enabled` config option controls the tailnet-wide
default for client auto-update. When true, every node's CapMap carries
`default-auto-update: [true]` so fresh clients pick up the default
unless they make a local opt-in / opt-out choice.

Policies that use the `funnel` cap, `ipPool` blocks, or
`autogroup:admin` / `autogroup:owner` targets are rejected at load —
those features depend on machinery headscale does not yet ship.

[#3251](https://github.com/juanfont/headscale/pull/3251)

### Taildrive

Taildrive ([file-sync between
nodes](https://tailscale.com/docs/features/taildrive)) is now
configurable through policy. Grant `drive:share` to the node that
hosts files and `drive:access` to nodes that read or write them; pair
with a `tailscale.com/cap/drive` grant to set the per-share access
mode:

```jsonc
{
  "nodeAttrs": [
    { "target": ["tag:fileserver"], "attr": ["drive:share"] },
    { "target": ["autogroup:member"], "attr": ["drive:access"] },
  ],
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["tag:fileserver"],
      "app": {
        "tailscale.com/cap/drive": [{ "shares": ["*"], "access": "rw" }],
      },
    },
  ],
}
```

A wildcard `nodeAttrs` (`"target": ["*"]`) hands the caps to every
node when fine-grained control is not needed.

### Hostname sanitisation

Hostnames are now sanitised using Tailscale's `magicdns` sanitisation rules, matching Tailscale SaaS behavior. This means that hostnames with non-ASCII characters, special characters, or reserved DNS label characters are now transformed into valid DNS labels for MagicDNS. This improves our previously too strict sanitisation that rejected hostnames based on our guesswork and not based on the Tailscale upstream behaviour.

Examples that previously regressed and now work:

| Input                | Raw (Hostname)       | DNS label (GivenName) |
| -------------------- | -------------------- | --------------------- |
| `Joe's Mac mini`     | `Joe's Mac mini`     | `joes-mac-mini`       |
| `Yuri's MacBook Pro` | `Yuri's MacBook Pro` | `yuris-macbook-pro`   |
| `Test@Host`          | `Test@Host`          | `test-host`           |
| `mail.server`        | `mail.server`        | `mail-server`         |
| `My-PC!`             | `My-PC!`             | `my-pc`               |
| `我的电脑`           | `我的电脑`           | `node`                |

[#3202](https://github.com/juanfont/headscale/pull/3202)

### HA subnet router health probing

Headscale now actively probes HA subnet routers to detect nodes that are connected but not
forwarding traffic. The control plane periodically pings HA subnet routers via the Noise
control channel and fails over to a healthy standby if the primary stops responding. This is
enabled by default (`node.routes.ha.probe_interval: 10s`, `probe_timeout: 5s`) and only
active when HA routes exist (2+ nodes advertising the same prefix). Set `probe_interval` to
`0` to disable. This complements the existing disconnect-based failover, catching "zombie
connected" routers that maintain their control session but cannot route packets.
[#3194](https://github.com/juanfont/headscale/pull/3194)

### BREAKING

#### Hostname handling

- The `GivenName` collision policy changed from an 8-char random hash suffix (`laptop-abc12xyz`) to a monotonic numeric suffix (`laptop`, `laptop-1`, `laptop-2`, …), matching Tailscale SaaS. Empty / all-non-ASCII hostnames now fall back to the literal `node` instead of `invalid-<rand>`. MagicDNS names change on upgrade for any node whose previous label was a random-suffix form; the raw `Hostname` column is unchanged. [#3202](https://github.com/juanfont/headscale/pull/3202)

#### ACL Policy

- Wildcard (`*`) in ACL sources now resolves to Tailscale's CGNAT range (`100.64.0.0/10`) and ULA range (`fd7a:115c:a1e0::/48`) instead of all IPs (`0.0.0.0/0` and `::/0`). [#3036](https://github.com/juanfont/headscale/pull/3036)
  - This better matches Tailscale's security model where `*` means "any node in the tailnet" rather than "any IP address".
  - Policies that need to match all IP addresses including non-Tailscale IPs should use `autogroup:danger-all` as a source. [#2180](https://github.com/juanfont/headscale/pull/2180)
  - `autogroup:danger-all` can only be used as a source. It cannot be used as a destination.
- `autogroup:self` source restrictions are validated, matching Tailscale behavior. Tags, hosts, and IPs are rejected as sources for `autogroup:self` destinations. [#3036](https://github.com/juanfont/headscale/pull/3036)
  - Policies using tags, hosts, or IP addresses as sources for `autogroup:self` destinations will now fail validation.
- The `proto:icmp` protocol name now only includes ICMPv4 (protocol 1), matching Tailscale behavior. [#3036](https://github.com/juanfont/headscale/pull/3036)
  - Previously, `proto:icmp` included both ICMPv4 and ICMPv6.
  - ICMPv6 needs `proto:ipv6-icmp` or protocol number `58` explicitly.

#### Upgrade Path

- Headscale now enforces a strict version upgrade path. [#3083](https://github.com/juanfont/headscale/pull/3083)
  - Skipping minor versions (e.g. 0.27 → 0.29) is blocked. Upgrade one minor version at a time.
  - Downgrading to a previous minor version is blocked.
  - Patch version changes within the same minor are always allowed.

#### Configuration

- The `randomize_client_port` server-config key was removed. The
  toggle now lives in the policy file as a top-level
  `randomizeClientPort` field, matching the Tailscale-hosted schema. [#3251](https://github.com/juanfont/headscale/pull/3251)
  Headscale refuses to start when the old key is set. Move it to the
  policy file referenced by `policy.path`:

  ```jsonc
  {
    "randomizeClientPort": true,
  }
  ```

  If you do not have a policy file yet, create one with that minimal
  content and point `policy.path` at it. The default carries over —
  empty / absent policy means `randomizeClientPort: false`, matching
  the previous behaviour for operators who never set the key. Per-node
  opt-in via `nodeAttrs` is also supported and stacks on top of the
  global default.

#### CLI

- `headscale nodes register` is deprecated in favour of `headscale auth register --auth-id <id> --user <user>`. [#1850](https://github.com/juanfont/headscale/pull/1850)
  - The old command continues to work but will be removed in a future release.

### Changes

#### ACL Policy

- Subnet-to-subnet peer visibility works. Subnet routers now correctly become peers when ACL rules reference only subnet CIDRs as sources, without requiring node IP rules. [#3175](https://github.com/juanfont/headscale/pull/3175)
- Filter rule reduction uses only approved subnet routes instead of all advertised routes, matching Tailscale SaaS behavior. [#3175](https://github.com/juanfont/headscale/pull/3175)
- Default filter rules include ICMP and IPv6-ICMP protocols when no protocol is specified. [#3036](https://github.com/juanfont/headscale/pull/3036)
- autogroup:self handling for tagged nodes is fixed. Tagged nodes no longer incorrectly receive autogroup:self filter rules. [#3036](https://github.com/juanfont/headscale/pull/3036)
- autogroup:self destination IPs use CIDR format, matching Tailscale behavior. [#3036](https://github.com/juanfont/headscale/pull/3036)
- Filter rules with identical SrcIPs and IPProto are merged, matching Tailscale behavior. Multiple ACL rules with the same source now produce a single FilterRule with combined DstPorts. [#3036](https://github.com/juanfont/headscale/pull/3036)
- Exit nodes no longer incorrectly receive filter rules for destinations that only overlap via exit routes. [#3169](https://github.com/juanfont/headscale/issues/3169) [#3175](https://github.com/juanfont/headscale/pull/3175)
- Address-based aliases (hosts, raw IPs) no longer incorrectly expand to include the matching node's other address family. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Identity-based aliases (tags, users, groups) no longer resolve to IPv4 only. They now include both IPv4 and IPv6, matching Tailscale behavior. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Wildcard (`*`) source in ACLs now uses actually-approved subnet routes instead of autoApprover policy prefixes. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Non-wildcard source IPs are no longer dropped when combined with wildcard `*` in the same ACL rule. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Exit node approval triggers filter rule recalculation for peers. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Policy validation error messages now include field context (e.g., `src=`, `dst=`) and are more descriptive. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Policies whose `user@` tokens match multiple DB users are rejected. Rename the duplicate via `headscale users rename` to load. [#3160](https://github.com/juanfont/headscale/issues/3160)
- The policy `tests` block is evaluated on user-initiated writes across both `acls` and `grants`. Policies whose tests fail are rejected (beta). [#1803](https://github.com/juanfont/headscale/issues/1803)

#### Grants

- Policy grants with `ip`, `app`, and `via` fields are supported. [#2180](https://github.com/juanfont/headscale/pull/2180)
- `autogroup:danger-all` is a source-only autogroup resolving to all IP addresses. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Taildrive (`cap/drive`) and peer relay (`cap/relay`) have capability grants with automatic companion capabilities. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Via routes are steered per viewer. Grants with `via` tags control which subnet router or exit node handles traffic for each group of viewers. [#2180](https://github.com/juanfont/headscale/pull/2180)
- Taildrive node attributes are enabled on all nodes. Actual access is controlled by `cap/drive` grants. [#2180](https://github.com/juanfont/headscale/pull/2180)

#### SSH Policy

- The SSH rule `users` field supports `localpart:*@<domain>`, mapping each matching user's email local-part as their OS username. [#3091](https://github.com/juanfont/headscale/pull/3091)
- SSH supports the `check` action with OIDC and CLI-based approval flows. [#1850](https://github.com/juanfont/headscale/pull/1850)

#### CLI

- `headscale auth register`, `headscale auth approve`, and `headscale auth reject` are new CLI commands. [#1850](https://github.com/juanfont/headscale/pull/1850)
- `headscale nodes register --key` is deprecated in favour of `headscale auth register --auth-id`. [#1850](https://github.com/juanfont/headscale/pull/1850)
- `headscale policy check --bypass-grpc-and-access-database-directly` validates `user@` tokens against the live user database. [#3160](https://github.com/juanfont/headscale/issues/3160)
- The deprecated `--namespace` flag is removed from `nodes list`, `nodes register`, and `debug create-node` commands (use `--user` instead). [#3093](https://github.com/juanfont/headscale/pull/3093)
- The deprecated `namespace`/`ns` command aliases for `users` and `machine`/`machines` aliases for `nodes` are removed. [#3093](https://github.com/juanfont/headscale/pull/3093)
- `DestroyUser` deletes only the target user's keys instead of all pre-auth keys in the database. [#3155](https://github.com/juanfont/headscale/pull/3155)
- `headscale policy check` evaluates the `tests` block when invoked with `--bypass-grpc-and-access-database-directly`. Without the flag it warns instead of running the tests against empty data. [#1803](https://github.com/juanfont/headscale/issues/1803)

#### API

- The API has `auth` related routes. The `auth/register` endpoint now expects data as JSON. [#1850](https://github.com/juanfont/headscale/pull/1850)
- gRPC reflection is removed from the remote (TCP) server. [#3180](https://github.com/juanfont/headscale/pull/3180)

#### OIDC

- A confirmation page before completing node registration shows the device hostname and machine key fingerprint. [#3180](https://github.com/juanfont/headscale/pull/3180)
- Auth templates are generalised into reusable `AuthSuccess` and `AuthWeb` components. [#1850](https://github.com/juanfont/headscale/pull/1850)
- The auth pipeline is unified with an `AuthVerdict` type, supporting registration, reauthentication, and SSH checks. [#1850](https://github.com/juanfont/headscale/pull/1850)

#### Configuration

- The `node.expiry` configuration option sets a default node key expiry for nodes registered via auth key. [#3122](https://github.com/juanfont/headscale/pull/3122)
  - Tagged nodes (registered with tagged pre-auth keys) are exempt from default expiry.
  - `oidc.expiry` has been removed. Use `node.expiry` instead (applies to all registration methods including OIDC).
  - `ephemeral_node_inactivity_timeout` is deprecated in favour of `node.ephemeral.inactivity_timeout`.
- `trusted_proxies` gates `True-Client-IP` / `X-Real-IP` / `X-Forwarded-For` (previously honoured from any client). [#3268](https://github.com/juanfont/headscale/pull/3268)

#### Debug

- A node connectivity ping page verifies control-plane reachability. [#3183](https://github.com/juanfont/headscale/pull/3183)
- `/debug/config` JSON output omits secret fields (`Pass`, `ClientSecret`, `APIKey`). [#3180](https://github.com/juanfont/headscale/pull/3180)
- `statsviz` is routed through `tsweb.Protected`. [#3180](https://github.com/juanfont/headscale/pull/3180)

#### Other

- Old migrations for the debian package are removed. [#3185](https://github.com/juanfont/headscale/pull/3185)
- The debian package installs `config-example.yaml` as example. [#3186](https://github.com/juanfont/headscale/pull/3186)
- User-owned re-registration with zero client expiry and no default stores `NULL` in the database instead of `0001-01-01 00:00:00`. [#3199](https://github.com/juanfont/headscale/pull/3199)
- A `tailscaled` restart on a node with no expiry no longer resets `NULL` to `0001-01-01 00:00:00` in the database. This affected both tagged and untagged nodes. [#3197](https://github.com/juanfont/headscale/pull/3197)
- `nodes.expiry` rows persisted by older versions as `0001-01-01 00:00:00` are backfilled to `NULL`, so nodes upgraded from <0.28 stop reporting as expired. [#3284](https://github.com/juanfont/headscale/issues/3284)
- The reverse proxy documentation covers the `trusted_proxies` configuration option. [#3292](https://github.com/juanfont/headscale/pull/3292)

## 0.28.0 (2026-02-04)

**Minimum supported Tailscale client version: v1.74.0**

### Tags as identity

Tags now follow the Tailscale model, where tags and user ownership are mutually exclusive. A device is either
user-owned (authenticated via web/OIDC) or tagged (authenticated via tagged PreAuthKeys). Tagged devices take their identity from
tags rather than users, which suits servers and infrastructure. Applying a tag to a device removes user-based
ownership. See the [Tailscale tags documentation](https://tailscale.com/docs/features/tags) for details on how tags work.

User-owned nodes can now request tags during registration using `--advertise-tags`. Tags are validated against the `tagOwners` policy
and applied at registration time. After registration, tags can be managed via the CLI or API. Tagged nodes can return to user-owned
by re-authenticating with `tailscale up --advertise-tags= --force-reauth`.

A one-time migration validates and migrates any `RequestTags` (stored in hostinfo) to the tags column. Tags are validated against
your policy's `tagOwners` rules during migration. [#3011](https://github.com/juanfont/headscale/pull/3011)

### Smarter map updates

The map update system has been rewritten to send smaller, partial updates instead of full network maps whenever possible. This reduces bandwidth usage and improves performance, especially for large networks. The system now properly tracks peer
changes and can send removal notifications when nodes are removed due to policy changes.
[#2856](https://github.com/juanfont/headscale/pull/2856) [#2961](https://github.com/juanfont/headscale/pull/2961)

### Pre-authentication key security improvements

Pre-authentication keys now use bcrypt hashing for improved security. Keys
are stored as a prefix and bcrypt hash instead of plaintext. The full key is displayed only once, at creation time. Listing keys
shows only the prefix (e.g., `hskey-auth-{prefix}-***`). All new keys use the format `hskey-auth-{prefix}-{secret}`. Legacy plaintext keys in the format `{secret}` continue to work for backwards compatibility. [#2853](https://github.com/juanfont/headscale/pull/2853)

### Web registration templates redesign

The OIDC callback and device registration web pages now use the Material for MkDocs design system from the official
documentation. The templates use consistent typography, spacing, and colours across all registration flows.

### Database migration support removed for pre-0.25.0 databases

Headscale no longer supports direct upgrades from databases created before version 0.25.0. Users on older versions must upgrade
sequentially through each stable release, selecting the latest patch version available for each minor release.

### BREAKING

- **API**: The Node message in the gRPC/REST API is simplified. A single `Tags` field with the node's applied tags replaces the `ForcedTags`, `InvalidTags`, and `ValidTags` fields. [#2993](https://github.com/juanfont/headscale/pull/2993)
  - API clients should use the `Tags` field instead of `ValidTags`.
  - The `headscale nodes list` CLI command always shows a Tags column. The `--tags` flag is removed.
- **PreAuthKey CLI**: Commands use ID-based operations instead of user+key combinations. [#2992](https://github.com/juanfont/headscale/pull/2992)
  - `headscale preauthkeys create` no longer requires the `--user` flag. It stays optional, for tracking creation.
  - `headscale preauthkeys list` lists all keys. It no longer filters by user.
  - `headscale preauthkeys expire --id <ID>` replaces `--user <USER> <KEY>`.
  - `headscale preauthkeys delete --id <ID>` replaces `--user <USER> <KEY>`.

  **Before:**

  ```bash
  headscale preauthkeys create --user 1 --reusable --tags tag:server
  headscale preauthkeys list --user 1
  headscale preauthkeys expire --user 1 <KEY>
  headscale preauthkeys delete --user 1 <KEY>
  ```

  **After:**

  ```bash
  headscale preauthkeys create --reusable --tags tag:server
  headscale preauthkeys list
  headscale preauthkeys expire --id 123
  headscale preauthkeys delete --id 123
  ```

- **Tags**: The gRPC `SetTags` endpoint can convert user-owned nodes to tagged nodes by setting tags. [#2885](https://github.com/juanfont/headscale/pull/2885)
- **Tags**: Tags are resolved only from the node's stored Tags field. [#2931](https://github.com/juanfont/headscale/pull/2931)
  - `--advertise-tags` is processed during registration, not on every policy evaluation.
  - Devices tagged by a PreAuthKey ignore `--advertise-tags` from clients.
  - User-owned nodes can use `--advertise-tags` if the `tagOwners` policy authorizes them.
  - After registration, tags can be managed via the CLI (`headscale nodes tag`) or the SetTags API.
- Migrations for pre-0.25.0 databases are removed. [#2883](https://github.com/juanfont/headscale/pull/2883)
  - If you run a version older than 0.25.0, upgrade to 0.25.1 first, then to this release.
  - See the [upgrade path documentation](https://headscale.net/stable/about/faq/#what-is-the-recommended-update-path-can-i-skip-multiple-versions-while-updating) for detailed guidance.
  - In version 0.29, all migrations before 0.28.0 will also be removed.
- Nodes can no longer move between users. [#2922](https://github.com/juanfont/headscale/pull/2922)
  - The `headscale nodes move` CLI command is removed.
  - The `MoveNode` API endpoint is removed.
  - Nodes are permanently tied to their user or tag at registration time.
- The `oidc.email_verified_required` config option controls whether OIDC requires a verified email. [#2860](https://github.com/juanfont/headscale/pull/2860)
  - When `true` (default), only verified emails can authenticate via OIDC in conjunction with `oidc.allowed_domains` or
    `oidc.allowed_users`. Previous versions allowed authentication with an unverified email but did not store the email
    address in the user profile. Authentication now rejects this with an `unverified email` error.
  - When `false`, OIDC authentication allows unverified emails and stores the email address in the user
    profile regardless of its verification state.
- **SSH Policy**: Wildcard (`*`) is no longer supported as an SSH destination. [#3009](https://github.com/juanfont/headscale/issues/3009)
  - Use `autogroup:member` for user-owned devices.
  - Use `autogroup:tagged` for tagged devices.
  - Use specific tags (e.g., `tag:server`) for targeted access.

  **Before:**

  ```json
  { "action": "accept", "src": ["group:admins"], "dst": ["*"], "users": ["root"] }
  ```

  **After:**

  ```json
  { "action": "accept", "src": ["group:admins"], "dst": ["autogroup:member", "autogroup:tagged"], "users": ["root"] }
  ```

- **SSH Policy**: SSH source/destination validation enforces Tailscale's security model. [#3010](https://github.com/juanfont/headscale/issues/3010)

  Per [Tailscale SSH documentation](https://tailscale.com/docs/features/tailscale-ssh), these rules are now enforced:
  1. **Tags cannot SSH to user-owned devices**: SSH rules with `tag:*` or `autogroup:tagged` as source cannot have username destinations (e.g., `alice@`) or `autogroup:member`/`autogroup:self` as destination.
  2. **Username destinations require same-user source**: If the destination is a specific username (e.g., `alice@`), the source must be exactly that user. Use `autogroup:self` for same-user SSH access instead.

  **Invalid policies are rejected at load time:**

  ```json
  // INVALID: tag source to user destination
  {"src": ["tag:server"], "dst": ["alice@"], ...}

  // INVALID: autogroup:tagged to autogroup:member
  {"src": ["autogroup:tagged"], "dst": ["autogroup:member"], ...}

  // INVALID: group to specific user (use autogroup:self instead)
  {"src": ["group:admins"], "dst": ["alice@"], ...}
  ```

  **Valid patterns:**

  ```json
  // Users/groups can SSH to their own devices via autogroup:self
  {"src": ["group:admins"], "dst": ["autogroup:self"], ...}

  // Users/groups can SSH to tagged devices
  {"src": ["group:admins"], "dst": ["autogroup:tagged"], ...}

  // Tagged devices can SSH to other tagged devices
  {"src": ["autogroup:tagged"], "dst": ["autogroup:tagged"], ...}

  // Same user can SSH to their own devices
  {"src": ["alice@"], "dst": ["alice@"], ...}
  ```

### Changes

- Smarter change notifications send partial map updates and node removals instead of full maps. [#2961](https://github.com/juanfont/headscale/pull/2961)
  - Headscale sends lightweight endpoint and DERP region updates instead of full maps. [#2856](https://github.com/juanfont/headscale/pull/2856)
- The repository includes a NixOS module for faster iteration. [#2857](https://github.com/juanfont/headscale/pull/2857)
- Webpages have a favicon. [#2858](https://github.com/juanfont/headscale/pull/2858)
- The OIDC callback and registration web templates are redesigned. [#2832](https://github.com/juanfont/headscale/pull/2832)
- The IP allocator reclaims IPs when nodes are deleted. [#2831](https://github.com/juanfont/headscale/pull/2831)
- Pre-authentication keys are hashed with bcrypt. [#2853](https://github.com/juanfont/headscale/pull/2853)
- API keys have a prefix (`hskey-api-{prefix}-{secret}`). [#2853](https://github.com/juanfont/headscale/pull/2853)
- Registration keys have a prefix for web authentication tracking (`hskey-reg-{random}`). [#2853](https://github.com/juanfont/headscale/pull/2853)
- Tags can be tagOwner of other tags. [#2930](https://github.com/juanfont/headscale/pull/2930)
- The `taildrop.enabled` configuration option enables or disables Taildrop file sharing. [#2955](https://github.com/juanfont/headscale/pull/2955)
- An empty `metrics_listen_addr` disables the metrics server. [#2914](https://github.com/juanfont/headscale/pull/2914)
- ACME/autocert errors are logged for easier debugging. [#2933](https://github.com/juanfont/headscale/pull/2933)
- CLI list output formatting is improved. [#2951](https://github.com/juanfont/headscale/pull/2951)
- Container images use Debian 13 distroless base images. [#2944](https://github.com/juanfont/headscale/pull/2944)
- New OIDC nodes get the ACL policy without a client restart. [#2890](https://github.com/juanfont/headscale/pull/2890)
- autogroup:self no longer prevents visibility of nodes matched by other ACL rules. [#2882](https://github.com/juanfont/headscale/pull/2882)
- Nodes are no longer rejected after their pre-authentication key expires. [#2917](https://github.com/juanfont/headscale/pull/2917)
- The list-routes command respects the identifier filter with JSON output. [#2927](https://github.com/juanfont/headscale/pull/2927)
- API key expire/delete commands accept an `--id` flag as an alternative to `--prefix`. [#3016](https://github.com/juanfont/headscale/pull/3016)

## 0.27.1 (2025-11-11)

**Minimum supported Tailscale client version: v1.64.0**

### Changes

- Nodes can be expired with a custom timestamp. [#2828](https://github.com/juanfont/headscale/pull/2828)
- Node expiry is no longer reset when tailscaled restarts. [#2875](https://github.com/juanfont/headscale/pull/2875)
- OIDC authentication works when multiple login URLs are opened. [#2861](https://github.com/juanfont/headscale/pull/2861)
- Node re-registration no longer fails with expired auth keys. [#2859](https://github.com/juanfont/headscale/pull/2859)
- Old unused database tables and indices are removed. [#2844](https://github.com/juanfont/headscale/pull/2844) [#2872](https://github.com/juanfont/headscale/pull/2872)
- Database validation ignores litestream tables. [#2843](https://github.com/juanfont/headscale/pull/2843)
- Exit node visibility respects ACL rules. [#2855](https://github.com/juanfont/headscale/pull/2855)
- The SSH policy no longer becomes empty when an unknown user is referenced. [#2874](https://github.com/juanfont/headscale/pull/2874)
- Policy validation works in bypass-grpc mode. [#2854](https://github.com/juanfont/headscale/pull/2854)
- autogroup:self interacts correctly with other ACL rules. [#2842](https://github.com/juanfont/headscale/pull/2842)
- The DERP map shuffle test is no longer flaky. [#2848](https://github.com/juanfont/headscale/pull/2848)
- Debian and Alpine containers use current stable base images. [#2827](https://github.com/juanfont/headscale/pull/2827)

## 0.27.0 (2025-10-27)

**Minimum supported Tailscale client version: v1.64.0**

### Database integrity improvements

This release includes a significant database migration that addresses
longstanding issues with the database schema and data integrity that have
accumulated over the years. The migration introduces a `schema.sql` file as the
source of truth for the expected database schema, so that new migrations do not
cause divergence again.

These issues arose from several factors discovered over time: SQLite
foreign keys were not enforced for many early versions, all migrations ran in
one large function until version 0.23.0, and GORM's AutoMigrate feature was
used inconsistently. From now on, all new migrations will be explicit SQL
operations rather than relying on GORM AutoMigrate, and foreign keys will be
enforced throughout the migration process.

This change only improves SQLite databases. PostgreSQL databases
are not affected.

Read the
[PR description](https://github.com/juanfont/headscale/pull/2617) for more
technical details about the issues and solutions.

**SQLite Database Backup Example:**

```bash
# Stop headscale
systemctl stop headscale

# Backup sqlite database
cp /var/lib/headscale/db.sqlite /var/lib/headscale/db.sqlite.backup

# Backup sqlite WAL/SHM files (if they exist)
cp /var/lib/headscale/db.sqlite-wal /var/lib/headscale/db.sqlite-wal.backup
cp /var/lib/headscale/db.sqlite-shm /var/lib/headscale/db.sqlite-shm.backup

# Start headscale (migration will run automatically)
systemctl start headscale
```

### DERPMap update frequency

The default DERPMap update frequency changed from 24 hours to 3 hours.
If you set the `derp.update_frequency` configuration option, we recommend
changing it to `3h` so that the headscale instance gets the latest
DERPMap updates when upstream changes.

### Autogroups

This release adds the three missing autogroups: `self`
(experimental), `member`, and `tagged`. See the
[documentation](https://tailscale.com/docs/reference/targets-and-selectors#autogroups)
for a detailed explanation.

`autogroup:self` is experimental and should be used with caution, but
we need help testing it. Experimental here means two things. First, generating
the packet filter from policies that use `autogroup:self` is very expensive, and
it might perform poorly, or not work at all, on Headscale installations with a
large number of nodes. Second, the implementation might have bugs or edge cases
we are not aware of, so nodes or users might gain _more_ access than
expected. Please report bugs.

### Node store (in memory database)

Under the hood, a new data structure stores nodes in memory. It
is called `NodeStore` and aims to reduce reads and writes
of nodes to the database layer. We have not benchmarked it, but expect it to
improve performance for read-heavy workloads. In the "worst case", we
have moved the bottleneck somewhere else. In the "best case", we should see a good
improvement in compute resource usage at the expense of memory usage. We are
excited about this change and think it will make it easier to improve
the code base over time and make it more correct and efficient.

### BREAKING

- 32-bit binaries are no longer supported. [#2692](https://github.com/juanfont/headscale/pull/2692)
- Policy: Zero or empty destination ports are no longer allowed. [#2606](https://github.com/juanfont/headscale/pull/2606)
- Hostname validation is stricter. [#2383](https://github.com/juanfont/headscale/pull/2383)
  - Hostnames must be valid DNS labels (2-63 characters, alphanumeric and
    hyphens only, cannot start/end with hyphen).
  - **Client Registration (New Nodes)**: Invalid hostnames are automatically
    renamed to `invalid-XXXXXX` format.
    - `my-laptop` → accepted as-is
    - `My-Laptop` → `my-laptop` (lowercased)
    - `my_laptop` → `invalid-a1b2c3` (underscore not allowed)
    - `test@host` → `invalid-d4e5f6` (@ not allowed)
    - `laptop-🚀` → `invalid-j1k2l3` (emoji not allowed)
  - **Hostinfo Updates / CLI**: Invalid hostnames are rejected with an error.
    - Valid names are accepted or lowercased.
    - Names with invalid characters, too short (<2), too long (>63), or
      starting/ending with hyphen are rejected.

### Changes

- **Database schema migration improvements for SQLite** [#2617](https://github.com/juanfont/headscale/pull/2617)
  - **IMPORTANT: Back up your SQLite database before upgrading.**
  - The migration uses a safer table renaming strategy.
  - The migration addresses longstanding database integrity issues.
- A new flag manipulates the policy in the database directly. [#2765](https://github.com/juanfont/headscale/pull/2765)
- The DERPmap update frequency default changed from 24h to 3h. [#2741](https://github.com/juanfont/headscale/pull/2741)
- DERPmap updates retry, and fail conservatively by preserving the old map
  upon failure.
  [#2741](https://github.com/juanfont/headscale/pull/2741)
- `autogroup:member` and `autogroup:tagged` are supported. [#2572](https://github.com/juanfont/headscale/pull/2572)
- Policy no longer removes return routes. [#2767](https://github.com/juanfont/headscale/pull/2767)
- Policy v1 code is removed. [#2600](https://github.com/juanfont/headscale/pull/2600)
- Debian/Ubuntu packaging is refactored, and Ubuntu 20.04 is no longer supported. [#2614](https://github.com/juanfont/headscale/pull/2614)
- A redundant check regarding `noise` config is removed. [#2658](https://github.com/juanfont/headscale/pull/2658)
- The OpenID Connect documentation is refactored. [#2625](https://github.com/juanfont/headscale/pull/2625)
- Headscale doesn't crash if the config file is missing. [#2656](https://github.com/juanfont/headscale/pull/2656)
- A `/robots.txt` endpoint keeps crawlers away. [#2643](https://github.com/juanfont/headscale/pull/2643)
- OIDC: Headscale uses the group claim from UserInfo. [#2663](https://github.com/juanfont/headscale/pull/2663)
- OIDC: Headscale updates the user with claims from UserInfo _before_ comparing
  with allowed groups, email and domain.
  [#2663](https://github.com/juanfont/headscale/pull/2663)
- The policy rejects invalid fields, making spelling errors easier to
  spot. [#2764](https://github.com/juanfont/headscale/pull/2764)
- The FAQ explains how to recover from an invalid policy in the database. [#2776](https://github.com/juanfont/headscale/pull/2776)
- EXPERIMENTAL: Headscale supports `autogroup:self`. [#2789](https://github.com/juanfont/headscale/pull/2789)
- Headscale has a healthcheck command. [#2659](https://github.com/juanfont/headscale/pull/2659)

## 0.26.1 (2025-06-06)

### Changes

- Nodes must match both node key and machine key when connecting. [#2642](https://github.com/juanfont/headscale/pull/2642)

## 0.26.0 (2025-05-14)

### BREAKING

#### Routes

Route internals have been rewritten, and the dedicated route table is removed
from the database. This simplifies the codebase, which had grown unnecessarily
complex after the routes were split into separate tables. Going via the
database and keeping the state in sync made the code very hard to reason about
and prone to errors. Most of the route state is only relevant while headscale
is running, and is now kept only in memory. As part of this, the CLI and API
are simplified to reflect the changes:

```console
$ headscale nodes list-routes
ID | Hostname           | Approved | Available       | Serving (Primary)
1  | ts-head-ruqsg8     |          | 0.0.0.0/0, ::/0 |
2  | ts-unstable-fq7ob4 |          | 0.0.0.0/0, ::/0 |

$ headscale nodes approve-routes --identifier 1 --routes 0.0.0.0/0,::/0
Node updated

$ headscale nodes list-routes
ID | Hostname           | Approved        | Available       | Serving (Primary)
1  | ts-head-ruqsg8     | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0 | 0.0.0.0/0, ::/0
2  | ts-unstable-fq7ob4 |                 | 0.0.0.0/0, ::/0 |
```

Approving an exit route (0.0.0.0/0 or ::/0) approves both IPv4 and IPv6.

- The Route API and CLI are removed. [#2422](https://github.com/juanfont/headscale/pull/2422)
- Routes are managed via the Node API. [#2422](https://github.com/juanfont/headscale/pull/2422)
- A node receives only the routes accessible to it. [#2561](https://github.com/juanfont/headscale/pull/2561)

#### Policy v2

This release introduces a new policy implementation. It is a complete rewrite
with some significant quality and consistency improvements. In principle, there
are no new features, but some long-standing bugs should be resolved, or be
easier to fix in the future. The new policy code passes all of our tests.

**Changes**

- The policy is validated and "resolved" when loading, with errors for
  invalid rules and conditions.
  - Previously this happened partly at load time and partly at runtime (when
    the policy was applied to a node).
  - So the first time you convert, a policy that previously loaded but failed
    at runtime now fails at load time.
- Error messages should be more descriptive and informative.
  - There is still work to be done here, but "typing" already improves them
    (e.g. only Users can be put in Groups).
- All users in the policy must contain an `@` character.
  - If your user naturally contains an `@`, like an email, this just works.
  - If it is based on usernames, or other identifiers without an `@`, append an
    `@` at the end. For example, if your user is `john`, it
    must be written as `john@` in the policy.

<details>

<summary>Migration notes when the policy is stored in the database.</summary>

This section **only** applies if the policy is stored in the database and
Headscale 0.26 doesn't start due to a policy error
(`failed to load ACL policy`).

- Start Headscale 0.26 with the environment variable `HEADSCALE_POLICY_V1=1`
  set. To check that Headscale picked up the environment variable, look for
  this message during startup: `Using policy manager version: 1`.
- Dump the policy to a file: `headscale policy get > policy.json`.
- Edit `policy.json` and migrate to policy V2. Use the command
  `headscale policy check --file policy.json` to check for policy errors.
- Load the modified policy: `headscale policy set --file policy.json`.
- Restart Headscale **without** the environment variable `HEADSCALE_POLICY_V1`.
  Headscale should now print the message `Using policy manager version: 2` and
  start successfully.

</details>

**SSH**

The SSH policy has been reworked to be more consistent with the rest of the
policy. Several inconsistencies between our implementation and Tailscale's
upstream are also closed, which might be a breaking change for some users. See the
[upstream documentation](https://tailscale.com/docs/reference/syntax/policy-file#tailscale-ssh)
for which types are allowed in `src`, `dst` and `users`.

One large inconsistency remains: we allow `*` as a destination because we
do not yet support `autogroup:self`, `autogroup:member` and
`autogroup:tagged`. Support for `*` will be removed once we support
the autogroups.

**Current state**

The new policy passes all tests, both integration and unit tests. This does
not mean it is perfect, but it is a good start. Corner cases that currently
work in v1 and are not tested might be broken in v2 (and vice versa).

**We do need help testing this code**

#### Other breaking changes

- `server_url` and `base_domain` can no longer be equal. [#2544](https://github.com/juanfont/headscale/pull/2544)
- The API returns the full user for pre auth keys instead of a string. [#2542](https://github.com/juanfont/headscale/pull/2542)
- The pre auth key API/CLI uses ID over username. [#2542](https://github.com/juanfont/headscale/pull/2542)
- A non-empty list of global nameservers must be specified via
  `dns.nameservers.global` if the configuration option `dns.override_local_dns`
  is enabled or is not specified in the configuration file. This aligns with
  the behaviour of tailscale.com.
  [#2438](https://github.com/juanfont/headscale/pull/2438)

### Changes

- Headscale uses Go 1.24. [#2427](https://github.com/juanfont/headscale/pull/2427)
- The `headscale policy check` command checks the policy. [#2553](https://github.com/juanfont/headscale/pull/2553)
- `oidc.map_legacy_users` and `oidc.strip_email_domain` are removed. [#2411](https://github.com/juanfont/headscale/pull/2411)
- The `/debug` endpoint shows more information. [#2420](https://github.com/juanfont/headscale/pull/2420)
  - It can inspect running goroutines and take profiles.
  - It shows config, policy, filter, ssh policy per node, connected nodes and
    DERPmap.
- OIDC: Headscale fetches UserInfo to get EmailVerified if necessary. [#2493](https://github.com/juanfont/headscale/pull/2493)
  - If an OIDC provider doesn't include the `email_verified` claim in its ID
    tokens, Headscale tries to get it from the UserInfo endpoint.
- OIDC: Headscale tries to populate name, email and username from UserInfo. [#2545](https://github.com/juanfont/headscale/pull/2545)
- Node updates query only the relevant nodes from the database, which improves
  performance. [#2509](https://github.com/juanfont/headscale/pull/2509)
- Node FQDNs in the netmap end with a dot ("."). This aligns
  with the behaviour of tailscale.com.
  [#2503](https://github.com/juanfont/headscale/pull/2503)
- Support for "Override local DNS" is restored. [#2438](https://github.com/juanfont/headscale/pull/2438)
- Routes are documented. [#2496](https://github.com/juanfont/headscale/pull/2496)

## 0.25.1 (2025-02-25)

### Changes

- Registration errors reach the client in the register response, as Tailscale clients expect, not as an HTTP error. [#2435](https://github.com/juanfont/headscale/pull/2435)
- Routes passed on registration are saved. [#2444](https://github.com/juanfont/headscale/pull/2444)
- The registration page is no longer displayed twice. [#2445](https://github.com/juanfont/headscale/pull/2445)

## 0.25.0 (2025-02-11)

### BREAKING

- The authentication flow has been rewritten. This change should be
  transparent to users, except for some bugfixes that were
  discovered and fixed as part of the rewrite. [#2374](https://github.com/juanfont/headscale/pull/2374)
  - When a node is registered with _a new user_, it is registered as a new
    node. [#2327](https://github.com/juanfont/headscale/issues/2327)
    [#1310](https://github.com/juanfont/headscale/issues/1310)
  - A logged out node logging in with the same user replaces the existing
    node.
- Tailscale clients older than 1.62 (Capability version 87) are no longer supported. [#2405](https://github.com/juanfont/headscale/pull/2405)

### Changes

- `oidc.map_legacy_users` is now `false` by default. [#2350](https://github.com/juanfont/headscale/pull/2350)
- Headscale prints the Tailscale version instead of capability versions for outdated nodes. [#2391](https://github.com/juanfont/headscale/pull/2391)
- Users from OIDC can no longer be renamed. [#2393](https://github.com/juanfont/headscale/pull/2393)
- The minimum hostname length is 2. [#2393](https://github.com/juanfont/headscale/pull/2393)
- Nodes with invalid auth keys no longer cause a migration error. [#2412](https://github.com/juanfont/headscale/pull/2412)
- Pre auth keys belonging to a user are no longer deleted with the user. [#2396](https://github.com/juanfont/headscale/pull/2396)
- Pre auth keys used by a node can no longer be deleted. [#2396](https://github.com/juanfont/headscale/pull/2396)
- HTTP errors are reworked to return better status codes and errors to users. [#2398](https://github.com/juanfont/headscale/pull/2398)
- Headscale prints its version and commit on server startup. [#2415](https://github.com/juanfont/headscale/pull/2415)

## 0.24.3 (2025-02-07)

### Changes

- Migrations no longer fail on nodes that have invalid auth keys. [#2412](https://github.com/juanfont/headscale/pull/2412)
- Deleting a user no longer deletes the user's pre auth keys. [#2396](https://github.com/juanfont/headscale/pull/2396)
- Pre auth keys used by a node can no longer be deleted. [#2396](https://github.com/juanfont/headscale/pull/2396)

## 0.24.2 (2025-01-30)

### Changes

- Policy matches a user whose email and username are equal. [#2388](https://github.com/juanfont/headscale/pull/2388)
- Invalid routes are deleted before a NOT NULL constraint is added on node_id. [#2386](https://github.com/juanfont/headscale/pull/2386)

## 0.24.1 (2025-01-23)

### Changes

- A migration issue with the user table on PostgreSQL is fixed. [#2367](https://github.com/juanfont/headscale/pull/2367)
- Username validation is relaxed to allow emails. [#2364](https://github.com/juanfont/headscale/pull/2364)
- Invalid routes are removed and routes get stronger constraints to avoid an
  API panic. [#2371](https://github.com/juanfont/headscale/pull/2371)
- headscale no longer panics when `derp.update_frequency` is 0. [#2368](https://github.com/juanfont/headscale/pull/2368)

## 0.24.0 (2025-01-17)

### Security fix: OIDC changes in Headscale 0.24.0

The following issue _only_ affects Headscale installations which authenticate
with OIDC.

_Headscale v0.23.0 and earlier_ identified OIDC users by the "username" part of
their email address (when `strip_email_domain: true`, the default) or whole
email address (when `strip_email_domain: false`).

Depending on how Headscale and your Identity Provider (IdP) were configured,
only using the `email` claim could allow a malicious user with an IdP account to
take over another Headscale user's account, even when
`strip_email_domain: false`.

This would also cause a user to lose access to their Headscale account if they
changed their email address.

_Headscale v0.24.0_ now identifies OIDC users by the `iss` and `sub` claims.
[These are guaranteed by the OIDC specification to be stable and unique](https://openid.net/specs/openid-connect-core-1_0.html#ClaimStability),
even if a user changes email address. A well-designed IdP will typically set
`sub` to an opaque identifier like a UUID or numeric ID, which has no relation
to the user's name or email address.

Headscale v0.24.0 and later will also automatically update profile fields with
OIDC data on login. This means that users can change those details in your IdP
and have them populate to Headscale automatically the next time they log in.
However, this may affect the way you reference users in policies.

Headscale v0.23.0 and earlier never recorded the `iss` and `sub` fields, so all
legacy (existing) OIDC accounts _need to be migrated_ to be properly secured.

#### What do I need to do to migrate?

Headscale v0.24.0 has an automatic migration feature, which is enabled by
default (`map_legacy_users: true`). **This will be disabled by default in a
future version of Headscale – any unmigrated users will get new accounts.**

The migration will mostly be done automatically, with one exception. If your
OIDC does not provide an `email_verified` claim, Headscale will ignore the
`email`. This means that either the administrator will have to mark the user
emails as verified, or ensure the users verify their emails. Any unverified
emails will be ignored, meaning that the users will get new accounts instead of
being migrated.

After this exception is ensured, make all users log into Headscale with their
account, and Headscale will automatically update the account record. This will
be transparent to the users.

When all users have logged in, you can disable the automatic migration by
setting `map_legacy_users: false` in your configuration file.

`map_legacy_users` will be set to `false` by default in v0.25.0, and the
migration mechanism will be removed in v0.26.0.

<details>

<summary>What does automatic migration do?</summary>

##### What does automatic migration do?

When automatic migration is enabled (`map_legacy_users: true`), Headscale will
first match an OIDC account to a Headscale account by `iss` and `sub`, and then
fall back to matching OIDC users similarly to how Headscale v0.23.0 did:

- If `strip_email_domain: true` (the default): the Headscale username matches
  the "username" part of their email address.
- If `strip_email_domain: false`: the Headscale username matches the _whole_
  email address.

On migration, Headscale will change the account's username to their
`preferred_username`. **This could break any ACLs or policies which are
configured to match by username.**

Like with Headscale v0.23.0 and earlier, this migration only works for users who
haven't changed their email address since their last Headscale login.

A _successful_ automated migration should otherwise be transparent to users.

Once a Headscale account has been migrated, it will be _unavailable_ to be
matched by the legacy process. An OIDC login with a matching username, but
_non-matching_ `iss` and `sub` will instead get a _new_ Headscale account.

Because of the way OIDC works, Headscale's automated migration process can
_only_ work when a user tries to log in after the update.

Legacy account migration should have no effect on new installations where all
users have a recorded `sub` and `iss`.

</details>

<details>

<summary>What happens when automatic migration is disabled?</summary>

##### What happens when automatic migration is disabled?

When automatic migration is disabled (`map_legacy_users: false`), Headscale will
only try to match an OIDC account to a Headscale account by `iss` and `sub`.

If there is no match, it will get a _new_ Headscale account – even if there was
a legacy account which _could_ have matched and migrated.

We recommend new Headscale users explicitly disable automatic migration – but it
should otherwise have no effect if every account has a recorded `iss` and `sub`.

When automatic migration is disabled, the `strip_email_domain` setting will have
no effect.

</details>

Special thanks to @micolous for reviewing, proposing and working with us on
these changes.

#### Other OIDC changes

Headscale now uses
[the standard OIDC claims](https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims)
to populate and update user information every time they log in:

| Headscale profile field | OIDC claim           | Notes / examples                                                                                          |
| ----------------------- | -------------------- | --------------------------------------------------------------------------------------------------------- |
| email address           | `email`              | Only used when `"email_verified": true`                                                                   |
| display name            | `name`               | eg: `Sam Smith`                                                                                           |
| username                | `preferred_username` | Varies depending on IdP and configuration, eg: `ssmith`, `ssmith@idp.example.com`, `\\example.com\ssmith` |
| profile picture         | `picture`            | URL to a profile picture or avatar                                                                        |

These should show up nicely in the Tailscale client.

This will also affect the way you
[reference users in policies](https://github.com/juanfont/headscale/pull/2205).

### BREAKING

- The `dns.use_username_in_magic_dns` configuration option is removed.
  [#2020](https://github.com/juanfont/headscale/pull/2020) [#2279](https://github.com/juanfont/headscale/pull/2279)
  - Having usernames in magic DNS is no longer possible.
- Support for versions older than 1.56 is removed. [#2149](https://github.com/juanfont/headscale/pull/2149)
  - Old code required by old versions is cleaned up.
- The user gRPC/API has changed. [#2261](https://github.com/juanfont/headscale/pull/2261)
  - If you depend on a Headscale Web UI, wait with this update until the UI has
    been updated to match the new API.
  - `GET /api/v1/user/{name}` and `GetUser` have been removed in favour of
    `ListUsers` with an ID parameter.
  - `RenameUser` and `DeleteUser` now require an ID instead of a name.

### Changes

- The built-in DERP server is more compatible with clients connecting over
  WebSocket. [#2132](https://github.com/juanfont/headscale/pull/2132)
- Nodes can use SSH agent forwarding. [#2145](https://github.com/juanfont/headscale/pull/2145)
- The MoveNode rpc processes the fields in its post request correctly. [#2179](https://github.com/juanfont/headscale/pull/2179)
- 'Hostname' is converted to 'givenName' in a node with FQDN rules applied. [#2198](https://github.com/juanfont/headscale/pull/2198)
- hostname and givenName update when the hostname in HostInfo changes. [#2199](https://github.com/juanfont/headscale/pull/2199)
- The `stable-debug` container tag is no longer missing. [#2232](https://github.com/juanfont/headscale/pull/2232)
- The `server_url` and `base_domain` check is looser. It was overly strict in some
  cases. [#2248](https://github.com/juanfont/headscale/pull/2248)
- The CLI for managing users now accepts `--identifier` in addition to
  `--name`. Using `--identifier` is recommended.
  [#2261](https://github.com/juanfont/headscale/pull/2261)
- The configuration takes a `dns.extra_records_path` option. [#2262](https://github.com/juanfont/headscale/issues/2262)
- headscale supports client verify for DERP. [#2046](https://github.com/juanfont/headscale/pull/2046)
- headscale supports a PKCE Verifier for OIDC. [#2314](https://github.com/juanfont/headscale/pull/2314)

## 0.23.0 (2024-09-18)

This release was intended to be mainly a code reorganisation and refactoring,
significantly improving the maintainability of the codebase. This should allow
us to improve further and make it easier for the maintainers to keep on top of
the project. However, as you all have noticed, it turned out to become a much
larger, much longer release cycle than anticipated. It ended up as a release
with a lot of rewrites and changes to the code base and functionality of
Headscale, cleaning up a lot of technical debt and introducing a lot of
improvements. This does come with some breaking changes.

**Please remember to always back up your database between versions.**

#### Here is a short summary of the broad topics of changes:

Code has been organised into modules, reducing use of global variables/objects,
isolating concerns and “putting the right things in the logical place”.

The new
[policy](https://github.com/juanfont/headscale/tree/main/hscontrol/policy) and
[mapper](https://github.com/juanfont/headscale/tree/main/hscontrol/mapper)
package, containing the ACL/Policy logic and the logic for creating the data
served to clients (the network “map”) has been rewritten and improved. This
change has allowed us to finish SSH support and add additional tests throughout
the code to ensure correctness.

The
[“poller”, or streaming logic](https://github.com/juanfont/headscale/blob/main/hscontrol/poll.go)
has been rewritten. Instead of keeping track of the latest updates and checking
at a fixed interval, it now uses go channels, implemented in our new
[notifier](https://github.com/juanfont/headscale/tree/main/hscontrol/notifier)
package. This allows us to send updates to connected clients immediately. This
should both improve performance and potential latency before a client picks up
an update.

Headscale now supports sending “delta” updates, thanks to the new mapper and
poller logic, allowing us to only inform nodes about new nodes, changed nodes
and removed nodes. Previously we sent the entire state of the network every time
an update was due.

While we have a pretty good
[test harness](https://github.com/search?q=repo%3Ajuanfont%2Fheadscale+path%3A_test.go&type=code)
for validating our changes, the changes came down to
[284 changed files with 32,316 additions and 24,245 deletions](https://github.com/juanfont/headscale/compare/b01f1f1867136d9b2d7b1392776eb363b482c525...ed78ecd)
and bugs are expected. We need help testing this release. In addition, while we
think the performance should in general be better, there might be regressions in
parts of the platform, particularly where we prioritised correctness over speed.

There are also several bugfixes that have been encountered and fixed as part of
implementing these changes, particularly after improving the test harness as
part of adopting [#1460](https://github.com/juanfont/headscale/pull/1460).

### BREAKING

- Code reorganisation: a lot of code has moved. Please review the following PRs
  accordingly. [#1473](https://github.com/juanfont/headscale/pull/1473)
- The database configuration has a new structure. See
  [config-example.yaml](./config-example.yaml) for the new structure.
  [#1700](https://github.com/juanfont/headscale/pull/1700)
  - The old structure has been removed and the configuration _must_ be
    converted.
  - PostgreSQL takes additional configuration for setting max open, idle
    connection and idle connection lifetime.
- API: Machine is now Node. [#1553](https://github.com/juanfont/headscale/pull/1553)
- Support for older Tailscale clients is removed. [#1611](https://github.com/juanfont/headscale/pull/1611)
  - The oldest supported client is 1.42.
- Headscale checks that _at least_ one DERP is defined at start. [#1564](https://github.com/juanfont/headscale/pull/1564)
  - If no DERP is configured, the server will fail to start. This can be
    because it cannot load the DERPMap from file or url.
- Embedded DERP server requires a private key. [#1611](https://github.com/juanfont/headscale/pull/1611)
  - Add a filepath entry to
    [`derp.server.private_key_path`](https://github.com/juanfont/headscale/blob/b35993981297e18393706b2c963d6db882bba6aa/config-example.yaml#L95).
- Docker images are now built with goreleaser (ko). [#1716](https://github.com/juanfont/headscale/pull/1716)
  [#1763](https://github.com/juanfont/headscale/pull/1763)
  - The entrypoint of the container image has changed from shell to headscale.
    This requires changing `headscale serve` to `serve`.
  - `/var/lib/headscale` and `/var/run/headscale` are no longer created
    automatically. See [container docs](./docs/setup/install/container.md).
- Prefixes are now defined per v4 and v6 range. [#1756](https://github.com/juanfont/headscale/pull/1756)
  - `ip_prefixes` option is now `prefixes.v4` and `prefixes.v6`.
  - `prefixes.allocation` can be set to assign IPs at `sequential` or `random`.
    [#1869](https://github.com/juanfont/headscale/pull/1869)
- MagicDNS domains no longer contain usernames.
  - This is in preparation to fix Headscale's implementation of tags, which
    currently does not correctly remove the link between a tagged device and a
    user. As tagged devices will not have a user, this will require a change to
    the DNS generation, removing the username. See
    [#1369](https://github.com/juanfont/headscale/issues/1369) for more
    information.
  - `use_username_in_magic_dns` can be used to turn this behaviour on again, but
    note that this option _will be removed_ when tags are fixed.
    - dns.base_domain can no longer be the same as (or part of) server_url.
    - This option brings Headscale's behaviour in line with Tailscale.
- YAML files are no longer supported for headscale policy. [#1792](https://github.com/juanfont/headscale/pull/1792)
  - HuJSON is now the only supported format for policy.
- DNS configuration has been restructured. [#2034](https://github.com/juanfont/headscale/pull/2034)
  - Review the new [config-example.yaml](./config-example.yaml) for the new
    structure.

### Changes

- Database migrations are versioned. [#1644](https://github.com/juanfont/headscale/pull/1644)
- The OIDC callback page is better. [#1484](https://github.com/juanfont/headscale/pull/1484)
- headscale supports SSH. [#1487](https://github.com/juanfont/headscale/pull/1487)
- State management is improved. [#1492](https://github.com/juanfont/headscale/pull/1492)
- Tests use error group handling to ensure they actually pass. [#1535](https://github.com/juanfont/headscale/pull/1535) based on
  [#1460](https://github.com/juanfont/headscale/pull/1460)
- headscale no longer hangs on SIGTERM. [#1492](https://github.com/juanfont/headscale/pull/1492)
  taken from [#1480](https://github.com/juanfont/headscale/pull/1480)
- Logs go to stderr by default. [#1524](https://github.com/juanfont/headscale/pull/1524)
- The [TS-2023-006](https://tailscale.com/security-bulletins/#ts-2023-006)
  security UPnP issue is fixed. [#1563](https://github.com/juanfont/headscale/pull/1563)
- gRPC logging is off. [#1640](https://github.com/juanfont/headscale/pull/1640)
  fixes [#1259](https://github.com/juanfont/headscale/issues/1259)
- A DERP-map entry can be created manually and customized, instead of being
  created automatically.
  [#1565](https://github.com/juanfont/headscale/pull/1565)
- API keys can be deleted. [#1702](https://github.com/juanfont/headscale/pull/1702)
- A new command backfills IP addresses for nodes missing IPs from configured
  prefixes. [#1869](https://github.com/juanfont/headscale/pull/1869)
- An available update is logged as a warning. [#1877](https://github.com/juanfont/headscale/pull/1877)
- Policy supports `autogroup:internet`. [#1917](https://github.com/juanfont/headscale/pull/1917)
- Foreign keys are restored and constraints are added. [#1562](https://github.com/juanfont/headscale/pull/1562)
- The registration page is easier to use on mobile devices.
- The write-ahead-log is on by default and configurable for SQLite. [#1985](https://github.com/juanfont/headscale/pull/1985)
- New APIs manage headscale policy. [#1792](https://github.com/juanfont/headscale/pull/1792)
- Nodes can register using preauthkeys when running on a postgres database in
  a non-UTC timezone.
  [#764](https://github.com/juanfont/headscale/issues/764)
- Integration tests cover postgres for all scenarios.
- CLI commands (all except `serve`) only require minimal configuration. No more
  errors or warnings from unset settings.
  [#2109](https://github.com/juanfont/headscale/pull/2109)
- CLI results are now consistently sent to stdout and errors to stderr. [#2109](https://github.com/juanfont/headscale/pull/2109)
- Shutting down headscale no longer hangs. [#2113](https://github.com/juanfont/headscale/pull/2113)

## 0.22.3 (2023-05-12)

### Changes

- The Docker image includes the previously missing ca-certificates. [#1463](https://github.com/juanfont/headscale/pull/1463)

## 0.22.2 (2023-05-10)

### Changes

- Environment flags enable pprof (profiling). [#1382](https://github.com/juanfont/headscale/pull/1382)
  - Profiles are continuously generated in our integration tests.
- `.deb` packages put the systemd service file in the correct location. [#1391](https://github.com/juanfont/headscale/pull/1391)
- The Noise implementation is improved. [#1379](https://github.com/juanfont/headscale/pull/1379)
- New node filter logic ensures nodes with access can see each other. [#1381](https://github.com/juanfont/headscale/pull/1381)
- Both exit routes are disabled (or deleted) at the same time. [#1428](https://github.com/juanfont/headscale/pull/1428)
- The Docker image is no longer distroless and creates the default socket dir
  in `/var/run/headscale`. [#1450](https://github.com/juanfont/headscale/pull/1450)

## 0.22.1 (2023-04-20)

### Changes

- systemd can now bind to port 80. [#1365](https://github.com/juanfont/headscale/pull/1365)

## 0.22.0 (2023-04-20)

### Changes

- The release process includes `.deb` packages. [#1297](https://github.com/juanfont/headscale/pull/1297)
- The documentation is updated and simplified to use new `.deb` packages. [#1349](https://github.com/juanfont/headscale/pull/1349)
- The release process includes 32-bit Arm platforms. [#1297](https://github.com/juanfont/headscale/pull/1297)
- "\*" works properly in ACLs, fixing a longstanding bug.
  [#699](https://github.com/juanfont/headscale/issues/699)
  [#1279](https://github.com/juanfont/headscale/pull/1279)
- IPv6 can be used in, and while using, ACLs (part of [#809](https://github.com/juanfont/headscale/issues/809)).
  [#1339](https://github.com/juanfont/headscale/pull/1339)
- Headscale targets Go 1.20 and Tailscale 1.38. [#1323](https://github.com/juanfont/headscale/pull/1323)

## 0.21.0 (2023-03-20)

### Changes

- The CLI has a "configtest" command. [#1230](https://github.com/juanfont/headscale/pull/1230)
- `/apple` documents connecting with iOS. [#1261](https://github.com/juanfont/headscale/pull/1261)
- iOS compatibility is updated and iOS has documentation. [#1264](https://github.com/juanfont/headscale/pull/1264)
- Routes can be deleted. [#1244](https://github.com/juanfont/headscale/pull/1244)

## 0.20.0 (2023-02-03)

### Changes

- Wrong behaviour in exit nodes is fixed. [#1159](https://github.com/juanfont/headscale/pull/1159)
- `dns_config.restricted_nameservers` behaves like it does in tailscale. [#1162](https://github.com/juanfont/headscale/pull/1162)
- OpenID Connect authenticated client expiry time is configurable. [#1191](https://github.com/juanfont/headscale/pull/1191)
  - Defaults to 180 days like Tailscale SaaS.
  - An option uses the expiry time from the OpenID token for the node.
    See config-example.yaml.
- Map info sent to nodes sets ControlTime. [#1195](https://github.com/juanfont/headscale/pull/1195)
- Node updates sent populate the Tags field. [#1195](https://github.com/juanfont/headscale/pull/1195)

## 0.19.0 (2023-01-29)

### BREAKING

- Namespace is renamed to User. [#1144](https://github.com/juanfont/headscale/pull/1144)
  - **BACKUP your database before upgrading.**
- Command line flags previously taking `--namespace` or `-n` now require
  `--user` or `-u`.

## 0.18.0 (2023-01-14)

### Changes

- Routing is reworked and supports subnet router failover. [#1024](https://github.com/juanfont/headscale/pull/1024)
- OIDC has AllowGroups configuration options and an authorization check. [#1041](https://github.com/juanfont/headscale/pull/1041)
- `db_ssl` is false by default. [#1052](https://github.com/juanfont/headscale/pull/1052)
- Nodes are no longer duplicated due to incorrect implementation of the
  protocol. [#1058](https://github.com/juanfont/headscale/pull/1058)
- The CLI reports more accurately whether a machine is online. [#1062](https://github.com/juanfont/headscale/pull/1062)
- A config option sets custom DNS records. [#1035](https://github.com/juanfont/headscale/pull/1035)
- Nodes expire based on OIDC token expiry. [#1067](https://github.com/juanfont/headscale/pull/1067)
- Ephemeral nodes are removed on logout. [#1098](https://github.com/juanfont/headscale/pull/1098)
- ACL performance is improved. [#1129](https://github.com/juanfont/headscale/pull/1129)
- OIDC client secret can be passed via a file. [#1127](https://github.com/juanfont/headscale/pull/1127)

## 0.17.1 (2022-12-05)

### Changes

- A typo on the macOS standalone profile link is corrected. [#1028](https://github.com/juanfont/headscale/pull/1028)
- Platform docs cover Fast User Switching. [#1016](https://github.com/juanfont/headscale/pull/1016)

## 0.17.0 (2022-11-26)

### BREAKING

- `noise.private_key_path` has been added and is required for the new noise
  protocol.
- Log level option `log_level` was moved to a distinct `log` config section and
  renamed to `level`. [#768](https://github.com/juanfont/headscale/pull/768)
- The Alpine Linux container image is removed. [#962](https://github.com/juanfont/headscale/pull/962)

### Important Changes

- headscale supports the Tailscale TS2021 protocol. [#738](https://github.com/juanfont/headscale/pull/738)
- headscale has experimental support for
  [SSH ACL](https://tailscale.com/docs/reference/syntax/policy-file#tailscale-ssh) (see docs for
  limitations). [#847](https://github.com/juanfont/headscale/pull/847)
  - This support should be considered _partially_ implemented.
  - SSH ACLs status:
    - `accept` and `check` are supported (SSH can be enabled and used for connecting
      and authentication).
    - Rejecting connections **is not supported**. If you enable SSH, assume
      that _all_ `ssh` connections **will be allowed**.
    - If you decide to try this feature, carefully manage permissions by
      blocking port `22` with regular ACLs, or do _not_ set `--ssh` on your
      clients.
    - We are currently improving our testing of the SSH ACLs. Help us get an
      overview by testing and giving feedback.
  - This feature should be considered dangerous and is disabled by default.
    Enable it by setting `HEADSCALE_EXPERIMENTAL_FEATURE_SSH=1`.

### Changes

- The env var `HEADSCALE_CONFIG` specifies the config location. [#674](https://github.com/juanfont/headscale/issues/674)
- Headscale targets Go 1.19. [#778](https://github.com/juanfont/headscale/pull/778)
- Headscale is built against Tailscale v1.30.0. [#780](https://github.com/juanfont/headscale/pull/780)
- Headscale warns when running with a reverse proxy improperly configured for
  WebSockets. [#788](https://github.com/juanfont/headscale/pull/788)
- Subnet routers with Primary Routes are fixed. [#811](https://github.com/juanfont/headscale/pull/811)
- headscale supports JSON logs. [#653](https://github.com/juanfont/headscale/issues/653)
- The node key passed to the registration url is sanitised. [#823](https://github.com/juanfont/headscale/pull/823)
- Pre-auth keys can be generated with tags. [#767](https://github.com/juanfont/headscale/pull/767)
- `autoApprovers` ACL entries are evaluated when a machine is registered. [#763](https://github.com/juanfont/headscale/pull/763)
- A config flag allows Headscale to start if the OIDC provider is down. [#829](https://github.com/juanfont/headscale/pull/829)
- A prefix length comparison bug in AutoApprovers route evaluation is fixed. [#862](https://github.com/juanfont/headscale/pull/862)
- Random node DNS suffix is only applied if names collide in namespace. [#766](https://github.com/juanfont/headscale/issues/766)
- The `ip_prefix` configuration option and warning are removed. [#899](https://github.com/juanfont/headscale/pull/899)
- The configuration takes a `dns_config.override_local_dns` option. [#905](https://github.com/juanfont/headscale/pull/905)
- Some DNS config issues are fixed. [#660](https://github.com/juanfont/headscale/issues/660)
- A build flag can disable TS2019. [#928](https://github.com/juanfont/headscale/pull/928)
- OIDC registration issues are fixed. [#960](https://github.com/juanfont/headscale/pull/960)
  [#971](https://github.com/juanfont/headscale/pull/971)
- The NextDNS DNS-over-HTTPS resolver can be specified. [#940](https://github.com/juanfont/headscale/pull/940)
- More sslmode options are available for postgresql connections. [#927](https://github.com/juanfont/headscale/pull/927)

## 0.16.4 (2022-08-21)

### Changes

- Headscale can connect to PostgreSQL over TLS/SSL. [#745](https://github.com/juanfont/headscale/pull/745)
- The CLI can register expired machines. [#754](https://github.com/juanfont/headscale/pull/754)

## 0.16.3 (2022-08-17)

### Changes

- An issue with OIDC authentication is fixed. [#747](https://github.com/juanfont/headscale/pull/747)

## 0.16.2 (2022-08-14)

### Changes

- Bugs in the client registration process after migration to NodeKey are
  fixed. [#735](https://github.com/juanfont/headscale/pull/735)

## 0.16.1 (2022-08-12)

### Changes

- Dependencies are updated (including the library that lacked armhf support). [#722](https://github.com/juanfont/headscale/pull/722)
- Function `excludeCorrectlyTaggedNodes` expands groups. [#563](https://github.com/juanfont/headscale/issues/563)
- The registration protocol implementation is improved and uses NodeKey as
  main identifier. [#725](https://github.com/juanfont/headscale/pull/725)
- Headscale can connect to PostgreSQL via unix socket. [#734](https://github.com/juanfont/headscale/pull/734)

## 0.16.0 (2022-07-25)

**Note:** Take a backup of your database before upgrading.

### BREAKING

- Old ACL syntax is no longer supported ("users" & "ports" -> "src" & "dst").
  Check [the new syntax](https://tailscale.com/docs/features/access-control/acls).

### Changes

- armhf (32-bit ARM) support is **dropped**. [#609](https://github.com/juanfont/headscale/pull/609)
- Headscale fails to serve if the ACL policy file cannot be parsed. [#537](https://github.com/juanfont/headscale/pull/537)
- Registering an unknown pre-auth key no longer causes a labels cardinality
  error. [#519](https://github.com/juanfont/headscale/pull/519)
- Polling no longer crashes on a send on closed channel. [#542](https://github.com/juanfont/headscale/pull/542)
- Ephemeral nodes no longer make spurious calls to setLastStateChangeToNow. [#566](https://github.com/juanfont/headscale/pull/566)
- A new command moves nodes between namespaces. [#362](https://github.com/juanfont/headscale/issues/362)
- OpenID Connect takes more configuration parameters (scopes, free-form
  parameters, domain and user allowlist).
- A new command sets tags on a node. [#525](https://github.com/juanfont/headscale/issues/525)
- A new command shows tags of nodes. [#356](https://github.com/juanfont/headscale/issues/356)
- The enable routes command takes an --all (-a) flag. [#360](https://github.com/juanfont/headscale/issues/360)
- Nodes are now updated across namespaces. [#560](https://github.com/juanfont/headscale/pull/560)
- Nodes can be renamed. [#560](https://github.com/juanfont/headscale/pull/560)
  - Node DNS names are now unique. A random suffix will be added when a node
    joins.
  - This change contains database changes. Remember to **backup** your
    database before upgrading.
- An option enables/disables logtail (Tailscale's logging infrastructure). [#596](https://github.com/juanfont/headscale/pull/596)
  - This change disables the logs by default.
- Durations are parsed with [Prometheus]'s duration parser, supporting days (`d`), weeks (`w`) and
  years (`y`). [#598](https://github.com/juanfont/headscale/pull/598)
- SIGHUP reloads ACLs. [#601](https://github.com/juanfont/headscale/pull/601)
- Headscale uses the new ACL syntax. [#618](https://github.com/juanfont/headscale/pull/618)
- The -c option specifies the config file from the command line. [#285](https://github.com/juanfont/headscale/issues/285)
  [#612](https://github.com/juanfont/headscale/pull/612)
- A configuration option allows Tailscale clients to use a random WireGuard
  port. [Tailscale docs](https://tailscale.com/docs/reference/syntax/policy-file#randomizeclientport)
  [#624](https://github.com/juanfont/headscale/pull/624)
- UX regarding missing configuration (`ephemeral_node_inactivity_timeout` not
  set) is less obtuse.
  [#639](https://github.com/juanfont/headscale/pull/639)
- Nodes are no longer shown as 'offline' in `tailscale status`. [#648](https://github.com/juanfont/headscale/pull/648)
- Shutdown behaviour is improved. [#651](https://github.com/juanfont/headscale/pull/651)
- Headscale no longer uses Gin as web framework.
  [#648](https://github.com/juanfont/headscale/pull/648)
  [#677](https://github.com/juanfont/headscale/pull/677)
- The tailnet node updates check interval is configurable. [#675](https://github.com/juanfont/headscale/pull/675)
- A regression with the HTTP API is fixed. [#684](https://github.com/juanfont/headscale/pull/684)
- nodes ls now prints both Hostname and Name. [#647](https://github.com/juanfont/headscale/issues/647)
  [#687](https://github.com/juanfont/headscale/pull/687)

## 0.15.0 (2022-03-20)

**Note:** Take a backup of your database before upgrading.

### BREAKING

- Boundaries between Namespaces have been removed and all nodes can communicate
  by default. [#357](https://github.com/juanfont/headscale/pull/357)
  - To limit access between nodes, use [ACLs](./docs/ref/acls.md).
- `/metrics` is now a configurable host:port endpoint. You must update your
  `config.yaml` file to include the following. [#344](https://github.com/juanfont/headscale/pull/344)
  ```yaml
  metrics_listen_addr: 127.0.0.1:9090
  ```

### Features

- ACL files can be written with YAML. [#359](https://github.com/juanfont/headscale/pull/359)
- Users can now use emails in ACL groups. [#372](https://github.com/juanfont/headscale/issues/372)
- Commands and subcommands have shorthand aliases. [#376](https://github.com/juanfont/headscale/pull/376)
- A `/windows` endpoint serves Windows configuration instructions and registry
  file download. [#392](https://github.com/juanfont/headscale/pull/392)
- Headscale has an embedded DERP (and STUN) server. [#388](https://github.com/juanfont/headscale/pull/388)

### Changes

- The same IP is no longer assigned to multiple hosts if joined in quick
  succession. [#346](https://github.com/juanfont/headscale/pull/346)
- The code behind registration of machines is simpler. [#366](https://github.com/juanfont/headscale/pull/366)
  - Nodes are now only written to the database if they are registered
    successfully.
- Users can write ACL rules with `*` as source. [#374](https://github.com/juanfont/headscale/issues/374)
- Specific types in Machine reduce the overhead of marshal/unmarshal for
  Hostinfo, routes and endpoints.
  [#371](https://github.com/juanfont/headscale/pull/371)
- A normalization function is applied to FQDN on hostnames when hosts register
  and retrieve information. [#363](https://github.com/juanfont/headscale/issues/363)
- `tailscale logout` works with OIDC. [#508](https://github.com/juanfont/headscale/issues/508)
- The integration tests target Tailscale repo HEAD and the unstable releases
  channel. [#513](https://github.com/juanfont/headscale/pull/513)

## 0.14.0 (2022-02-24)

**UPCOMING BREAKING:** From the **next** version (`0.15.0`), all machines will
be able to communicate regardless of whether they are in the same namespace.
This means that the behaviour currently limited to ACLs will become default.
From version `0.15.0`, all limitation of communications must be done with ACLs.

This is a part of aligning `headscale`'s behaviour with Tailscale's upstream
behaviour.

### BREAKING

- ACLs have been rewritten to align with the behaviour Tailscale Control Panel
  provides. **NOTE:** This is only active if you use ACLs.
  - Namespaces are now treated as Users.
  - All machines can communicate with all machines by default.
  - Tags should now work correctly, and adding a host to Headscale should now
    reload the rules.
  - The documentation has a [fictional example](./docs/ref/acls.md) that should
    cover some use cases of the ACLs features.

### Features

- headscale supports configurable mTLS. [docs](./docs/ref/tls.md) [#297](https://github.com/juanfont/headscale/pull/297)

### Changes

- headscale no longer depends on CGO (switch from CGO SQLite to pure Go). [#346](https://github.com/juanfont/headscale/pull/346)

**0.13.0 (2022-02-18):**

### Features

- The prefix assigned to namespaces supports IPv6.
- headscale has API Key support.
  - `headscale` can be controlled remotely via CLI.
    [docs](./docs/ref/api.md#grpc)
  - The HTTP API is enabled (beta, subject to change).
- OpenID Connect users will be mapped per namespace.
  - Each user will get its own namespace, created if it does not exist.
  - `oidc.domain_map` option has been removed.
  - `strip_email_domain` option has been added. See
    [config-example.yaml](./config-example.yaml).

### Changes

- `ip_prefix` is now superseded by `ip_prefixes` in the configuration. [#208](https://github.com/juanfont/headscale/pull/208)
- `tailscale` (1.20.4) and other dependencies are upgraded to latest. [#314](https://github.com/juanfont/headscale/pull/314)
- `/metrics` no longer swaps machine<->namespace labels. [#312](https://github.com/juanfont/headscale/pull/312)
- The key-value based update mechanism for namespace changes is removed. [#316](https://github.com/juanfont/headscale/pull/316)

**0.12.4 (2022-01-29):**

### Changes

- gRPC Unix Socket permissions are configurable. [#292](https://github.com/juanfont/headscale/pull/292)
- Whitespace is trimmed before reading Private Key from file. [#289](https://github.com/juanfont/headscale/pull/289)
- A new command generates a private key for `headscale`. [#290](https://github.com/juanfont/headscale/pull/290)
- Hosts deleted from control server could be written back to the database, as
  long as they were connected to the control server. They no longer are.
  [#278](https://github.com/juanfont/headscale/pull/278)

## 0.12.3 (2022-01-13)

### Changes

- An Alpine container is available. [#270](https://github.com/juanfont/headscale/pull/270)
- Minor updates in dependencies. [#271](https://github.com/juanfont/headscale/pull/271)

## 0.12.2 (2022-01-11)

Happy New Year!

### Changes

- The Docker release is fixed. [#258](https://github.com/juanfont/headscale/pull/258)
- The main docs are rewritten. [#262](https://github.com/juanfont/headscale/pull/262)
- The Docker docs are improved. [#263](https://github.com/juanfont/headscale/pull/263)

## 0.12.1 (2021-12-24)

(We are skipping 0.12.0 to correct a mishap done weeks ago with the version
tagging.)

### BREAKING

- Headscale is upgraded to Tailscale 1.18. [#229](https://github.com/juanfont/headscale/pull/229)
  - This change requires a new format for private key. Private keys are now
    generated automatically:
    1. Delete your current key.
    2. Restart `headscale`. A new key will be generated.
    3. Restart all Tailscale clients to fetch the new key.

### Changes

- The configuration example is unified. [#197](https://github.com/juanfont/headscale/pull/197)
- Linting and formatting are stricter. [#223](https://github.com/juanfont/headscale/pull/223)

### Features

- Headscale has a gRPC and HTTP API (HTTP API is currently disabled). [#204](https://github.com/juanfont/headscale/pull/204)
- The CLI and the server communicate over gRPC. [#206](https://github.com/juanfont/headscale/pull/206)
  [#212](https://github.com/juanfont/headscale/pull/212)
- Headscale has beta OpenID Connect support. [#126](https://github.com/juanfont/headscale/pull/126)
  [#227](https://github.com/juanfont/headscale/pull/227)

## 0.11.0 (2021-10-25)

### BREAKING

- headscale fetches the DERP map from URL and file. [#196](https://github.com/juanfont/headscale/pull/196)
