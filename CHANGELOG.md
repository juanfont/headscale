# CHANGELOG

## 0.15.0 (2022-xx-xx)

**Note:** Take a backup of your database before upgrading.

### BREAKING

- Boundaries between Namespaces has been removed and all nodes can communicate by default [#357](https://github.com/juanfont/headscale/pull/357)
  - To limit access between nodes, use [ACLs](./docs/acls.md).
- `/metrics` is now a configurable host:port endpoint: [#344](https://github.com/juanfont/headscale/pull/344). You must update your `config.yaml` file to include:
  ```yaml
  metrics_listen_addr: 127.0.0.1:9090
  ```

### Features

- Add support for writing ACL files with YAML [#359](https://github.com/juanfont/headscale/pull/359)
- Users can now use emails in ACL's groups [#372](https://github.com/juanfont/headscale/issues/372)
- Add shorthand aliases for commands and subcommands [#376](https://github.com/juanfont/headscale/pull/376)
- Add `/windows` endpoint for Windows configuration instructions + registry file download [#392](https://github.com/juanfont/headscale/pull/392)
- Added embedded DERP server into Headscale [#388](https://github.com/juanfont/headscale/pull/388)

### Changes

- Fix a bug were the same IP could be assigned to multiple hosts if joined in quick succession [#346](https://github.com/juanfont/headscale/pull/346)
- Simplify the code behind registration of machines [#366](https://github.com/juanfont/headscale/pull/366)
  - Nodes are now only written to database if they are registrated successfully
- Fix a limitation in the ACLs that prevented users to write rules with `*` as source [#374](https://github.com/juanfont/headscale/issues/374)
- Reduce the overhead of marshal/unmarshal for Hostinfo, routes and endpoints by using specific types in Machine [#371](https://github.com/juanfont/headscale/pull/371)
- Apply normalization function to FQDN on hostnames when hosts registers and retrieve informations [#363](https://github.com/juanfont/headscale/issues/363)

## 0.14.0 (2022-02-24)

**UPCOMING ### BREAKING
From the **next\*\* version (`0.15.0`), all machines will be able to communicate regardless of
if they are in the same namespace. This means that the behaviour currently limited to ACLs
will become default. From version `0.15.0`, all limitation of communications must be done
with ACLs.

This is a part of aligning `headscale`'s behaviour with Tailscale's upstream behaviour.

### BREAKING

- ACLs have been rewritten to align with the bevaviour Tailscale Control Panel provides. **NOTE:** This is only active if you use ACLs
  - Namespaces are now treated as Users
  - All machines can communicate with all machines by default
  - Tags should now work correctly and adding a host to Headscale should now reload the rules.
  - The documentation have a [fictional example](docs/acls.md) that should cover some use cases of the ACLs features

### Features

- Add support for configurable mTLS [docs](docs/tls.md#configuring-mutual-tls-authentication-mtls) [#297](https://github.com/juanfont/headscale/pull/297)

### Changes

- Remove dependency on CGO (switch from CGO SQLite to pure Go) [#346](https://github.com/juanfont/headscale/pull/346)

**0.13.0 (2022-02-18):**

### Features

- Add IPv6 support to the prefix assigned to namespaces
- Add API Key support
  - Enable remote control of `headscale` via CLI [docs](docs/remote-cli.md)
  - Enable HTTP API (beta, subject to change)
- OpenID Connect users will be mapped per namespaces
  - Each user will get its own namespace, created if it does not exist
  - `oidc.domain_map` option has been removed
  - `strip_email_domain` option has been added (see [config-example.yaml](./config_example.yaml))

### Changes

- `ip_prefix` is now superseded by `ip_prefixes` in the configuration [#208](https://github.com/juanfont/headscale/pull/208)
- Upgrade `tailscale` (1.20.4) and other dependencies to latest [#314](https://github.com/juanfont/headscale/pull/314)
- fix swapped machine<->namespace labels in `/metrics` [#312](https://github.com/juanfont/headscale/pull/312)
- remove key-value based update mechanism for namespace changes [#316](https://github.com/juanfont/headscale/pull/316)

**0.12.4 (2022-01-29):**

### Changes

- Make gRPC Unix Socket permissions configurable [#292](https://github.com/juanfont/headscale/pull/292)
- Trim whitespace before reading Private Key from file [#289](https://github.com/juanfont/headscale/pull/289)
- Add new command to generate a private key for `headscale` [#290](https://github.com/juanfont/headscale/pull/290)
- Fixed issue where hosts deleted from control server may be written back to the database, as long as they are connected to the control server [#278](https://github.com/juanfont/headscale/pull/278)

## 0.12.3 (2022-01-13)

### Changes

- Added Alpine container [#270](https://github.com/juanfont/headscale/pull/270)
- Minor updates in dependencies [#271](https://github.com/juanfont/headscale/pull/271)

## 0.12.2 (2022-01-11)

Happy New Year!

### Changes

- Fix Docker release [#258](https://github.com/juanfont/headscale/pull/258)
- Rewrite main docs [#262](https://github.com/juanfont/headscale/pull/262)
- Improve Docker docs [#263](https://github.com/juanfont/headscale/pull/263)

## 0.12.1 (2021-12-24)

(We are skipping 0.12.0 to correct a mishap done weeks ago with the version tagging)

### BREAKING

- Upgrade to Tailscale 1.18 [#229](https://github.com/juanfont/headscale/pull/229)
  - This change requires a new format for private key, private keys are now generated automatically:
    1. Delete your current key
    2. Restart `headscale`, a new key will be generated.
    3. Restart all Tailscale clients to fetch the new key

### Changes

- Unify configuration example [#197](https://github.com/juanfont/headscale/pull/197)
- Add stricter linting and formatting [#223](https://github.com/juanfont/headscale/pull/223)

### Features

- Add gRPC and HTTP API (HTTP API is currently disabled) [#204](https://github.com/juanfont/headscale/pull/204)
- Use gRPC between the CLI and the server [#206](https://github.com/juanfont/headscale/pull/206), [#212](https://github.com/juanfont/headscale/pull/212)
- Beta OpenID Connect support [#126](https://github.com/juanfont/headscale/pull/126), [#227](https://github.com/juanfont/headscale/pull/227)

## 0.11.0 (2021-10-25)

### BREAKING

- Make headscale fetch DERP map from URL and file [#196](https://github.com/juanfont/headscale/pull/196)
