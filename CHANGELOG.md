# CHANGELOG

## 0.23.0 (2023-XX-XX)

This release is mainly a code reorganisation and refactoring, significantly improving the maintainability of the codebase. This should allow us to improve further and make it easier for the maintainers to keep on top of the project.

**Please remember to always back up your database between versions**

#### Here is a short summary of the broad topics of changes:

Code has been organised into modules, reducing use of global variables/objects, isolating concerns and “putting the right things in the logical place”.

The new [policy](https://github.com/juanfont/headscale/tree/main/hscontrol/policy) and [mapper](https://github.com/juanfont/headscale/tree/main/hscontrol/mapper) package, containing the ACL/Policy logic and the logic for creating the data served to clients (the network “map”) has been rewritten and improved. This change has allowed us to finish SSH support and add additional tests throughout the code to ensure correctness.

The [“poller”, or streaming logic](https://github.com/juanfont/headscale/blob/main/hscontrol/poll.go) has been rewritten and instead of keeping track of the latest updates, checking at a fixed interval, it now uses go channels, implemented in our new [notifier](https://github.com/juanfont/headscale/tree/main/hscontrol/notifier) package and it allows us to send updates to connected clients immediately. This should both improve performance and potential latency before a client picks up an update.

Headscale now supports sending “delta” updates, thanks to the new mapper and poller logic, allowing us to only inform nodes about new nodes, changed nodes and removed nodes. Previously we sent the entire state of the network every time an update was due.

While we have a pretty good [test harness](https://github.com/search?q=repo%3Ajuanfont%2Fheadscale+path%3A_test.go&type=code) for validating our changes, we have rewritten over [10000 lines of code](https://github.com/juanfont/headscale/compare/b01f1f1867136d9b2d7b1392776eb363b482c525...main) and bugs are expected. We need help testing this release. In addition, while we think the performance should in general be better, there might be regressions in parts of the platform, particularly where we prioritised correctness over speed.

There are also several bugfixes that has been encountered and fixed as part of implementing these changes, particularly
after improving the test harness as part of adopting [#1460](https://github.com/juanfont/headscale/pull/1460).

### BREAKING

Code reorganisation, a lot of code has moved, please review the following PRs accordingly [#1473](https://github.com/juanfont/headscale/pull/1473)
API: Machine is now Node [#1553](https://github.com/juanfont/headscale/pull/1553)

### Changes

Make the OIDC callback page better [#1484](https://github.com/juanfont/headscale/pull/1484)
SSH support [#1487](https://github.com/juanfont/headscale/pull/1487)
State management has been improved [#1492](https://github.com/juanfont/headscale/pull/1492)
Use error group handling to ensure tests actually pass [#1535](https://github.com/juanfont/headscale/pull/1535) based on [#1460](https://github.com/juanfont/headscale/pull/1460)
Fix hang on SIGTERM [#1492](https://github.com/juanfont/headscale/pull/1492) taken from [#1480](https://github.com/juanfont/headscale/pull/1480)
Send logs to stderr by default [#1524](https://github.com/juanfont/headscale/pull/1524)
Restore foreign keys and add constraints [#1562](https://github.com/juanfont/headscale/pull/1562)

## 0.22.3 (2023-05-12)

### Changes

- Added missing ca-certificates in Docker image [#1463](https://github.com/juanfont/headscale/pull/1463)

## 0.22.2 (2023-05-10)

### Changes

- Add environment flags to enable pprof (profiling) [#1382](https://github.com/juanfont/headscale/pull/1382)
  - Profiles are continously generated in our integration tests.
- Fix systemd service file location in `.deb` packages [#1391](https://github.com/juanfont/headscale/pull/1391)
- Improvements on Noise implementation [#1379](https://github.com/juanfont/headscale/pull/1379)
- Replace node filter logic, ensuring nodes with access can see eachother [#1381](https://github.com/juanfont/headscale/pull/1381)
- Disable (or delete) both exit routes at the same time [#1428](https://github.com/juanfont/headscale/pull/1428)
- Ditch distroless for Docker image, create default socket dir in `/var/run/headscale` [#1450](https://github.com/juanfont/headscale/pull/1450)

## 0.22.1 (2023-04-20)

### Changes

- Fix issue where systemd could not bind to port 80 [#1365](https://github.com/juanfont/headscale/pull/1365)

## 0.22.0 (2023-04-20)

### Changes

- Add `.deb` packages to release process [#1297](https://github.com/juanfont/headscale/pull/1297)
- Update and simplify the documentation to use new `.deb` packages [#1349](https://github.com/juanfont/headscale/pull/1349)
- Add 32-bit Arm platforms to release process [#1297](https://github.com/juanfont/headscale/pull/1297)
- Fix longstanding bug that would prevent "\*" from working properly in ACLs (issue [#699](https://github.com/juanfont/headscale/issues/699)) [#1279](https://github.com/juanfont/headscale/pull/1279)
- Fix issue where IPv6 could not be used in, or while using ACLs (part of [#809](https://github.com/juanfont/headscale/issues/809)) [#1339](https://github.com/juanfont/headscale/pull/1339)
- Target Go 1.20 and Tailscale 1.38 for Headscale [#1323](https://github.com/juanfont/headscale/pull/1323)

## 0.21.0 (2023-03-20)

### Changes

- Adding "configtest" CLI command. [#1230](https://github.com/juanfont/headscale/pull/1230)
- Add documentation on connecting with iOS to `/apple` [#1261](https://github.com/juanfont/headscale/pull/1261)
- Update iOS compatibility and added documentation for iOS [#1264](https://github.com/juanfont/headscale/pull/1264)
- Allow to delete routes [#1244](https://github.com/juanfont/headscale/pull/1244)

## 0.20.0 (2023-02-03)

### Changes

- Fix wrong behaviour in exit nodes [#1159](https://github.com/juanfont/headscale/pull/1159)
- Align behaviour of `dns_config.restricted_nameservers` to tailscale [#1162](https://github.com/juanfont/headscale/pull/1162)
- Make OpenID Connect authenticated client expiry time configurable [#1191](https://github.com/juanfont/headscale/pull/1191)
  - defaults to 180 days like Tailscale SaaS
  - adds option to use the expiry time from the OpenID token for the node (see config-example.yaml)
- Set ControlTime in Map info sent to nodes [#1195](https://github.com/juanfont/headscale/pull/1195)
- Populate Tags field on Node updates sent [#1195](https://github.com/juanfont/headscale/pull/1195)

## 0.19.0 (2023-01-29)

### BREAKING

- Rename Namespace to User [#1144](https://github.com/juanfont/headscale/pull/1144)
  - **BACKUP your database before upgrading**
- Command line flags previously taking `--namespace` or `-n` will now require `--user` or `-u`

## 0.18.0 (2023-01-14)

### Changes

- Reworked routing and added support for subnet router failover [#1024](https://github.com/juanfont/headscale/pull/1024)
- Added an OIDC AllowGroups Configuration options and authorization check [#1041](https://github.com/juanfont/headscale/pull/1041)
- Set `db_ssl` to false by default [#1052](https://github.com/juanfont/headscale/pull/1052)
- Fix duplicate nodes due to incorrect implementation of the protocol [#1058](https://github.com/juanfont/headscale/pull/1058)
- Report if a machine is online in CLI more accurately [#1062](https://github.com/juanfont/headscale/pull/1062)
- Added config option for custom DNS records [#1035](https://github.com/juanfont/headscale/pull/1035)
- Expire nodes based on OIDC token expiry [#1067](https://github.com/juanfont/headscale/pull/1067)
- Remove ephemeral nodes on logout [#1098](https://github.com/juanfont/headscale/pull/1098)
- Performance improvements in ACLs [#1129](https://github.com/juanfont/headscale/pull/1129)
- OIDC client secret can be passed via a file [#1127](https://github.com/juanfont/headscale/pull/1127)

## 0.17.1 (2022-12-05)

### Changes

- Correct typo on macOS standalone profile link [#1028](https://github.com/juanfont/headscale/pull/1028)
- Update platform docs with Fast User Switching [#1016](https://github.com/juanfont/headscale/pull/1016)

## 0.17.0 (2022-11-26)

### BREAKING

- `noise.private_key_path` has been added and is required for the new noise protocol.
- Log level option `log_level` was moved to a distinct `log` config section and renamed to `level` [#768](https://github.com/juanfont/headscale/pull/768)
- Removed Alpine Linux container image [#962](https://github.com/juanfont/headscale/pull/962)

### Important Changes

- Added support for Tailscale TS2021 protocol [#738](https://github.com/juanfont/headscale/pull/738)
- Add experimental support for [SSH ACL](https://tailscale.com/kb/1018/acls/#tailscale-ssh) (see docs for limitations) [#847](https://github.com/juanfont/headscale/pull/847)
  - Please note that this support should be considered _partially_ implemented
  - SSH ACLs status:
    - Support `accept` and `check` (SSH can be enabled and used for connecting and authentication)
    - Rejecting connections **are not supported**, meaning that if you enable SSH, then assume that _all_ `ssh` connections **will be allowed**.
    - If you decied to try this feature, please carefully managed permissions by blocking port `22` with regular ACLs or do _not_ set `--ssh` on your clients.
    - We are currently improving our testing of the SSH ACLs, help us get an overview by testing and giving feedback.
  - This feature should be considered dangerous and it is disabled by default. Enable by setting `HEADSCALE_EXPERIMENTAL_FEATURE_SSH=1`.

### Changes

- Add ability to specify config location via env var `HEADSCALE_CONFIG` [#674](https://github.com/juanfont/headscale/issues/674)
- Target Go 1.19 for Headscale [#778](https://github.com/juanfont/headscale/pull/778)
- Target Tailscale v1.30.0 to build Headscale [#780](https://github.com/juanfont/headscale/pull/780)
- Give a warning when running Headscale with reverse proxy improperly configured for WebSockets [#788](https://github.com/juanfont/headscale/pull/788)
- Fix subnet routers with Primary Routes [#811](https://github.com/juanfont/headscale/pull/811)
- Added support for JSON logs [#653](https://github.com/juanfont/headscale/issues/653)
- Sanitise the node key passed to registration url [#823](https://github.com/juanfont/headscale/pull/823)
- Add support for generating pre-auth keys with tags [#767](https://github.com/juanfont/headscale/pull/767)
- Add support for evaluating `autoApprovers` ACL entries when a machine is registered [#763](https://github.com/juanfont/headscale/pull/763)
- Add config flag to allow Headscale to start if OIDC provider is down [#829](https://github.com/juanfont/headscale/pull/829)
- Fix prefix length comparison bug in AutoApprovers route evaluation [#862](https://github.com/juanfont/headscale/pull/862)
- Random node DNS suffix only applied if names collide in namespace. [#766](https://github.com/juanfont/headscale/issues/766)
- Remove `ip_prefix` configuration option and warning [#899](https://github.com/juanfont/headscale/pull/899)
- Add `dns_config.override_local_dns` option [#905](https://github.com/juanfont/headscale/pull/905)
- Fix some DNS config issues [#660](https://github.com/juanfont/headscale/issues/660)
- Make it possible to disable TS2019 with build flag [#928](https://github.com/juanfont/headscale/pull/928)
- Fix OIDC registration issues [#960](https://github.com/juanfont/headscale/pull/960) and [#971](https://github.com/juanfont/headscale/pull/971)
- Add support for specifying NextDNS DNS-over-HTTPS resolver [#940](https://github.com/juanfont/headscale/pull/940)
- Make more sslmode available for postgresql connection [#927](https://github.com/juanfont/headscale/pull/927)

## 0.16.4 (2022-08-21)

### Changes

- Add ability to connect to PostgreSQL over TLS/SSL [#745](https://github.com/juanfont/headscale/pull/745)
- Fix CLI registration of expired machines [#754](https://github.com/juanfont/headscale/pull/754)

## 0.16.3 (2022-08-17)

### Changes

- Fix issue with OIDC authentication [#747](https://github.com/juanfont/headscale/pull/747)

## 0.16.2 (2022-08-14)

### Changes

- Fixed bugs in the client registration process after migration to NodeKey [#735](https://github.com/juanfont/headscale/pull/735)

## 0.16.1 (2022-08-12)

### Changes

- Updated dependencies (including the library that lacked armhf support) [#722](https://github.com/juanfont/headscale/pull/722)
- Fix missing group expansion in function `excludeCorretlyTaggedNodes` [#563](https://github.com/juanfont/headscale/issues/563)
- Improve registration protocol implementation and switch to NodeKey as main identifier [#725](https://github.com/juanfont/headscale/pull/725)
- Add ability to connect to PostgreSQL via unix socket [#734](https://github.com/juanfont/headscale/pull/734)

## 0.16.0 (2022-07-25)

**Note:** Take a backup of your database before upgrading.

### BREAKING

- Old ACL syntax is no longer supported ("users" & "ports" -> "src" & "dst"). Please check [the new syntax](https://tailscale.com/kb/1018/acls/).

### Changes

- **Drop** armhf (32-bit ARM) support. [#609](https://github.com/juanfont/headscale/pull/609)
- Headscale fails to serve if the ACL policy file cannot be parsed [#537](https://github.com/juanfont/headscale/pull/537)
- Fix labels cardinality error when registering unknown pre-auth key [#519](https://github.com/juanfont/headscale/pull/519)
- Fix send on closed channel crash in polling [#542](https://github.com/juanfont/headscale/pull/542)
- Fixed spurious calls to setLastStateChangeToNow from ephemeral nodes [#566](https://github.com/juanfont/headscale/pull/566)
- Add command for moving nodes between namespaces [#362](https://github.com/juanfont/headscale/issues/362)
- Added more configuration parameters for OpenID Connect (scopes, free-form paramters, domain and user allowlist)
- Add command to set tags on a node [#525](https://github.com/juanfont/headscale/issues/525)
- Add command to view tags of nodes [#356](https://github.com/juanfont/headscale/issues/356)
- Add --all (-a) flag to enable routes command [#360](https://github.com/juanfont/headscale/issues/360)
- Fix issue where nodes was not updated across namespaces [#560](https://github.com/juanfont/headscale/pull/560)
- Add the ability to rename a nodes name [#560](https://github.com/juanfont/headscale/pull/560)
  - Node DNS names are now unique, a random suffix will be added when a node joins
  - This change contains database changes, remember to **backup** your database before upgrading
- Add option to enable/disable logtail (Tailscale's logging infrastructure) [#596](https://github.com/juanfont/headscale/pull/596)
  - This change disables the logs by default
- Use [Prometheus]'s duration parser, supporting days (`d`), weeks (`w`) and years (`y`) [#598](https://github.com/juanfont/headscale/pull/598)
- Add support for reloading ACLs with SIGHUP [#601](https://github.com/juanfont/headscale/pull/601)
- Use new ACL syntax [#618](https://github.com/juanfont/headscale/pull/618)
- Add -c option to specify config file from command line [#285](https://github.com/juanfont/headscale/issues/285) [#612](https://github.com/juanfont/headscale/pull/601)
- Add configuration option to allow Tailscale clients to use a random WireGuard port. [kb/1181/firewalls](https://tailscale.com/kb/1181/firewalls) [#624](https://github.com/juanfont/headscale/pull/624)
- Improve obtuse UX regarding missing configuration (`ephemeral_node_inactivity_timeout` not set) [#639](https://github.com/juanfont/headscale/pull/639)
- Fix nodes being shown as 'offline' in `tailscale status` [#648](https://github.com/juanfont/headscale/pull/648)
- Improve shutdown behaviour [#651](https://github.com/juanfont/headscale/pull/651)
- Drop Gin as web framework in Headscale [648](https://github.com/juanfont/headscale/pull/648) [677](https://github.com/juanfont/headscale/pull/677)
- Make tailnet node updates check interval configurable [#675](https://github.com/juanfont/headscale/pull/675)
- Fix regression with HTTP API [#684](https://github.com/juanfont/headscale/pull/684)
- nodes ls now print both Hostname and Name(Issue [#647](https://github.com/juanfont/headscale/issues/647) PR [#687](https://github.com/juanfont/headscale/pull/687))

## 0.15.0 (2022-03-20)

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
- Added embedded DERP (and STUN) server into Headscale [#388](https://github.com/juanfont/headscale/pull/388)

### Changes

- Fix a bug were the same IP could be assigned to multiple hosts if joined in quick succession [#346](https://github.com/juanfont/headscale/pull/346)
- Simplify the code behind registration of machines [#366](https://github.com/juanfont/headscale/pull/366)
  - Nodes are now only written to database if they are registrated successfully
- Fix a limitation in the ACLs that prevented users to write rules with `*` as source [#374](https://github.com/juanfont/headscale/issues/374)
- Reduce the overhead of marshal/unmarshal for Hostinfo, routes and endpoints by using specific types in Machine [#371](https://github.com/juanfont/headscale/pull/371)
- Apply normalization function to FQDN on hostnames when hosts registers and retrieve informations [#363](https://github.com/juanfont/headscale/issues/363)
- Fix a bug that prevented the use of `tailscale logout` with OIDC [#508](https://github.com/juanfont/headscale/issues/508)
- Added Tailscale repo HEAD and unstable releases channel to the integration tests targets [#513](https://github.com/juanfont/headscale/pull/513)

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
  - `strip_email_domain` option has been added (see [config-example.yaml](./config-example.yaml))

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
