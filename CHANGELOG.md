# CHANGELOG

**TBD (TBD):**

**0.13.0 (2022-xx-xx):**

**Features**:

- Add IPv6 support to the prefix assigned to namespaces

**Changes**:

- `ip_prefix` is now superseded by `ip_prefixes` in the configuration [#208](https://github.com/juanfont/headscale/pull/208)

**0.12.4 (2022-01-29):**

**Changes**:

- Make gRPC Unix Socket permissions configurable [#292](https://github.com/juanfont/headscale/pull/292)
- Trim whitespace before reading Private Key from file [#289](https://github.com/juanfont/headscale/pull/289)
- Add new command to generate a private key for `headscale` [#290](https://github.com/juanfont/headscale/pull/290)
- Fixed issue where hosts deleted from control server may be written back to the database, as long as they are connected to the control server [#278](https://github.com/juanfont/headscale/pull/278)

**0.12.3 (2022-01-13):**

**Changes**:

- Added Alpine container [#270](https://github.com/juanfont/headscale/pull/270)
- Minor updates in dependencies [#271](https://github.com/juanfont/headscale/pull/271)

**0.12.2 (2022-01-11):**

Happy New Year!

**Changes**:

- Fix Docker release [#258](https://github.com/juanfont/headscale/pull/258)
- Rewrite main docs [#262](https://github.com/juanfont/headscale/pull/262)
- Improve Docker docs [#263](https://github.com/juanfont/headscale/pull/263)

**0.12.1 (2021-12-24):**

(We are skipping 0.12.0 to correct a mishap done weeks ago with the version tagging)

**BREAKING**:

- Upgrade to Tailscale 1.18 [#229](https://github.com/juanfont/headscale/pull/229)
  - This change requires a new format for private key, private keys are now generated automatically:
    1. Delete your current key
    2. Restart `headscale`, a new key will be generated.
    3. Restart all Tailscale clients to fetch the new key

**Changes**:

- Unify configuration example [#197](https://github.com/juanfont/headscale/pull/197)
- Add stricter linting and formatting [#223](https://github.com/juanfont/headscale/pull/223)

**Features**:

- Add gRPC and HTTP API (HTTP API is currently disabled) [#204](https://github.com/juanfont/headscale/pull/204)
- Use gRPC between the CLI and the server [#206](https://github.com/juanfont/headscale/pull/206), [#212](https://github.com/juanfont/headscale/pull/212)
- Beta OpenID Connect support [#126](https://github.com/juanfont/headscale/pull/126), [#227](https://github.com/juanfont/headscale/pull/227)

**0.11.0 (2021-10-25):**

**BREAKING**:

- Make headscale fetch DERP map from URL and file [#196](https://github.com/juanfont/headscale/pull/196)
