# CHANGELOG

**0.12.0:**

**BREAKING**:
- Upgrade to Tailscale 1.18 [#229](https://github.com/juanfont/headscale/pull/229)
    - This change requires a new format for private key, private keys are now generated automatically:
      1. Delete your current key 
      2. Restart `headscale`, a new key will be generated.
      3. Restart all Tailscale clients to fetch the new key



**Changes**:
- Unifi configuration example [#197](https://github.com/juanfont/headscale/pull/197)
- Add gRPC and API (API is currently unavailable) [#204](https://github.com/juanfont/headscale/pull/204)
- Use gRPC between the CLI and the server [#206](https://github.com/juanfont/headscale/pull/206) [#212](https://github.com/juanfont/headscale/pull/212)
- Add stricter linting and formatting [#223](https://github.com/juanfont/headscale/pull/223)
