# Headscale Threat Model

Snapshot of the unreleased 0.30.0 line. Paths are under `hscontrol/` unless noted. This names what could go wrong, who would do it, and what matters most. It lists no fixes; concrete gaps live in a separate findings list.

## 1. System and scope

Headscale is a self-hosted Tailscale control server for one tailnet on one host (systemd, Docker, or NixOS). It is the trust root. Every node believes what it says about which WireGuard key owns which IP, which peers it may reach, which DNS and relays to use, and whether an SSH login may proceed. Node traffic bypasses it unless the embedded DERP relay is on.

In scope: public router (`app.go`), Noise server (`noise.go`), registration and OIDC (`auth.go`, `oidc.go`), State and NodeStore (`state/`), map streamer (`mapper/`), policy engine (`policy/v2/`), admin APIs (`api/`, `scope/`), database (`db/`), DNS and node certificates (`dns/`), TLS, embedded DERP (`derp/`), metrics listener (`debug.go`), templates, and the release pipeline (`.github/workflows/`, `.goreleaser.yml`, `flake.nix`, `tools/bump`).

Out of scope: `HEADSCALE_DEBUG_*` switches and the NixOS test kit; the local host (socket group, database bypass flag, file permissions); third-party API consumers as software; dev and CI tooling (`cmd/hi`, `integration/`, `servertest/`); Tailscale client bugs; root on the server.

Deployment assumptions: headscale terminates TLS on public port 443; the admin API and OAuth token endpoint share that port; admins are trusted, tailnet users probably but not certainly; all four registration paths are used; relay is mostly Tailscale's public DERP map; node certificates through a DNS provider are on; the metrics listener stays on loopback.

## 2. Trust boundaries

| ID  | Edge                                               | What checks it                                                                                                                                                                                                                                                                                        |
| --- | -------------------------------------------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| B1  | Internet to public router                          | HTTPS, or plain HTTP with a warning. No authentication. 30 s timeouts, 1 MiB bodies. No rate limiting.                                                                                                                                                                                                |
| B2  | Any machine key to Noise tunnel                    | Any client key completes the handshake and gets a private HTTP/2 server (`noise.go:115-141`). Inside, only `/machine/register` serves unregistered keys; every other route needs a registered NodeKey bound to this MachineKey (`noise.go:1064-1075`). 1 MiB body, 30 s read and idle, no per-IP cap. |
| B3  | Registered node to State                           | NodeKey lookup plus MachineKey match. Hostinfo bounded by size and count only. Routes take effect once approved.                                                                                                                                                                                      |
| B4  | State to every visible peer                        | Peers if a rule matches in either direction. A peer receives full Hostinfo, endpoints, public keys, owner email, every extra DNS record, the full DERP map, and filter rules with complete source lists.                                                                                              |
| B5  | Browser to registration, OIDC callback, confirm    | 96-bit auth IDs, single-use state and nonce, CSRF token on confirm, PKCE optional.                                                                                                                                                                                                                    |
| B6  | Headscale and the identity provider                | Identity is issuer plus subject. Claims overwrite name and email on every login. `allowed_*` filters optional. User row written before confirm.                                                                                                                                                       |
| B7  | API client to `/api/v1`, `/api/v2`, token endpoint | Constant-time SHA-256 of random secrets. No rate limit, lockout, or audit log. Admin keys are all-access and can mint more admin keys. OAuth tokens are scope and tag bounded, one hour.                                                                                                              |
| B8  | Node through headscale to DNS provider             | Only the node's own `_acme-challenge` name, four in flight per node. Provider token sits in config.                                                                                                                                                                                                   |
| B9  | Tailscale DERP map URL to all nodes                | Fetched every three hours, no status, size, or schema check, pushed to everyone.                                                                                                                                                                                                                      |
| B11 | DERP clients to embedded relay, `/verify`, STUN    | Admitted if the NodeKey is registered. STUN open.                                                                                                                                                                                                                                                     |
| B13 | Policy document to engine                          | `tagOwners` defines who may claim tags. `TagOwnedByTags` walks the live policy transitively.                                                                                                                                                                                                          |
| B14 | Release pipeline to operator hosts                 | Tag push, goreleaser, GitHub Releases, ghcr.io, Docker Hub. Checksums only, no signatures. Base image by tag.                                                                                                                                                                                         |

Route sources of truth: `app.go` `createRouter`, the `/machine` block in `noise.go`, the Huma registrations in `api/v1` and `api/v2`, the mux in `debug.go`.

## 3. Assets

The Noise private key is the root of trust and has no rotation or revocation path. Next: the TLS key and ACME account, admin API keys, OAuth clients and tokens, pre-auth keys, pending auth IDs, and the policy document, whose `tagOwners` section is tag authority. Node identity records and approved routes decide who is who and where traffic goes. Peer metadata (home IP endpoints, Hostinfo, user emails) is confidential. The DNS provider token controls a public zone and certificate issuance under `base_domain`. The metrics listener is a privileged introspection surface (node records, policy, config). Availability matters less than it looks: WireGuard sessions survive an outage, but joins, key rotation, policy pushes, SSH check mode, node certificates, and embedded relay stop. Release artefacts run on every operator host.

## 4. Attackers

| ID  | Who                                                            | Reaches                                                        | Cannot                                                         |
| --- | -------------------------------------------------------------- | -------------------------------------------------------------- | -------------------------------------------------------------- |
| A1  | Anonymous Internet                                             | B1, B2 (tunnel layer), B5, B11. Every route in `createRouter`. | Read other tunnels, forge server keys, guess a 256-bit secret. |
| A2  | Hostile registered node, possibly a modified client            | A1 plus B3, B4, B8, B11. The `/machine` block in `noise.go`.   | Change policy, see other tunnels, forge peers' keys.           |
| A3  | Hostile tailnet user with an IdP account                       | B5, B6. Becomes A2 per device.                                 | Assert another user's claims.                                  |
| A4  | Holder of a leaked pre-auth key or OAuth secret                | B3 or B7 within the credential's declared limits.              | Anything beyond declared scope, if enforcement holds (T2, T3). |
| A5  | Holder of a leaked admin API key                               | B7 in full. Equivalent to an admin.                            | Read the Noise key or database directly.                       |
| A6  | Compromised dependency: IdP, DERP map source, DNS provider, CA | B6, B8, B9.                                                    |                                                                |
| A7  | Supply-chain adversary                                         | B14.                                                           |                                                                |

Not modelled: root on the host, WireGuard or Noise flaws, client-only bugs, legitimate admins.

## 5. Threats

Entries end with likelihood, impact, priority.

**T1. A leaked admin API key gives silent total control.** Elevation, repudiation. A5 at B7. Keys sit in web-UI configs, CI secrets, and Terraform state. The holder rewrites policy, registers their own machine as any user, mints tagged pre-auth keys, and mints fresh admin keys to outlive revocation. Nothing records which key acted. Evidence: `api/v1/apikeys.go:80-104`; no failed-auth logging in `api/` or `db/`. Medium, High, **High**.

**T2. A scoped OAuth credential escalates to admin through policy and tag ownership.** Elevation. A4 at B7 and B13. In database policy mode, `policy_file` replaces the whole policy including `tagOwners`. Ownership checks read the live policy, so the holder then owns any tag and can mint keys or retag devices. Scope names copy Tailscale's, so operators assume Tailscale's blast radius. Evidence: `api/v2/acl.go:110-160`; `policy/v2/policy.go:1235-1285`. Medium, High, **High**.

**T3. A leaked pre-auth key is a standing join credential.** Spoofing, elevation. A4 at B3. Keys are pasted into cloud-init, Dockerfiles, and CI. The holder joins as the key's user or tags and becomes A2 with that identity's grants. Evidence: v2 default expiry 90 days (`api/v2/keys.go:21`); admin-created key tags unchecked against `tagOwners` (`db/preauth_keys.go:31-46`); reusable keys have no node cap. High, High, **High**.

**T4. A victim completes a registration the attacker started.** Spoofing. A1 at B5 and B6. The attacker runs `tailscale up`, receives `/register/{auth_id}`, and sends the link to a user. The user authenticates at the genuine IdP and lands on the confirm page, which shows an attacker-chosen hostname. One click binds the attacker's machine to the user's identity. An admin approving the wrong auth ID has the same effect. Evidence: `oidc.go:185-194,927-937`; `api/v1/auth.go:77-92`. Medium, High, **High**.

**T5. The identity provider chain admits or confuses users.** Spoofing, elevation. A3 and A6 at B6 and B13. With `allowed_*` unset, anyone who can log in at the IdP joins. Policy names users by name or email, both overwritten from claims. A user who can choose their IdP name or email makes a policy alias ambiguous, which the compiler silently drops, or becomes the sole match when the victim's row is absent. Evidence: `oidc.go:373,389,619-652`; `policy/v2/types.go:391-420`; `compiled.go:431-441`. Medium, High, **High**.

**T6. Re-registration lets a user or node change ownership, tags, or lifetime.** Elevation, tampering. A2 and A3 at B3. Registration reconciles MachineKey, NodeKey, user, tags, and auth method across first join, re-auth, user switch, and key reuse. Any inconsistency grants a device, tag, or lifetime nobody approved. Evidence: a login-registered tagged node is claimable by any user on that machine (`state.go:2883-2894`); client-supplied expiry is stored uncapped (`state.go:3270-3272`); 0.29.7 fixed several such cases. Medium, High, **High**.

**T7. A hostile node steers traffic through routes or names.** Spoofing, tampering. A2 at B3 and B4. A compromised router inside an `autoApprovers` prefix announces a more specific route and is approved automatically. Primary election falls to the lowest node ID when the incumbent is offline, so outlasting the legitimate router wins. Freed MagicDNS names can be taken. Evidence: `policy/v2/policy.go:1351-1399`; `node_store.go:784-869`. Medium, High, **High**.

**T8. The netmap over-discloses peers.** Information disclosure. A2 and A3 at B4. One low-privilege device learns every reachable peer's OS, services, SSH host keys, home IP endpoints, and owner email. Evidence: `types/node.go:1404-1441`; `mapper/mapper.go:68-155`. High, Low to Medium, Medium.

**T9. Anyone exhausts the control plane.** Denial of service. A1 and A2 at B1 to B3. Throwaway machine keys open unlimited tunnels and fill the 1024-entry registration cache, which then refuses every enrolment and OIDC login for 15 minutes. A registered node opens unlimited map sessions. Evidence: no rate-limit code anywhere; `node_conn.go:227-235`; `state.go:1989-2004`. High, Medium, **High**.

**T10. A stolen node key gets Tailscale SSH despite check mode.** Elevation. A2 at B3. Check mode forces re-authentication when a node key is stolen. Any weakness in who may complete a check, how long an approval lasts, or whose word is trusted defeats its purpose. Evidence: `noise.go:401-523,647-724`; `api/v1/auth.go:112-128`. Low to Medium, Medium, Medium.

**T11. The node-certificate path abuses the public zone or its token.** Spoofing, tampering. A2 at B8. Every node can cause TXT writes under `base_domain` and obtain a public certificate for its MagicDNS name, including a name another service used before. The provider token is usually zone-wide, so a config leak or code execution yields the zone. Evidence: `noise.go:925-951`; `types/node.go:855-889`. Low to Medium, High, Medium.

**T12. Theft of the Noise or TLS key yields a lasting fake control plane.** Spoofing. Any file read, at B1 and B2. Nodes pin nothing but `server_url` and the Noise key from `/key`. An attacker with the key and traffic steering maps their own key to victims' IPs and reads everything. No rotation, no revocation. Evidence: `handlers.go:191-224`. Low, Critical, Medium.

**T13. An unvalidated external feed steers or crashes the server.** Tampering, denial of service. A6 at B9. The DERP map arrives from Tailscale unchecked and goes to every node. A hostile source directs relayed traffic through attacker relays (metadata and outages, not plaintext) or sends an unbounded body. Evidence: `derp/derp.go:43-73`. Low, Medium, Low.

**T14. The release pipeline ships a backdoored build.** Tampering. A7 at B14. Consumers cannot tell a tampered artefact from a genuine one, so a compromised token, Action, runner, or dependency reaches every host unnoticed. Evidence: checksums only; base image by tag; `build.yml` runs with `write-all`; one provider from a personal namespace (`go.mod:27`). Controls: SHA-pinned Actions, reproducible builds, vendor hash check. Low, Critical, Medium.

## 6. Priorities

| Priority | Threats                        |
| -------- | ------------------------------ |
| High     | T1, T2, T3, T4, T5, T6, T7, T9 |
| Medium   | T8, T10, T11, T12, T14         |
| Low      | T13                            |

Nothing is Critical. Every path to full control needs a leaked credential, a hostile insider, a compromised dependency, or a file-read bug. Anonymous attackers get denial of service, not control.

Assumptions that move the ranking most:

1. Admin API Internet-reachable. Firewalled, T1 and T2 drop to Medium.
2. Registered nodes may be hostile. Trusted nodes lower or remove T6, T7, T8, T10, T11, and half of T9.
3. OIDC filters often unset. Strict filters drop T5 to Medium.
4. `autoApprovers` in use. Manual approval drops T7 to Medium.
5. Host compromise out of scope. In scope, T12 is the top item.
6. Node certificates on with a zone-wide token. Off, T11 disappears.
7. Policy in the database. File mode drops T2 to Medium.

## 7. Triage rules

- Any file read, path traversal, or config dump is Critical (T12).
- A node-facing path that skips expiry or revocation checks is High.
- A tag-ownership decision resolved from mutable policy is High (T2).
- A bypass of the registration confirm step is High (T4).
- A new field peers receive is Medium (T8); a leak to non-visible peers is High.
- Registration changes in `state.go` need adversarial review (T6).
