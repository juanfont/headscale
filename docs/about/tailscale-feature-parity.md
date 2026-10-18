# Tailscale Feature Parity — Clean-Room Roadmap

Net-Scale's project aim is to be a better alternative to the Tailscale control
plane and a multi-node evolution of headscale. This document tracks parity with
the Tailscale feature set in a **clean-room** fashion.

## Clean-room policy

1. **Features, not code.** Feature *behaviour* visible to a Tailscale client on
   the wire is the target, described from public documentation and the
   client's observable behaviour. No Tailscale source code, assets, or
   documentation prose are copied.
2. **Wire compatibility wins.** The Tailscale clients are MIT/Apache-2.0 open
   source; a compatible control server must speak the same protocols
   (`Noise`, `tailcfg`, derper). Feature parity is measured against that
   contract, not against Tailscale's admin-console internals.
3. **Independent implementation.** Each feature is designed and implemented
   against headscale's architecture (`hscontrol/state`, `mapper`, `policy/v2`)
   from its public specification.
4. **Trademark hygiene.** Net-Scale does not use the Tailscale or headscale
   marks to imply endorsement.
5. **Extra credit is fine.** Net-Scale-specific features (e.g. OIDC
   `group:<name>` in ACLs, multi-node operation) are outside of parity and
   tracked separately.

## Legend

- ✅ Supported (by upstream headscale or Net-Scale itself)
- 🟡 Partial (config/API surface exists, limits or missing pieces)
- ❌ Not implemented (roadmap item)

## Networking connectivity

| Feature | Status | Notes |
| --- | --- | --- |
| Peer-to-peer WireGuard connections | ✅ | Core protocol, fully compatible |
| End-to-end encryption (WireGuard) | ✅ | Inherited from the client |
| Split tunneling | ✅ | Client-driven; control plane plays no role |
| Subnet routers (advertise/accept routes) | ✅ | With auto-approval via policy |
| HA subnet routers | 🟡 | Multiple routers can advertise the same route; failover semantics depend on clients |
| Exit nodes | ✅ | Including policy-based auto-approval |
| 4via6 subnet routers (IP collision resolution) | 🟡 | Supported in headscale's routing model |
| MagicDNS (short host names) | ✅ | Global DNS config + per-node overrides |
| Search domains | ✅ | Configured via DNS settings |
| Custom DNS resolvers / split DNS | ✅ | |
| DERP relay network | ✅ | Embedded derper; self-hosted relays supported |

## Least privilege access

| Feature | Status | Notes |
| --- | --- | --- |
| ACLs (RBAC policy file) | ✅ | `policy/v2` engine, HuJSON policy file |
| Grants (recommended access model) | ✅ | Same feature surface as Tailscale's grants |
| ACL tests | ✅ | `tests`/`sshTests` in the policy file |
| ACL tags (service provisioning identity) | ✅ | Tags XOR user ownership enforced |
| Tag owners | ✅ | IP/user/group-based tag authorization |
| Groups (policy-defined) | ✅ | Local `group:<name>` principals |
| **OIDC groups in policies** | ✅ | **Net-Scale-specific**: IdP `groups` claim as `group:<name>` — beyond upstream |
| Autogroups (`self`, `member`, `internet`) | ✅ | |
| Auto approvers (routes, tags, DNS) | ✅ | |
| GitOps for policies (CI/CD managed policy file) | ✅ | Policy file on disk / API; works with any Git workflow |
| SSH access control (Tailscale SSH) | ✅ | via grants/check rules |
| Funnel (public internet sharing) | ❌ | Roadmap; requires relay + HTTPS cert lifecycle for public services |
| Serve (local service sharing) | ❌ | Client-side feature; control plane needs policy hooks |
| Node sharing across tailnets | ❌ | Roadmap; big coordination feature |
| On-demand access (Just-in-Time partners) | ❌ | Depends on partner ecosystem; the underlying time-bound grants are already supported |
| Separation of admin duties (role-based admin) | 🟡 | API keys/OAuth clients are scoped; full admin RBAC is roadmap |

## Identity & user management

| Feature | Status | Notes |
| --- | --- | --- |
| SSO via OIDC/SAML-style IdP | ✅ | OIDC providers fully supported |
| Custom OIDC provider | ✅ | Any standard provider |
| OIDC allowed groups (login gating) | ✅ | `allowed_groups` check on login |
| Custom authentication (key expiry) periods | ✅ | Per-user/per-node expiry settings |
| User approval | ✅ | Interactive registration approval |
| User & group provisioning (SCIM) | 🟡 | Users/groups manageable via API and OIDC groups; directory sync server is roadmap |
| Machine users / service accounts | 🟡 | Tagged nodes serve this role today |

## Device & posture management

| Feature | Status | Notes |
| --- | --- | --- |
| Auth keys / pre-auth keys | ✅ | Reusable + ephemeral keys |
| OAuth clients (scoped API tokens) | ✅ | Client-credentials grant with scopes and tags |
| Device approval | ✅ | |
| Key expiry management | ✅ | |
| Route approval management (admin) | ✅ | |
| Tailnet lock (key verification chain) | ❌ | Protocol work required; roadmap |
| Device posture (attributes in policy) | ❌ | Roadmap: node capabilities/attributes in policy evaluation |
| EDR/posture integrations (CrowdStrike etc.) | ❌ | Depends on device posture |
| MDM/system policies for clients | 🟡 | Client-side feature; config examples doable in docs |

## Services management

| Feature | Status | Notes |
| --- | --- | --- |
| HTTPS certificates (MagicDNS cert provisioning) | ✅ | ACME issuance for MagicDNS names |
| tsnet (embed control-plane client in Go apps) | 🟡 | Possible via tailscale library; not packaged |
| Taildrop (file transfer) | 🟡 | Client feature; works with Net-Scale as control plane |
| Services inventory/monitoring | ❌ | Roadmap |

## Monitoring & audit

| Feature | Status | Notes |
| --- | --- | --- |
| Configuration audit logging | ✅ | Net-Scale-specific MVP: `audit:` config section, append-only JSONL record (`hscontrol/audit`) of user, tag, policy and OIDC-group changes with size-based rotation; SIEM streaming and actor attribution are the next steps |
| Network flow logging | ❌ | Roadmap (enterprise tier in Tailscale) |
| Log streaming (SIEM) | ❌ | Roadmap; build on the audit log work |
| SSH session recording (S3) | ❌ | Roadmap |
| Webhooks (event triggers) | ❌ | Roadmap; natural next step after audit logging |
| Metrics (Prometheus) | ✅ | `/metrics` built in |

## Application networking / integrations

| Feature | Status | Notes |
| --- | --- | --- |
| v1 API (headscale-style) | ✅ | |
| v2 API (Tailscale-compatible) | ✅ | Managed via huma endpoints; OAuth client-credentials |
| Terraform / IaC providers | 🟡 | Works against the v2 API with the upstream provider; Net-Scale-specific resources are roadmap |
| CLI (`headscale`) | ✅ | Full admin + policy CLI incl. `oauth-clients`, mock OIDC |
| Kubernetes operator | 🟡 | Community k8s integrations exist; first-class support is roadmap |

## Net-Scale-specific extras (not in Tailscale)

- OIDC group memberships usable directly in ACL policies via
  `group:<name>` — [docs/ref/oidc-groups.md](../ref/oidc-groups.md).
- Periodic stale-OIDC-group cleanup so IdP-driven revocation converges
  without re-login.
- Multi-node operation is the architectural north star: the control plane is
  structured around `hscontrol/state` so multiple control-plane nodes can be
  introduced without redesign.

## Roadmap order (suggested)

1. **Audit logging + webhooks** — unlocks compliance use cases and is mostly
   control-plane-local work.
2. **Flow logging / log streaming** — pairs with (1) as a system of record.
3. **Funnel + Serve support** — highest user-visible parity gap.
4. **Device posture attributes** — extends `policy/v2` evaluation.
5. **Tailnet lock** — protocol-level work, needs client cooperation.
6. **SCIM/token-based provisioning server** — polish user-management parity.
