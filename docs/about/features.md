# Features

Headscale aims to implement a self-hosted, open source alternative to the Tailscale control server. Headscale's goal is
to provide self-hosters and hobbyists with an open-source server they can use for their projects and labs. This page
provides on overview of Headscale's feature and compatibility with the Tailscale control server:

- [x] Full "base" support of Tailscale's features
- [x] [Node registration](../ref/registration.md)
    - [x] [Web authentication](../ref/registration.md#web-authentication)
    - [x] [Pre authenticated key](../ref/registration.md#pre-authenticated-key)
- [x] [DNS](../ref/dns.md)
    - [x] [MagicDNS](https://tailscale.com/docs/features/magicdns)
    - [x] [Global and restricted nameservers (split DNS)](https://tailscale.com/docs/reference/dns-in-tailscale#nameservers)
    - [x] [search domains](https://tailscale.com/docs/reference/dns-in-tailscale#search-domains)
    - [x] [Extra DNS records (Headscale only)](../ref/dns.md#setting-extra-dns-records)
- [x] [Taildrop (File Sharing)](https://tailscale.com/docs/features/taildrop)
- [x] [Tags](../ref/tags.md)
- [x] [Routes](../ref/routes.md)
    - [x] [Subnet routers](../ref/routes.md#subnet-router)
    - [x] [Exit nodes](../ref/routes.md#exit-node)
- [x] Dual stack (IPv4 and IPv6)
- [x] Ephemeral nodes
- [x] Embedded [DERP server](../ref/derp.md)
- [x] Access control lists ([GitHub label "policy"](https://github.com/juanfont/headscale/labels/policy%20%F0%9F%93%9D))
    - [x] ACL management via API
    - [x] Some [Autogroups](../ref/policy.md#autogroups)
    - [x] [Auto approvers](https://tailscale.com/docs/reference/syntax/policy-file#auto-approvers) for [subnet
      routers](../ref/routes.md#automatically-approve-routes-of-a-subnet-router) and [exit
      nodes](../ref/routes.md#automatically-approve-an-exit-node-with-auto-approvers)
    - [x] [Tailscale SSH](https://tailscale.com/docs/features/tailscale-ssh)
- [x] [Node registration using Single-Sign-On (OpenID Connect)](../ref/oidc.md) ([GitHub label "OIDC"](https://github.com/juanfont/headscale/labels/OIDC))
    - [x] Basic registration
    - [x] Update user profile from identity provider
    - [ ] OIDC groups cannot be used in ACLs
- [ ] [Funnel](https://tailscale.com/docs/features/tailscale-funnel) ([#1040](https://github.com/juanfont/headscale/issues/1040))
- [ ] [Serve](https://tailscale.com/docs/features/tailscale-serve) ([#1234](https://github.com/juanfont/headscale/issues/1921))
- [ ] [Network flow logs](https://tailscale.com/docs/features/logging/network-flow-logs) ([#1687](https://github.com/juanfont/headscale/issues/1687))
