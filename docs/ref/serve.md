# Tailscale Serve and HTTPS certificates

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) lets a
node expose a local service (a reverse proxy, file server, or static text) to
the rest of your tailnet. Serve runs almost entirely on the node — the
`ServeConfig` lives on the client, not on Headscale.

There are two tiers:

| Mode | Needs from Headscale | Status |
| --- | --- | --- |
| `tailscale serve --http=...` (plain HTTP) | MagicDNS | Works out of the box |
| `tailscale serve [--https=...]` and `tailscale cert` | Per-node TLS certificates | Requires the setup on this page |
| `tailscale funnel` (public internet) | Tailscale's ingress relays | **Not supported** — see [below](#funnel-is-not-supported) |

Plain HTTP serve only relies on [MagicDNS](dns.md) and works without any extra
configuration. Serving over **HTTPS** needs a TLS certificate for the node's
MagicDNS name (`<node>.<base_domain>`), which the client obtains itself from
[Let's Encrypt](https://letsencrypt.org/) using an ACME **DNS-01** challenge.
Headscale's role is to answer that challenge.

## How certificate provisioning works

`tailscale cert` (used implicitly by `tailscale serve --https`) cannot use the
HTTP-01 or TLS-ALPN-01 challenge types: those require Let's Encrypt to connect
**to the node**, and tailnet nodes are not publicly reachable. Only the DNS-01
challenge works, because it only requires a public DNS **TXT** record:

1. The node sees its FQDN advertised in `MapResponse.DNSConfig.CertDomains` and
   enables `tailscale cert` / `tailscale serve --https`.
2. The node runs ACME against Let's Encrypt and generates all keys locally —
   Headscale never sees the certificate or the ACME account key.
3. To answer the DNS-01 challenge, the node sends the challenge value to
   Headscale's `/machine/set-dns` endpoint.
4. Headscale publishes it as a TXT record at
   `_acme-challenge.<node>.<base_domain>` from a small **embedded
   authoritative DNS server**.
5. Let's Encrypt resolves that record over the public internet and issues the
   certificate.

For step 5 to succeed, `base_domain` must be a **real, publicly delegated
domain** whose DNS queries reach Headscale.

## Requirements

- [MagicDNS](dns.md) is enabled and `dns.base_domain` is set.
- `dns.base_domain` is a domain you own and can delegate (it cannot be a made-up
  name such as `example.internal`).
- Headscale is reachable from the public internet on the DNS port (UDP and TCP)
  configured below. Binding a privileged port such as `:53` requires
  `CAP_NET_BIND_SERVICE` or running as root.

## Configuration

```yaml title="config.yaml"
dns:
  magic_dns: true
  base_domain: ts.example.com

  https_certs:
    # Enable per-node HTTPS certificate provisioning (tailscale serve /
    # tailscale cert). Headscale advertises CertDomains to nodes and runs an
    # authoritative DNS server for base_domain to answer ACME DNS-01
    # challenges.
    enabled: true

    # Address the embedded authoritative DNS server listens on (UDP and TCP)
    # for ACME challenge queries from public resolvers.
    listen_addr: ":53"

    # FQDN of this authoritative DNS server, used in SOA and NS answers. When
    # empty it defaults to "ns." + base_domain.
    nameserver: "ns1.example.com"
```

## Delegate the zone

Headscale only answers the `_acme-challenge` TXT lookups (and the zone's
SOA/NS records) for `base_domain`. Node `A`/`AAAA` records stay internal to the
tailnet via MagicDNS and are intentionally **not** served publicly.

At your domain registrar or parent DNS zone, delegate `base_domain` to
Headscale by pointing its `NS` records at the configured `nameserver`, and make
sure that name resolves to Headscale's public IP. For example, for
`base_domain: ts.example.com` and `nameserver: ns1.example.com`:

```dns
ts.example.com.   NS   ns1.example.com.
ns1.example.com.  A    203.0.113.10        ; Headscale's public IP
```

## Usage

Once enabled and delegated, use Tailscale's CLI on a node as usual:

```console
# Obtain a certificate for this node's MagicDNS name
$ sudo tailscale cert

# Reverse-proxy a local service over HTTPS
$ tailscale serve --bg 8080

# Serve over plain HTTP (works without https_certs)
$ tailscale serve --http=80 --bg 8080
```

## Security notes

- A node may only set the ACME challenge record for **its own** FQDN;
  `/machine/set-dns` rejects any other name.
- Certificate and ACME account private keys are generated and stored on the
  node. Headscale only stores the short-lived challenge TXT value, which is
  evicted automatically after the challenge completes.

## Funnel is not supported

[Tailscale Funnel](https://tailscale.com/docs/features/tailscale-funnel)
exposes a node's service to the public internet through Tailscale-operated
ingress relays. Headscale cannot provide that infrastructure, so Funnel is not
supported. See [#1040](https://github.com/juanfont/headscale/issues/1040).
