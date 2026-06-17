# Tailscale Serve and certificates

[Tailscale Serve](https://tailscale.com/docs/features/tailscale-serve) is a
client-side feature: the Serve configuration and TLS private keys live on the
node, not on Headscale.

Plain HTTP Serve works with MagicDNS. HTTPS Serve and `tailscale cert` require
Headscale to advertise the node's MagicDNS name as certificate-eligible and to
publish ACME DNS-01 TXT challenge records for the node.

## Certificate flow

1. Headscale advertises the node's FQDN in `DNSConfig.CertDomains`.
   This is the client signal that avoids:

   ```console
   HTTPS cert support is not enabled/configured for your tailnet.
   ```

2. The node runs `tailscale cert <node>.<base_domain>` or
   `tailscale serve --https`.
3. The node starts an ACME order locally. Headscale never sees the ACME account
   key, certificate private key, or issued certificate.
4. The node calls Headscale's Noise endpoint `/machine/set-dns` with a
   `TXT` record for `_acme-challenge.<node>.<base_domain>`.
5. Headscale validates that the Noise machine key owns the node key and that
   the requested TXT name belongs to that node's own FQDN.
6. Headscale publishes the TXT RRset through the configured `libdns`
   `RecordSetter`.
7. The client asks the ACME CA to validate DNS-01 and stores the issued
   certificate locally.

## Configuration

```yaml
dns:
  magic_dns: true
  base_domain: example.com

  certificates:
    enabled: true
    provider: "provider-name"
    zone: "example.com"
    ttl: 2m
    propagation_wait: 10s
    provider_config:
      token: "provider-api-token"
```

`dns.certificates.enabled` requires:

- `dns.magic_dns: true`
- `dns.base_domain` set
- `dns.certificates.provider` set
- a Headscale build that registers a matching `libdns` provider factory

`zone` defaults to `dns.base_domain` when empty. `provider_config` is passed
unchanged to the registered provider factory and is omitted from JSON debug
configuration output because it commonly contains API credentials.

## Provider registration

Headscale's core implementation is provider-neutral. It imports only
`github.com/libdns/libdns`; it does not import Cloudflare, Hetzner, Route53, or
any other provider package directly.

A concrete provider package must be included in the build and register a
factory with:

```go
hscontrol.RegisterDNSCertificateProvider("provider-name", func(config map[string]string) (libdns.RecordSetter, error) {
    // Construct and return the provider-specific libdns RecordSetter.
})
```

The factory receives `dns.certificates.provider_config`.

## Security properties

- Nodes can only publish `TXT` records.
- Nodes can only publish `_acme-challenge.<their-node-fqdn>`.
- The Noise machine key must match the node key in the request.
- Concurrent TXT values for the same challenge name are preserved in the RRset
  so overlapping ACME validations do not replace each other.
- Challenge values are retained in memory only for a short period and then
  dropped from Headscale's local RRset cache.

## Usage

After enabling the config and restarting Headscale, clients need a fresh netmap
containing `DNSConfig.CertDomains`. This normally happens automatically; if a
client still says certificate support is not enabled, restart or reconnect the
client and check that the node's map response contains its FQDN in
`CertDomains`.

Then run:

```console
tailscale cert <node>.<base_domain>
tailscale serve --https=443 localhost:8080
```

Funnel remains unsupported because it depends on Tailscale's public ingress
infrastructure.
