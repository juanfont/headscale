# DNS in headscale

headscale supports Tailscale's DNS configuration and MagicDNS. Please have a look to their KB to better understand what this means:

- https://tailscale.com/kb/1054/dns/
- https://tailscale.com/kb/1081/magicdns/
- https://tailscale.com/blog/2021-09-private-dns-with-magicdns/

Long story short, you can define the DNS servers you want to use in your tailnets, activate MagicDNS (so you don't have to remember the IP addresses of your nodes), define search domains, as well as predefined hosts. headscale will inject that settings into your nodes.

## Configuration reference

The setup is done via the `config.yaml` file, under the `dns_config` key.

```yaml
server_url: http://127.0.0.1:8001
listen_addr: 0.0.0.0:8001
private_key_path: private.key
dns_config:
  nameservers:
    - 1.1.1.1
    - 8.8.8.8
  restricted_nameservers:
    foo.bar.com:
      - 1.1.1.1
    darp.headscale.net:
      - 1.1.1.1
      - 8.8.8.8
  domains: []
  magic_dns: true
  base_domain: example.com
```

- `nameservers`: The list of DNS servers to use.
- `domains`: Search domains to inject.
- `magic_dns`: Whether to use [MagicDNS](https://tailscale.com/kb/1081/magicdns/). Only works if there is at least a nameserver defined.
- `base_domain`: Defines the base domain to create the hostnames for MagicDNS. `base_domain` must be a FQDNs, without the trailing dot. The FQDN of the hosts will be `hostname.namespace.base_domain` (e.g., _myhost.mynamespace.example.com_).
- `restricted_nameservers`: Split DNS (see https://tailscale.com/kb/1054/dns/), list of search domains and the DNS to query for each one.
