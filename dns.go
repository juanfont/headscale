package headscale

import (
	"fmt"

	"tailscale.com/util/dnsname"
)

func (h *Headscale) generateMagicDNSRootDomains() (*[]dnsname.FQDN, error) {
	base, err := dnsname.ToFQDN(h.cfg.BaseDomain)
	if err != nil {
		return nil, err
	}

	// TODO(juanfont): we are not handing out IPv6 addresses yet
	// and in fact this is Tailscale.com's range (note the fd7a:115c:a1e0: range in the fc00::/7 network)
	ipv6base := dnsname.FQDN("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.")
	fqdns := []dnsname.FQDN{base, ipv6base}

	// TODO(juanfont): This only works for the 100.64.0.0/10 range.
	for i := 64; i <= 127; i++ {
		fqdn, err := dnsname.ToFQDN(fmt.Sprintf("%d.100.in-addr.arpa.", i))
		if err != nil {
			continue
		}
		fqdns = append(fqdns, fqdn)
	}

	return &fqdns, nil
}
