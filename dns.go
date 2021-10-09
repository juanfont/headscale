package headscale

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/util/dnsname"
)

func generateMagicDNSRootDomains(ipPrefix netaddr.IPPrefix, baseDomain string) (*[]dnsname.FQDN, error) {
	base, err := dnsname.ToFQDN(baseDomain)
	if err != nil {
		return nil, err
	}

	// TODO(juanfont): we are not handing out IPv6 addresses yet
	// and in fact this is Tailscale.com's range (not the fd7a:115c:a1e0: range in the fc00::/7 network)
	ipv6base := dnsname.FQDN("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.")
	fqdns := []dnsname.FQDN{base, ipv6base}

	netRange := ipPrefix.IPNet()
	maskBits, _ := netRange.Mask.Size()

	lastByte := maskBits / 8
	unmaskedBits := 8 - maskBits%8
	min := uint(netRange.IP[lastByte])
	max := uint((min + 1<<uint(unmaskedBits)) - 1)

	rdnsSlice := []string{}
	for i := lastByte - 1; i >= 0; i-- {
		rdnsSlice = append(rdnsSlice, fmt.Sprintf("%d", netRange.IP[i]))
	}
	rdnsSlice = append(rdnsSlice, "in-addr.arpa.")
	rdnsBase := strings.Join(rdnsSlice, ".")

	for i := min; i <= max; i++ {
		fqdn, err := dnsname.ToFQDN(fmt.Sprintf("%d.%s", i, rdnsBase))
		if err != nil {
			continue
		}
		fqdns = append(fqdns, fqdn)
	}
	return &fqdns, nil
}
