package headscale

import (
	"fmt"
	"strings"

	"inet.af/netaddr"
	"tailscale.com/util/dnsname"
)

// generateMagicDNSRootDomains generates a list of DNS entries to be included in the
// routing for DNS in the MapResponse struct. This list of DNS instructs the OS
// on what domains the Tailscale embedded DNS server should be used for.
func generateMagicDNSRootDomains(ipPrefix netaddr.IPPrefix, baseDomain string) (*[]dnsname.FQDN, error) {
	base, err := dnsname.ToFQDN(baseDomain)
	if err != nil {
		return nil, err
	}

	// TODO(juanfont): we are not handing out IPv6 addresses yet
	// and in fact this is Tailscale.com's range (note the fd7a:115c:a1e0: range in the fc00::/7 network)
	ipv6base := dnsname.FQDN("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.")
	fqdns := []dnsname.FQDN{base, ipv6base}

	// Conversion to the std lib net.IPnet, a bit easier to operate
	netRange := ipPrefix.IPNet()
	maskBits, _ := netRange.Mask.Size()

	// lastByte is the last IP byte covered by the mask
	lastByte := maskBits / 8

	// unmaskedBits is the number of bits not under the mask in the byte lastByte
	unmaskedBits := 8 - maskBits%8

	// min is the value in the lastByte byte of the IP
	// max is basically 2^unmaskedBits - i.e., the value when all the unmaskedBits are set to 1
	min := uint(netRange.IP[lastByte])
	max := uint((min + 1<<uint(unmaskedBits)) - 1)

	// here we generate the base domain (e.g., 100.in-addr.arpa., 16.172.in-addr.arpa., etc.)
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
