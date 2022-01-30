package headscale

import (
	"fmt"
	"strings"

	"github.com/fatih/set"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
)

const (
	ByteSize = 8
)

// generateMagicDNSRootDomains generates a list of DNS entries to be included in `Routes` in `MapResponse`.
// This list of reverse DNS entries instructs the OS on what subnets and domains the Tailscale embedded DNS
// server (listening in 100.100.100.100 udp/53) should be used for.
//
// Tailscale.com includes in the list:
// - the `BaseDomain` of the user
// - the reverse DNS entry for IPv6 (0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa., see below more on IPv6)
// - the reverse DNS entries for the IPv4 subnets covered by the user's `IPPrefix`.
//   In the public SaaS this is [64-127].100.in-addr.arpa.
//
// The main purpose of this function is then generating the list of IPv4 entries. For the 100.64.0.0/10, this
// is clear, and could be hardcoded. But we are allowing any range as `IPPrefix`, so we need to find out the
// subnets when we have 172.16.0.0/16 (i.e., [0-255].16.172.in-addr.arpa.), or any other subnet.
//
// How IN-ADDR.ARPA domains work is defined in RFC1035 (section 3.5). Tailscale.com seems to adhere to this,
// and do not make use of RFC2317 ("Classless IN-ADDR.ARPA delegation") - hence generating the entries for the next
// class block only.

// From the netmask we can find out the wildcard bits (the bits that are not set in the netmask).
// This allows us to then calculate the subnets included in the subsequent class block and generate the entries.
func generateMagicDNSRootDomains(
	ipPrefix netaddr.IPPrefix,
) []dnsname.FQDN {
	// TODO(juanfont): we are not handing out IPv6 addresses yet
	// and in fact this is Tailscale.com's range (note the fd7a:115c:a1e0: range in the fc00::/7 network)
	ipv6base := dnsname.FQDN("0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.")
	fqdns := []dnsname.FQDN{ipv6base}

	// Conversion to the std lib net.IPnet, a bit easier to operate
	netRange := ipPrefix.IPNet()
	maskBits, _ := netRange.Mask.Size()

	// lastOctet is the last IP byte covered by the mask
	lastOctet := maskBits / ByteSize

	// wildcardBits is the number of bits not under the mask in the lastOctet
	wildcardBits := ByteSize - maskBits%ByteSize

	// min is the value in the lastOctet byte of the IP
	// max is basically 2^wildcardBits - i.e., the value when all the wildcardBits are set to 1
	min := uint(netRange.IP[lastOctet])
	max := (min + 1<<uint(wildcardBits)) - 1

	// here we generate the base domain (e.g., 100.in-addr.arpa., 16.172.in-addr.arpa., etc.)
	rdnsSlice := []string{}
	for i := lastOctet - 1; i >= 0; i-- {
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

	return fqdns
}

func getMapResponseDNSConfig(
	dnsConfigOrig *tailcfg.DNSConfig,
	baseDomain string,
	machine Machine,
	peers Machines,
) *tailcfg.DNSConfig {
	var dnsConfig *tailcfg.DNSConfig
	if dnsConfigOrig != nil && dnsConfigOrig.Proxied { // if MagicDNS is enabled
		// Only inject the Search Domain of the current namespace - shared nodes should use their full FQDN
		dnsConfig = dnsConfigOrig.Clone()
		dnsConfig.Domains = append(
			dnsConfig.Domains,
			fmt.Sprintf("%s.%s", machine.Namespace.Name, baseDomain),
		)

		namespaceSet := set.New(set.ThreadSafe)
		namespaceSet.Add(machine.Namespace)
		for _, p := range peers {
			namespaceSet.Add(p.Namespace)
		}
		for _, namespace := range namespaceSet.List() {
			dnsRoute := fmt.Sprintf("%s.%s", namespace.(Namespace).Name, baseDomain)
			dnsConfig.Routes[dnsRoute] = nil
		}
	} else {
		dnsConfig = dnsConfigOrig
	}

	return dnsConfig
}
