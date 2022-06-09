package headscale

import (
	"fmt"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"inet.af/netaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/dnsname"
)

const (
	ByteSize = 8
)

const (
	ipv4AddressLength = 32
	ipv6AddressLength = 128
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
func generateMagicDNSRootDomains(ipPrefixes []netaddr.IPPrefix) []dnsname.FQDN {
	fqdns := make([]dnsname.FQDN, 0, len(ipPrefixes))
	for _, ipPrefix := range ipPrefixes {
		var generateDNSRoot func(netaddr.IPPrefix) []dnsname.FQDN
		switch ipPrefix.IP().BitLen() {
		case ipv4AddressLength:
			generateDNSRoot = generateIPv4DNSRootDomain

		case ipv6AddressLength:
			generateDNSRoot = generateIPv6DNSRootDomain

		default:
			panic(
				fmt.Sprintf(
					"unsupported IP version with address length %d",
					ipPrefix.IP().BitLen(),
				),
			)
		}

		fqdns = append(fqdns, generateDNSRoot(ipPrefix)...)
	}

	return fqdns
}

func generateIPv4DNSRootDomain(ipPrefix netaddr.IPPrefix) []dnsname.FQDN {
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

	fqdns := make([]dnsname.FQDN, 0, max-min+1)
	for i := min; i <= max; i++ {
		fqdn, err := dnsname.ToFQDN(fmt.Sprintf("%d.%s", i, rdnsBase))
		if err != nil {
			continue
		}
		fqdns = append(fqdns, fqdn)
	}

	return fqdns
}

func generateIPv6DNSRootDomain(ipPrefix netaddr.IPPrefix) []dnsname.FQDN {
	const nibbleLen = 4

	maskBits, _ := ipPrefix.IPNet().Mask.Size()
	expanded := ipPrefix.IP().StringExpanded()
	nibbleStr := strings.Map(func(r rune) rune {
		if r == ':' {
			return -1
		}

		return r
	}, expanded)

	// TODO?: that does not look the most efficient implementation,
	// but the inputs are not so long as to cause problems,
	// and from what I can see, the generateMagicDNSRootDomains
	// function is called only once over the lifetime of a server process.
	prefixConstantParts := []string{}
	for i := 0; i < maskBits/nibbleLen; i++ {
		prefixConstantParts = append(
			[]string{string(nibbleStr[i])},
			prefixConstantParts...)
	}

	makeDomain := func(variablePrefix ...string) (dnsname.FQDN, error) {
		prefix := strings.Join(append(variablePrefix, prefixConstantParts...), ".")

		return dnsname.ToFQDN(fmt.Sprintf("%s.ip6.arpa", prefix))
	}

	var fqdns []dnsname.FQDN
	if maskBits%4 == 0 {
		dom, _ := makeDomain()
		fqdns = append(fqdns, dom)
	} else {
		domCount := 1 << (maskBits % nibbleLen)
		fqdns = make([]dnsname.FQDN, 0, domCount)
		for i := 0; i < domCount; i++ {
			varNibble := fmt.Sprintf("%x", i)
			dom, err := makeDomain(varNibble)
			if err != nil {
				continue
			}
			fqdns = append(fqdns, dom)
		}
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
			fmt.Sprintf(
				"%s.%s",
				machine.Namespace.Name,
				baseDomain,
			),
		)

		namespaceSet := mapset.NewSet[Namespace]()
		namespaceSet.Add(machine.Namespace)
		for _, p := range peers {
			namespaceSet.Add(p.Namespace)
		}
		for _, namespace := range namespaceSet.ToSlice() {
			dnsRoute := fmt.Sprintf("%v.%v", namespace.Name, baseDomain)
			dnsConfig.Routes[dnsRoute] = nil
		}
	} else {
		dnsConfig = dnsConfigOrig
	}

	return dnsConfig
}
