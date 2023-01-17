package headscale

import (
	"fmt"
	"net/netip"
	"net/url"
	"strings"

	mapset "github.com/deckarep/golang-set/v2"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/util/dnsname"
)

const (
	ByteSize = 8
)

const (
	ipv4AddressLength = 32
	ipv6AddressLength = 128
)

const (
	nextDNSDoHPrefix = "https://dns.nextdns.io"
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
func generateMagicDNSRootDomains(ipPrefixes []netip.Prefix) []dnsname.FQDN {
	fqdns := make([]dnsname.FQDN, 0, len(ipPrefixes))
	for _, ipPrefix := range ipPrefixes {
		var generateDNSRoot func(netip.Prefix) []dnsname.FQDN
		switch ipPrefix.Addr().BitLen() {
		case ipv4AddressLength:
			generateDNSRoot = generateIPv4DNSRootDomain

		case ipv6AddressLength:
			generateDNSRoot = generateIPv6DNSRootDomain

		default:
			panic(
				fmt.Sprintf(
					"unsupported IP version with address length %d",
					ipPrefix.Addr().BitLen(),
				),
			)
		}

		fqdns = append(fqdns, generateDNSRoot(ipPrefix)...)
	}

	return fqdns
}

func generateIPv4DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	// Conversion to the std lib net.IPnet, a bit easier to operate
	netRange := netipx.PrefixIPNet(ipPrefix)
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

func generateIPv6DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	const nibbleLen = 4

	maskBits, _ := netipx.PrefixIPNet(ipPrefix).Mask.Size()
	expanded := ipPrefix.Addr().StringExpanded()
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

// If any nextdns DoH resolvers are present in the list of resolvers it will
// take metadata from the machine metadata and instruct tailscale to add it
// to the requests. This makes it possible to identify from which device the
// requests come in the NextDNS dashboard.
//
// This will produce a resolver like:
// `https://dns.nextdns.io/<nextdns-id>?device_name=node-name&device_model=linux&device_ip=100.64.0.1`
func addNextDNSMetadata(resolvers []*dnstype.Resolver, machine Machine) {
	for _, resolver := range resolvers {
		if strings.HasPrefix(resolver.Addr, nextDNSDoHPrefix) {
			attrs := url.Values{
				"device_name":  []string{machine.Hostname},
				"device_model": []string{machine.HostInfo.OS},
			}

			if len(machine.IPAddresses) > 0 {
				attrs.Add("device_ip", machine.IPAddresses[0].String())
			}

			resolver.Addr = fmt.Sprintf("%s?%s", resolver.Addr, attrs.Encode())
		}
	}
}

func getMapResponseDNSConfig(
	dnsConfigOrig *tailcfg.DNSConfig,
	baseDomain string,
	machine Machine,
	peers Machines,
) *tailcfg.DNSConfig {
	var dnsConfig *tailcfg.DNSConfig = dnsConfigOrig.Clone()
	if dnsConfigOrig != nil && dnsConfigOrig.Proxied { // if MagicDNS is enabled
		// Only inject the Search Domain of the current user - shared nodes should use their full FQDN
		dnsConfig.Domains = append(
			dnsConfig.Domains,
			fmt.Sprintf(
				"%s.%s",
				machine.User.Name,
				baseDomain,
			),
		)

		userSet := mapset.NewSet[User]()
		userSet.Add(machine.User)
		for _, p := range peers {
			userSet.Add(p.User)
		}
		for _, user := range userSet.ToSlice() {
			dnsRoute := fmt.Sprintf("%v.%v", user.Name, baseDomain)
			dnsConfig.Routes[dnsRoute] = nil
		}
	} else {
		dnsConfig = dnsConfigOrig
	}

	addNextDNSMetadata(dnsConfig.Resolvers, machine)

	return dnsConfig
}
