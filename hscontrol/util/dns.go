package util

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"go4.org/netipx"
	"tailscale.com/util/dnsname"
)

const (
	ByteSize          = 8
	ipv4AddressLength = 32
	ipv6AddressLength = 128

	// LabelHostnameLength is the maximum length for a DNS label,
	// value related to RFC 1123 and 952.
	LabelHostnameLength = 63
)

// DNS validation errors. Hostname-side validation lives on
// `tailscale.com/util/dnsname` and [state.NodeStore] collision handling; only
// the username-side errors stay in this package.
var (
	ErrUsernameTooShort        = errors.New("username must be at least 2 characters long")
	ErrUsernameMustStartLetter = errors.New("username must start with a letter")
	ErrUsernameTooManyAt       = errors.New("username cannot contain more than one '@'")
	ErrUsernameInvalidChar     = errors.New("username contains invalid character")
)

// ValidateUsername checks if a username is valid.
// It must be at least 2 characters long, start with a letter, and contain
// only letters, numbers, hyphens, dots, and underscores.
// It cannot contain more than one '@'.
// It cannot contain invalid characters.
func ValidateUsername(username string) error {
	// Ensure the username meets the minimum length requirement
	if len(username) < 2 {
		return ErrUsernameTooShort
	}

	// Ensure the username starts with a letter
	if !unicode.IsLetter(rune(username[0])) {
		return ErrUsernameMustStartLetter
	}

	atCount := 0

	for _, char := range username {
		switch {
		case unicode.IsLetter(char),
			unicode.IsDigit(char),
			char == '-',
			char == '.',
			char == '_':
			// Valid characters
		case char == '@':
			atCount++
			if atCount > 1 {
				return ErrUsernameTooManyAt
			}
		default:
			return fmt.Errorf("%w: '%c'", ErrUsernameInvalidChar, char)
		}
	}

	return nil
}

// generateMagicDNSRootDomains generates a list of DNS entries to be included in [tailcfg.DNSConfig.Routes] in [tailcfg.MapResponse].
// This list of reverse DNS entries instructs the OS on what subnets and domains the Tailscale embedded DNS
// server (listening in 100.100.100.100 udp/53) should be used for.
//
// Tailscale.com includes in the list:
// - the [types.DNSConfig.BaseDomain] of the user
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

// GenerateIPv4DNSRootDomain generates the IPv4 reverse DNS root domains.
// From the netmask we can find out the wildcard bits (the bits that are not set in the netmask).
// This allows us to then calculate the subnets included in the subsequent class block and generate the entries.
func GenerateIPv4DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	// Conversion to the std lib [net.IPNet], a bit easier to operate
	netRange := netipx.PrefixIPNet(ipPrefix)
	maskBits, _ := netRange.Mask.Size()

	// lastOctet is the last IP byte covered by the mask
	lastOctet := maskBits / ByteSize

	// wildcardBits is the number of bits not under the mask in the lastOctet
	wildcardBits := ByteSize - maskBits%ByteSize

	// A mask covering the full address width (an IPv4 /32) leaves no wildcard
	// octet, so lastOctet would index past the address. Emit the single
	// reverse-DNS name for that exact address instead of panicking.
	if lastOctet >= len(netRange.IP) {
		rdnsSlice := make([]string, 0, len(netRange.IP)+1)
		for _, v := range slices.Backward(netRange.IP) {
			rdnsSlice = append(rdnsSlice, strconv.FormatUint(uint64(v), 10))
		}

		rdnsSlice = append(rdnsSlice, "in-addr.arpa.")

		fqdn, err := dnsname.ToFQDN(strings.Join(rdnsSlice, "."))
		if err != nil {
			return nil
		}

		return []dnsname.FQDN{fqdn}
	}

	// minVal is the value in the lastOctet byte of the IP
	// maxVal is basically 2^wildcardBits - i.e., the value when all the wildcardBits are set to 1
	minVal := uint(netRange.IP[lastOctet])
	maxVal := (minVal + 1<<uint(wildcardBits)) - 1 //nolint:gosec // wildcardBits is always < 8, no overflow

	// here we generate the base domain (e.g., 100.in-addr.arpa., 16.172.in-addr.arpa., etc.)
	rdnsSlice := []string{}
	for _, b := range slices.Backward(netRange.IP[:lastOctet]) {
		rdnsSlice = append(rdnsSlice, strconv.FormatUint(uint64(b), 10))
	}

	rdnsSlice = append(rdnsSlice, "in-addr.arpa.")
	rdnsBase := strings.Join(rdnsSlice, ".")

	fqdns := make([]dnsname.FQDN, 0, maxVal-minVal+1)
	for i := minVal; i <= maxVal; i++ {
		fqdn, err := dnsname.ToFQDN(fmt.Sprintf("%d.%s", i, rdnsBase))
		if err != nil {
			continue
		}

		fqdns = append(fqdns, fqdn)
	}

	return fqdns
}

// GenerateIPv6DNSRootDomain generates the IPv6 reverse DNS root domains.
// From the netmask we can find out the wildcard bits (the bits that are not set in the netmask).
// This allows us to then calculate the subnets included in the subsequent class block and generate the entries.
func GenerateIPv6DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	const nibbleLen = 4

	maskBits, _ := netipx.PrefixIPNet(ipPrefix).Mask.Size()
	expanded := ipPrefix.Addr().StringExpanded()
	nibbleStr := strings.ReplaceAll(expanded, ":", "")

	// TODO?: that does not look the most efficient implementation,
	// but the inputs are not so long as to cause problems,
	// and from what I can see, the generateMagicDNSRootDomains
	// function is called only once over the lifetime of a server process.
	prefixConstantParts := make([]string, 0, maskBits/nibbleLen)
	for i := range maskBits / nibbleLen {
		prefixConstantParts = append(prefixConstantParts, string(nibbleStr[i]))
	}

	slices.Reverse(prefixConstantParts)

	makeDomain := func(variablePrefix ...string) (dnsname.FQDN, error) {
		prefix := strings.Join(append(variablePrefix, prefixConstantParts...), ".")

		return dnsname.ToFQDN(prefix + ".ip6.arpa")
	}

	var fqdns []dnsname.FQDN

	if maskBits%4 == 0 {
		dom, _ := makeDomain()
		fqdns = append(fqdns, dom)
	} else {
		domCount := 1 << (maskBits % nibbleLen)

		fqdns = make([]dnsname.FQDN, 0, domCount)
		for i := range domCount {
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
