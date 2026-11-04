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

// GenerateIPv4DNSRootDomain returns the in-addr.arpa. names that route reverse
// lookups for ipPrefix to MagicDNS ([tailcfg.DNSConfig.Routes]). Reverse zones
// split on octets (RFC 1035 section 3.5) and Tailscale does not delegate
// classlessly (RFC 2317), so a prefix ending inside an octet yields one name
// per value of that octet, and an octet-aligned prefix yields one name.
func GenerateIPv4DNSRootDomain(ipPrefix netip.Prefix) []dnsname.FQDN {
	// Config prefixes keep their host bits, which would shift the range.
	netRange := netipx.PrefixIPNet(ipPrefix.Masked())
	maskBits, _ := netRange.Mask.Size()

	// lastOctet indexes the octet the mask ends in.
	lastOctet := maskBits / ByteSize

	// wildcardBits is the number of bits not under the mask in the lastOctet
	wildcardBits := ByteSize - maskBits%ByteSize

	// An aligned mask ends on an octet boundary: one name for the last masked
	// octet covers all 256 children. A /0 masks no octet.
	if maskBits%ByteSize == 0 {
		if maskBits == 0 {
			return []dnsname.FQDN{"in-addr.arpa."}
		}

		lastOctet--
		wildcardBits = 0
	}

	// maxVal is minVal with every wildcard bit set.
	minVal := uint(netRange.IP[lastOctet])
	maxVal := (minVal + 1<<uint(wildcardBits)) - 1 //nolint:gosec // wildcardBits is in [0, 7]

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
