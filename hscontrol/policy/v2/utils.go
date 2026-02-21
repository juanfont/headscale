package v2

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"
)

// Port parsing errors.
var (
	ErrInputMissingColon      = errors.New("input must contain a colon character separating destination and port")
	ErrInputStartsWithColon   = errors.New("input cannot start with a colon character")
	ErrInputEndsWithColon     = errors.New("input cannot end with a colon character")
	ErrInvalidPortRangeFormat = errors.New("invalid port range format")
	ErrPortRangeInverted      = errors.New("invalid port range: first port is greater than last port")
	ErrPortMustBePositive     = errors.New("first port must be >0, or use '*' for wildcard")
	ErrInvalidPortNumber      = errors.New("invalid port number")
	ErrPortNumberOutOfRange   = errors.New("port number out of range")
	ErrBracketsNotIPv6        = errors.New("square brackets are only valid around IPv6 addresses")
)

// splitDestinationAndPort takes an input string and returns the destination and port as a tuple, or an error if the input is invalid.
// It supports two bracketed IPv6 forms:
//   - "[addr]:port" (RFC 3986, e.g. "[::1]:80")
//   - "[addr]/prefix:port" (e.g. "[fd7a::1]/128:80,443")
//
// Brackets are only accepted around IPv6 addresses, not IPv4, hostnames, or other alias types.
// Bracket stripping reduces both forms to bare "addr:port" or "addr/prefix:port",
// which the normal LastIndex(":") split handles correctly because port strings
// never contain colons.
func splitDestinationAndPort(input string) (string, string, error) {
	// Handle RFC 3986 bracketed IPv6 (e.g. "[::1]:80" or "[fd7a::1]/128:80,443").
	// Strip brackets after validation and fall through to normal parsing.
	if strings.HasPrefix(input, "[") {
		closeBracket := strings.Index(input, "]")
		if closeBracket == -1 {
			return "", "", ErrBracketsNotIPv6
		}

		host := input[1:closeBracket]

		addr, err := netip.ParseAddr(host)
		if err != nil || !addr.Is6() {
			return "", "", fmt.Errorf("%w: %q", ErrBracketsNotIPv6, host)
		}

		rest := input[closeBracket+1:]
		if len(rest) == 0 || (rest[0] != ':' && rest[0] != '/') {
			return "", "", fmt.Errorf("%w: %q", ErrBracketsNotIPv6, input)
		}

		// Strip brackets: "[addr]:port" → "addr:port",
		// "[addr]/prefix:port" → "addr/prefix:port".
		input = host + rest
	}

	// Find the last occurrence of the colon character
	lastColonIndex := strings.LastIndex(input, ":")

	// Check if the colon character is present and not at the beginning or end of the string
	if lastColonIndex == -1 {
		return "", "", ErrInputMissingColon
	}

	if lastColonIndex == 0 {
		return "", "", ErrInputStartsWithColon
	}

	if lastColonIndex == len(input)-1 {
		return "", "", ErrInputEndsWithColon
	}

	// Split the string into destination and port based on the last colon
	destination := input[:lastColonIndex]
	port := input[lastColonIndex+1:]

	return destination, port, nil
}

// parsePortRange parses a port definition string and returns a slice of PortRange structs.
func parsePortRange(portDef string) ([]tailcfg.PortRange, error) {
	if portDef == "*" {
		return []tailcfg.PortRange{tailcfg.PortRangeAny}, nil
	}

	var portRanges []tailcfg.PortRange

	parts := strings.SplitSeq(portDef, ",")

	for part := range parts {
		if strings.Contains(part, "-") {
			rangeParts := strings.Split(part, "-")

			rangeParts = slices.DeleteFunc(rangeParts, func(e string) bool {
				return e == ""
			})
			if len(rangeParts) != 2 {
				return nil, ErrInvalidPortRangeFormat
			}

			first, err := parsePort(rangeParts[0])
			if err != nil {
				return nil, err
			}

			last, err := parsePort(rangeParts[1])
			if err != nil {
				return nil, err
			}

			if first > last {
				return nil, ErrPortRangeInverted
			}

			portRanges = append(portRanges, tailcfg.PortRange{First: first, Last: last})
		} else {
			port, err := parsePort(part)
			if err != nil {
				return nil, err
			}

			if port < 1 {
				return nil, ErrPortMustBePositive
			}

			portRanges = append(portRanges, tailcfg.PortRange{First: port, Last: port})
		}
	}

	return portRanges, nil
}

// parsePort parses a single port number from a string.
func parsePort(portStr string) (uint16, error) {
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return 0, ErrInvalidPortNumber
	}

	if port < 0 || port > 65535 {
		return 0, ErrPortNumberOutOfRange
	}

	return uint16(port), nil
}
