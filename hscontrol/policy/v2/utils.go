package v2

import (
	"errors"
	"slices"
	"strconv"
	"strings"

	"tailscale.com/tailcfg"
)

// splitDestinationAndPort takes an input string and returns the destination and port as a tuple, or an error if the input is invalid.
func splitDestinationAndPort(input string) (string, string, error) {
	// Find the last occurrence of the colon character
	lastColonIndex := strings.LastIndex(input, ":")

	// Check if the colon character is present and not at the beginning or end of the string
	if lastColonIndex == -1 {
		return "", "", errors.New("input must contain a colon character separating destination and port")
	}
	if lastColonIndex == 0 {
		return "", "", errors.New("input cannot start with a colon character")
	}
	if lastColonIndex == len(input)-1 {
		return "", "", errors.New("input cannot end with a colon character")
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
				return nil, errors.New("invalid port range format")
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
				return nil, errors.New("invalid port range: first port is greater than last port")
			}

			portRanges = append(portRanges, tailcfg.PortRange{First: first, Last: last})
		} else {
			port, err := parsePort(part)
			if err != nil {
				return nil, err
			}

			if port < 1 {
				return nil, errors.New("first port must be >0, or use '*' for wildcard")
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
		return 0, errors.New("invalid port number")
	}

	if port < 0 || port > 65535 {
		return 0, errors.New("port number out of range")
	}

	return uint16(port), nil
}
