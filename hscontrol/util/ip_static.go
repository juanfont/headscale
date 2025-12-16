package util

import (
	"errors"
	"fmt"
	"net/netip"
	"tailscale.com/net/tsaddr"
)

var (
	ErrInvalidIPFormat     = errors.New("invalid IP address format")
	ErrIPOutOfRange        = errors.New("IP address is outside configured prefix range")
	ErrIPConflict          = errors.New("IP address is already assigned to another node")
	ErrIPv6GenerationFailed = errors.New("failed to generate IPv6 address from IPv4")
)

// ValidateIPAddress validates that an IP address is in the correct format
func ValidateIPAddress(ipStr string) (netip.Addr, error) {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("%w: %v", ErrInvalidIPFormat, err)
	}
	return addr, nil
}

// ValidateIPInRange checks if an IP address is within the given prefix
func ValidateIPInRange(addr netip.Addr, prefix *netip.Prefix) error {
	if prefix == nil {
		return fmt.Errorf("prefix is nil")
	}
	if !prefix.Contains(addr) {
		return fmt.Errorf("%w: %s is not in prefix %s", ErrIPOutOfRange, addr, prefix)
	}
	return nil
}

// GenerateIPv6FromIPv4 generates an IPv6 address from an IPv4 address
// within the Tailscale IPv6 subnet (fd7a:115c:a1e0::/48).
// The IPv6 address is constructed by embedding the IPv4 address in the lower 32 bits
// of the IPv6 address, following the pattern: fd7a:115c:a1e0:0:0:0:<ipv4_bytes>
func GenerateIPv6FromIPv4(ipv4 netip.Addr, prefix6 *netip.Prefix) (netip.Addr, error) {
	if !ipv4.Is4() {
		return netip.Addr{}, fmt.Errorf("%w: input must be an IPv4 address", ErrIPv6GenerationFailed)
	}

	if prefix6 == nil {
		return netip.Addr{}, fmt.Errorf("%w: IPv6 prefix is not configured", ErrIPv6GenerationFailed)
	}

	// Get the base prefix (first 48 bits for Tailscale range)
	// Tailscale IPv6 range is fd7a:115c:a1e0::/48
	basePrefix := tsaddr.TailscaleULARange()
	// Check if basePrefix contains prefix6 or vice versa
	// A prefix contains another if it has fewer bits (larger network) and overlaps
	baseContainsPrefix6 := basePrefix.Bits() <= prefix6.Bits() && basePrefix.Overlaps(*prefix6)
	prefix6ContainsBase := prefix6.Bits() <= basePrefix.Bits() && prefix6.Overlaps(basePrefix)
	if !baseContainsPrefix6 && !prefix6ContainsBase {
		// If the configured prefix is not the standard Tailscale range,
		// we still try to generate within the configured prefix
		basePrefix = *prefix6
	}

	// Get the network address of the prefix
	networkAddr := basePrefix.Addr()

	// Extract IPv4 bytes
	ipv4Bytes := ipv4.AsSlice()
	if len(ipv4Bytes) != 4 {
		return netip.Addr{}, fmt.Errorf("%w: invalid IPv4 address", ErrIPv6GenerationFailed)
	}

	// Construct IPv6 address by embedding IPv4 in the lower 32 bits
	// Format: <prefix_network>:0:0:<ipv4_bytes>
	ipv6Bytes := make([]byte, 16)
	copy(ipv6Bytes[:12], networkAddr.AsSlice()[:12])
	// Leave bytes 12-15 as zeros (middle part)
	copy(ipv6Bytes[12:16], ipv4Bytes)

	ipv6, ok := netip.AddrFromSlice(ipv6Bytes)
	if !ok {
		return netip.Addr{}, fmt.Errorf("%w: failed to create IPv6 address", ErrIPv6GenerationFailed)
	}

	// Verify the generated IPv6 is within the configured prefix
	if prefix6 != nil && !prefix6.Contains(ipv6) {
		// If not in prefix, try a simpler approach: just use the prefix network + IPv4
		// This is a fallback for custom prefixes
		prefixAddr := prefix6.Addr()
		prefixBytes := prefixAddr.AsSlice()
		copy(ipv6Bytes, prefixBytes)
		// Replace last 4 bytes with IPv4
		copy(ipv6Bytes[12:16], ipv4Bytes)
		ipv6, ok = netip.AddrFromSlice(ipv6Bytes)
		if !ok || !prefix6.Contains(ipv6) {
			return netip.Addr{}, fmt.Errorf("%w: generated IPv6 %s is not in prefix %s", ErrIPv6GenerationFailed, ipv6, prefix6)
		}
	}

	return ipv6, nil
}


