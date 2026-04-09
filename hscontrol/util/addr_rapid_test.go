package util

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"pgregory.net/rapid"
)

// ============================================================================
// Generators
// ============================================================================

// genIPv4Addr generates a random IPv4 address.
func genIPv4Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		var b [4]byte
		for i := range b {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}

		return netip.AddrFrom4(b)
	})
}

// genIPv6Addr generates a random IPv6 address.
func genIPv6Addr() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		var b [16]byte
		for i := range b {
			b[i] = byte(rapid.IntRange(0, 255).Draw(t, "byte"))
		}

		return netip.AddrFrom16(b)
	})
}

// genIPAddr generates a random IPv4 or IPv6 address.
func genIPAddr() *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		if rapid.Bool().Draw(t, "isV6") {
			return genIPv6Addr().Draw(t, "addr")
		}

		return genIPv4Addr().Draw(t, "addr")
	})
}

// genMaskedIPv4Prefix generates a random masked IPv4 prefix with bits in [8, maxBits].
func genMaskedIPv4Prefix(maxBits int) *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(8, maxBits).Draw(t, "bits")
		addr := genIPv4Addr().Draw(t, "addr")

		return netip.PrefixFrom(addr, bits).Masked()
	})
}

// genIPv4AddrInPrefix generates a random IPv4 address within the given prefix.
func genIPv4AddrInPrefix(prefix netip.Prefix) *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		base := prefix.Addr().As4()
		bits := prefix.Bits()

		// Convert base to uint32
		baseInt := binary.BigEndian.Uint32(base[:])

		// Number of host bits
		hostBits := 32 - bits
		if hostBits == 0 {
			return prefix.Addr()
		}

		// Generate a random offset within the host range
		maxOffset := uint32((1 << hostBits) - 1)
		offset := rapid.Uint32Range(0, maxOffset).Draw(t, "offset")

		// Combine network part with random host part
		result := baseInt | offset

		var b [4]byte
		binary.BigEndian.PutUint32(b[:], result)

		return netip.AddrFrom4(b)
	})
}

// ============================================================================
// ParseIPSet properties
// ============================================================================

// Property: ParseIPSet("*", nil) contains any random IP (v4 or v6).
func TestRapid_ParseIPSet_WildcardContainsAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ip := genIPAddr().Draw(t, "ip")

		ipSet, err := ParseIPSet("*", nil)
		if err != nil {
			t.Fatalf("ParseIPSet(\"*\", nil) failed: %v", err)
		}

		if !ipSet.Contains(ip) {
			t.Fatalf("ParseIPSet(\"*\", nil) does not contain %s", ip)
		}
	})
}

// Property: For a random CIDR, every IP within it is contained by ParseIPSet.
func TestRapid_ParseIPSet_CIDRContainsMember(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(30).Draw(t, "prefix")
		member := genIPv4AddrInPrefix(prefix).Draw(t, "member")

		ipSet, err := ParseIPSet(prefix.String(), nil)
		if err != nil {
			t.Fatalf("ParseIPSet(%q, nil) failed: %v", prefix.String(), err)
		}

		if !ipSet.Contains(member) {
			t.Fatalf("ParseIPSet(%q) does not contain member %s", prefix.String(), member)
		}
	})
}

// Property: ParseIPSet("1.2.3.4/32", nil) contains exactly that IP.
func TestRapid_ParseIPSet_SingleIPContainsOnly(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random /32
		addr := genIPv4Addr().Draw(t, "addr")
		cidr := netip.PrefixFrom(addr, 32).String()

		ipSet, err := ParseIPSet(cidr, nil)
		if err != nil {
			t.Fatalf("ParseIPSet(%q, nil) failed: %v", cidr, err)
		}

		// The exact IP must be contained
		if !ipSet.Contains(addr) {
			t.Fatalf("ParseIPSet(%q) does not contain %s", cidr, addr)
		}

		// A different random IP should not be contained (unless it happens to be the same)
		other := genIPv4Addr().Draw(t, "other")
		if other != addr && ipSet.Contains(other) {
			t.Fatalf("ParseIPSet(%q) contains unrelated IP %s", cidr, other)
		}
	})
}

// Property: For a /24 prefix, random IPs outside the prefix are NOT contained.
func TestRapid_ParseIPSet_CIDRDoesNotContainOutside(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(24).Draw(t, "prefix")
		candidate := genIPv4Addr().Draw(t, "candidate")

		// Skip if the candidate is actually inside the prefix
		if prefix.Contains(candidate) {
			return
		}

		ipSet, err := ParseIPSet(prefix.String(), nil)
		if err != nil {
			t.Fatalf("ParseIPSet(%q, nil) failed: %v", prefix.String(), err)
		}

		if ipSet.Contains(candidate) {
			t.Fatalf("ParseIPSet(%q) contains outside IP %s", prefix.String(), candidate)
		}
	})
}
