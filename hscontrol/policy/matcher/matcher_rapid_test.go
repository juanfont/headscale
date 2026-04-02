package matcher

import (
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

// genMaskedIPv4Prefix generates a random masked IPv4 prefix.
func genMaskedIPv4Prefix(minBits, maxBits int) *rapid.Generator[netip.Prefix] {
	return rapid.Custom[netip.Prefix](func(t *rapid.T) netip.Prefix {
		bits := rapid.IntRange(minBits, maxBits).Draw(t, "bits")
		addr := genIPv4Addr().Draw(t, "addr")
		return netip.PrefixFrom(addr, bits).Masked()
	})
}

// genIPv4AddrInPrefix generates a random IPv4 address within the given prefix.
func genIPv4AddrInPrefix(prefix netip.Prefix) *rapid.Generator[netip.Addr] {
	return rapid.Custom[netip.Addr](func(t *rapid.T) netip.Addr {
		base := prefix.Addr().As4()
		bits := prefix.Bits()

		baseInt := uint32(base[0])<<24 | uint32(base[1])<<16 | uint32(base[2])<<8 | uint32(base[3])
		hostBits := 32 - bits
		if hostBits == 0 {
			return prefix.Addr()
		}

		maxOffset := uint32((1 << hostBits) - 1)
		offset := uint32(rapid.Uint32Range(0, maxOffset).Draw(t, "offset"))

		result := baseInt | offset
		return netip.AddrFrom4([4]byte{
			byte(result >> 24),
			byte(result >> 16),
			byte(result >> 8),
			byte(result),
		})
	})
}

// ============================================================================
// MatchFromStrings properties
// ============================================================================

// Property: Match{Srcs: ["*"]} contains any random IP.
func TestRapid_MatchFromStrings_WildcardMatchesAll(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ip := genIPAddr().Draw(t, "ip")

		m := MatchFromStrings([]string{"*"}, []string{"*"})

		if !m.SrcsContainsIPs(ip) {
			t.Fatalf("Match with wildcard src does not contain %s", ip)
		}
	})
}

// Property: If src has a CIDR, IPs within that CIDR match.
func TestRapid_MatchFromStrings_CIDRSourceContains(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(8, 30).Draw(t, "prefix")
		member := genIPv4AddrInPrefix(prefix).Draw(t, "member")

		m := MatchFromStrings([]string{prefix.String()}, []string{"*"})

		if !m.SrcsContainsIPs(member) {
			t.Fatalf("Match with src %q does not contain member %s", prefix.String(), member)
		}
	})
}

// Property: Empty srcs matches no IP.
func TestRapid_MatchFromStrings_EmptySourceMatchesNone(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		ip := genIPAddr().Draw(t, "ip")

		m := MatchFromStrings([]string{}, []string{"*"})

		if m.SrcsContainsIPs(ip) {
			t.Fatalf("Match with empty srcs should not contain %s", ip)
		}
	})
}
