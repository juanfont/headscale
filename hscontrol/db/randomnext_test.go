package db

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestRandomNextSingleAddressPrefix ensures a single-address prefix (/32 or
// /128) does not panic. from == to makes the random range zero, and rand.Int
// panics on a non-positive bound; the sole address must be returned instead.
func TestRandomNextSingleAddressPrefix(t *testing.T) {
	for _, p := range []string{"100.64.0.1/32", "fd7a:115c:a1e0::1/128"} {
		pfx := netip.MustParsePrefix(p)
		require.NotPanics(t, func() {
			ip, err := randomNext(pfx)
			require.NoError(t, err)
			assert.Equal(t, pfx.Addr(), ip)
		}, "prefix %s", p)
	}
}

// TestRandomNextLeadingZeroBytes ensures prefixes whose addresses have a zero
// high byte allocate successfully. big.Int.Bytes() strips leading zeros, so the
// drawn value would be too short for netip.AddrFromSlice without padding.
func TestRandomNextLeadingZeroBytes(t *testing.T) {
	pfx := netip.MustParsePrefix("0.0.0.0/16")
	for range 100 {
		ip, err := randomNext(pfx)
		require.NoError(t, err)
		assert.True(t, pfx.Contains(ip), "ip %s not in %s", ip, pfx)
	}
}
