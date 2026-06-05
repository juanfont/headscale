package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGenerateIPv4DNSRootDomainSingleAddress ensures a single-address IPv4
// prefix (/32) does not index past the 4-byte address and panic. A full-width
// mask leaves no wildcard octet, so the function must emit the one reverse-DNS
// name for that address.
func TestGenerateIPv4DNSRootDomainSingleAddress(t *testing.T) {
	require.NotPanics(t, func() {
		fqdns := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.1/32"))
		assert.Len(t, fqdns, 1)
	})
}
