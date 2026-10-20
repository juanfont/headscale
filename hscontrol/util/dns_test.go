package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

func TestMagicDNSRootDomainsIPv6PartialNibble(t *testing.T) {
	tests := []struct {
		prefix  string
		nibbles []string
	}{
		{"fd7a:115c:a1e0::/49", []string{"0", "1", "2", "3", "4", "5", "6", "7"}},
		{"fd7a:115c:a1e0:8000::/49", []string{"8", "9", "a", "b", "c", "d", "e", "f"}},
		{"fd7a:115c:a1e0:c000::/50", []string{"c", "d", "e", "f"}},
		{"fd7a:115c:a1e0:d123::1/50", []string{"c", "d", "e", "f"}},
		{"fd7a:115c:a1e0:a000::/51", []string{"a", "b"}},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix(tt.prefix))
			require.Len(t, domains, len(tt.nibbles))

			for i, nibble := range tt.nibbles {
				assert.Equal(
					t,
					nibble+".0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
					domains[i].WithTrailingDot(),
				)
			}
		})
	}
}

func TestDNSRootDomainsInvalidPrefix(t *testing.T) {
	assert.Nil(t, GenerateIPv4DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/48")))
	assert.Nil(t, GenerateIPv6DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10")))

	tests := []struct {
		name   string
		prefix netip.Prefix
	}{
		{"zero", netip.Prefix{}},
		{"IPv4 too many bits", netip.PrefixFrom(netip.MustParseAddr("100.64.0.1"), 33)},
		{"IPv4 negative bits", netip.PrefixFrom(netip.MustParseAddr("100.64.0.1"), -1)},
		{
			"IPv6 too many bits",
			netip.PrefixFrom(netip.MustParseAddr("fd7a:115c:a1e0::1"), 129),
		},
		{
			"IPv6 negative bits",
			netip.PrefixFrom(netip.MustParseAddr("fd7a:115c:a1e0::1"), -1),
		},
		{
			"mapped IPv4 too many bits",
			netip.PrefixFrom(netip.MustParseAddr("::ffff:100.64.0.1"), 129),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.False(t, tt.prefix.IsValid())
			assert.Equal(
				t,
				[]dnsname.FQDN(nil),
				GenerateIPv4DNSRootDomain(tt.prefix),
			)
			assert.Equal(
				t,
				[]dnsname.FQDN(nil),
				GenerateIPv6DNSRootDomain(tt.prefix),
			)
		})
	}
}

func TestDNSRootDomainPrefixBoundaries(t *testing.T) {
	tests := []struct {
		prefix string
		count  int
		first  string
		last   string
	}{
		{"100.64.0.1/32", 1, "1.0.64.100.in-addr.arpa.", "1.0.64.100.in-addr.arpa."},
		{"100.70.0.0/10", 64, "64.100.in-addr.arpa.", "127.100.in-addr.arpa."},
		{"0.0.0.0/0", 256, "0.in-addr.arpa.", "255.in-addr.arpa."},
		{"::/0", 1, "ip6.arpa.", "ip6.arpa."},
		{
			"::1/128", 1,
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
			"1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.ip6.arpa.",
		},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			prefix := netip.MustParsePrefix(tt.prefix)

			var domains []dnsname.FQDN
			if prefix.Addr().Is4() {
				domains = GenerateIPv4DNSRootDomain(prefix)
			} else {
				domains = GenerateIPv6DNSRootDomain(prefix)
			}

			require.Len(t, domains, tt.count)
			assert.Equal(t, tt.first, domains[0].WithTrailingDot())
			assert.Equal(t, tt.last, domains[len(domains)-1].WithTrailingDot())
		})
	}
}

func TestMagicDNSRootDomains100(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("64.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("100.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("127.100.in-addr.arpa.")))
}

func TestMagicDNSRootDomains172(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("0.16.172.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("255.16.172.in-addr.arpa.")))
}

// Happens when netmask is a multiple of 4 bits (sounds likely).
func TestMagicDNSRootDomainsIPv6Single(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/48"))

	assert.Len(t, domains, 1)
	assert.Equal(t, "0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.", domains[0].WithTrailingDot())
}

func TestMagicDNSRootDomainsIPv6SingleMultiple(t *testing.T) {
	domains := GenerateIPv6DNSRootDomain(netip.MustParsePrefix("fd7a:115c:a1e0::/50"))

	yieldsRoot := func(dom string) bool {
		for _, candidate := range domains {
			if candidate.WithTrailingDot() == dom {
				return true
			}
		}

		return false
	}

	assert.Len(t, domains, 4)
	assert.True(t, yieldsRoot("0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
	assert.True(t, yieldsRoot("3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."))
}
