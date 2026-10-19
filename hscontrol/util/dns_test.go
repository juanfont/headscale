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

func TestMagicDNSRootDomainsIPv6WrongFamilyCompatibility(t *testing.T) {
	tests := []struct {
		prefix string
		want   []dnsname.FQDN
	}{
		{"1.1.1.0/29", []dnsname.FQDN{}},
		{"1.1.1.0/30", []dnsname.FQDN{}},
		{"1.1.1.0/31", []dnsname.FQDN{}},
		{"192.0.2.0/29", []dnsname.FQDN{}},
		{"1.1.1.0/0", []dnsname.FQDN{"ip6.arpa."}},
		{"1.1.1.0/1", []dnsname.FQDN{"0.ip6.arpa.", "1.ip6.arpa."}},
		{"3.0.0.0/3", []dnsname.FQDN{
			"0.ip6.arpa.", "1.ip6.arpa.", "2.ip6.arpa.", "3.ip6.arpa.",
			"4.ip6.arpa.", "5.ip6.arpa.", "6.ip6.arpa.", "7.ip6.arpa.",
		}},
		{"1.1.1.0/5", []dnsname.FQDN{"0.1.ip6.arpa.", "1.1.ip6.arpa."}},
		{"1.1.1.0/28", []dnsname.FQDN{""}},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			var domains []dnsname.FQDN

			require.NotPanics(t, func() {
				domains = GenerateIPv6DNSRootDomain(netip.MustParsePrefix(tt.prefix))
			})
			assert.Equal(t, tt.want, domains)
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
