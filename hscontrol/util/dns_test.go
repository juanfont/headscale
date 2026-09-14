package util

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"tailscale.com/util/dnsname"
	"tailscale.com/util/must"
)

func TestMagicDNSRootDomains100(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("100.64.0.0/10"))

	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("64.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("100.100.in-addr.arpa.")))
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("127.100.in-addr.arpa.")))
}

func TestMagicDNSRootDomains172(t *testing.T) {
	domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix("172.16.0.0/16"))

	assert.Len(t, domains, 1)
	assert.Contains(t, domains, must.Get(dnsname.ToFQDN("16.172.in-addr.arpa.")))
}

// An octet-aligned mask has no wildcard bits, so it must yield exactly one
// reverse-DNS name. Enumerating the next octet instead emits all 256 children
// of that name, which overruns the search-domain limits of stub resolvers.
func TestMagicDNSRootDomainsOctetAligned(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		want   string
	}{
		{prefix: "100.0.0.0/8", want: "100.in-addr.arpa."},
		{prefix: "100.120.0.0/16", want: "120.100.in-addr.arpa."},
		{prefix: "100.120.0.0/24", want: "0.120.100.in-addr.arpa."},
		{prefix: "100.120.0.5/32", want: "5.0.120.100.in-addr.arpa."},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix(tt.prefix))

			assert.Len(t, domains, 1)
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.want)))
		})
	}
}

// An unaligned mask stops inside an octet, leaving wildcard bits that must
// enumerate every value that octet takes within the prefix. RFC1035 reverse
// delegation is per-octet, so a mask longer than /24 enumerates host names
// rather than delegating classlessly (RFC2317), which is what Tailscale
// expects. These counts and boundaries are unchanged by the aligned-mask case.
func TestMagicDNSRootDomainsUnaligned(t *testing.T) {
	for _, tt := range []struct {
		prefix string
		count  int
		first  string
		last   string
		absent []string
	}{
		{
			prefix: "10.0.0.0/9",
			count:  128,
			first:  "0.10.in-addr.arpa.",
			last:   "127.10.in-addr.arpa.",
			absent: []string{"128.10.in-addr.arpa."},
		},
		{
			prefix: "100.64.0.0/10",
			count:  64,
			first:  "64.100.in-addr.arpa.",
			last:   "127.100.in-addr.arpa.",
			absent: []string{
				"63.100.in-addr.arpa.",
				"128.100.in-addr.arpa.",
			},
		},
		{
			prefix: "172.16.0.0/12",
			count:  16,
			first:  "16.172.in-addr.arpa.",
			last:   "31.172.in-addr.arpa.",
			absent: []string{
				"15.172.in-addr.arpa.",
				"32.172.in-addr.arpa.",
			},
		},
		{
			prefix: "100.120.0.0/17",
			count:  128,
			first:  "0.120.100.in-addr.arpa.",
			last:   "127.120.100.in-addr.arpa.",
			absent: []string{"128.120.100.in-addr.arpa."},
		},
		{
			prefix: "192.168.0.0/23",
			count:  2,
			first:  "0.168.192.in-addr.arpa.",
			last:   "1.168.192.in-addr.arpa.",
			absent: []string{"2.168.192.in-addr.arpa."},
		},
		{
			prefix: "100.120.0.0/25",
			count:  128,
			first:  "0.0.120.100.in-addr.arpa.",
			last:   "127.0.120.100.in-addr.arpa.",
			absent: []string{"128.0.120.100.in-addr.arpa."},
		},
		{
			prefix: "100.120.0.4/30",
			count:  4,
			first:  "4.0.120.100.in-addr.arpa.",
			last:   "7.0.120.100.in-addr.arpa.",
			absent: []string{
				"3.0.120.100.in-addr.arpa.",
				"8.0.120.100.in-addr.arpa.",
			},
		},
	} {
		t.Run(tt.prefix, func(t *testing.T) {
			domains := GenerateIPv4DNSRootDomain(netip.MustParsePrefix(tt.prefix))

			assert.Len(t, domains, tt.count)
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.first)))
			assert.Contains(t, domains, must.Get(dnsname.ToFQDN(tt.last)))

			for _, dom := range tt.absent {
				assert.NotContains(t, domains, must.Get(dnsname.ToFQDN(dom)))
			}
		})
	}
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
