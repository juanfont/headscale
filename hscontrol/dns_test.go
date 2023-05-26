package hscontrol

import (
	"net/netip"

	"gopkg.in/check.v1"
)

func (s *Suite) TestMagicDNSRootDomains100(c *check.C) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("100.64.0.0/10"),
	}
	domains := generateMagicDNSRootDomains(prefixes)

	found := false
	for _, domain := range domains {
		if domain == "64.100.in-addr.arpa." {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "100.100.in-addr.arpa." {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "127.100.in-addr.arpa." {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)
}

func (s *Suite) TestMagicDNSRootDomains172(c *check.C) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("172.16.0.0/16"),
	}
	domains := generateMagicDNSRootDomains(prefixes)

	found := false
	for _, domain := range domains {
		if domain == "0.16.172.in-addr.arpa." {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)

	found = false
	for _, domain := range domains {
		if domain == "255.16.172.in-addr.arpa." {
			found = true

			break
		}
	}
	c.Assert(found, check.Equals, true)
}

// Happens when netmask is a multiple of 4 bits (sounds likely).
func (s *Suite) TestMagicDNSRootDomainsIPv6Single(c *check.C) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("fd7a:115c:a1e0::/48"),
	}
	domains := generateMagicDNSRootDomains(prefixes)

	c.Assert(len(domains), check.Equals, 1)
	c.Assert(
		domains[0].WithTrailingDot(),
		check.Equals,
		"0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa.",
	)
}

func (s *Suite) TestMagicDNSRootDomainsIPv6SingleMultiple(c *check.C) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("fd7a:115c:a1e0::/50"),
	}
	domains := generateMagicDNSRootDomains(prefixes)

	yieldsRoot := func(dom string) bool {
		for _, candidate := range domains {
			if candidate.WithTrailingDot() == dom {
				return true
			}
		}

		return false
	}

	c.Assert(len(domains), check.Equals, 4)
	c.Assert(yieldsRoot("0.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."), check.Equals, true)
	c.Assert(yieldsRoot("1.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."), check.Equals, true)
	c.Assert(yieldsRoot("2.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."), check.Equals, true)
	c.Assert(yieldsRoot("3.0.e.1.a.c.5.1.1.a.7.d.f.ip6.arpa."), check.Equals, true)
}
