package headscale

import (
	"gopkg.in/check.v1"
	"inet.af/netaddr"
)

func (s *Suite) TestMagicDNSRootDomains100(c *check.C) {
	prefix := netaddr.MustParseIPPrefix("100.64.0.0/10")
	domains, err := generateMagicDNSRootDomains(prefix, "headscale.net")
	c.Assert(err, check.IsNil)

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
	prefix := netaddr.MustParseIPPrefix("172.16.0.0/16")
	domains, err := generateMagicDNSRootDomains(prefix, "headscale.net")
	c.Assert(err, check.IsNil)

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
