// This file replays MagicDNS captures from Tailscale SaaS, one per ipPool,
// and compares the reverse-DNS routes headscale sends with those SaaS sent.
//
// Test data source: ../policy/v2/testdata/dns_results/dns-reverse-*.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"encoding/json"
	"maps"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/netmap"
)

// reverseRoutes returns the reverse-DNS keys of routes as FQDNs; headscale
// sends them without the trailing dot, SaaS with it.
func reverseRoutes(routes map[string][]*dnstype.Resolver) []string {
	var out []string

	for k := range routes {
		if k = strings.TrimSuffix(k, ".") + "."; strings.HasSuffix(k, ".arpa.") {
			out = append(out, k)
		}
	}

	slices.Sort(out)

	return out
}

// dnsNetmap starts headscale with prefixV4 and returns a node's netmap once
// its DNS config has arrived.
func dnsNetmap(t *testing.T, prefixV4 netip.Prefix, magicDNS bool) *netmap.NetworkMap {
	t.Helper()

	opts := []servertest.ServerOption{servertest.WithPrefixV4(prefixV4)}
	if magicDNS {
		opts = append(opts, servertest.WithMagicDNS("example.com"))
	}

	srv := servertest.NewServer(t, opts...)
	client := servertest.NewClient(t, srv, "node", servertest.WithUser(srv.CreateUser(t, "dns")))
	client.WaitForCondition(t, "dns config", 10*time.Second, func(nm *netmap.NetworkMap) bool {
		return nm != nil && nm.SelfNode.Valid() && nm.DNS.Proxied == magicDNS
	})

	nm := client.Netmap()
	require.True(t, slices.ContainsFunc(nm.GetAddresses().AsSlice(), func(p netip.Prefix) bool {
		return prefixV4.Contains(p.Addr())
	}), "node address outside prefixes.v4 %s", prefixV4)

	return nm
}

// TestMagicDNSReverseRoutesCompat: with an ipPool inside CGNAT, SaaS sends no
// reverse-DNS routes, whatever the pool's size or alignment; clients add the
// ones for the Tailscale ranges themselves. Headscale runs each pool as
// prefixes.v4 and must send the same.
func TestMagicDNSReverseRoutesCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("..", "policy", "v2", "testdata", "dns_results", "dns-reverse-*.hujson"))
	require.NoError(t, err)
	require.NotEmpty(t, files)

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err)

		// SaaS refuses an ipPool outside CGNAT; TestMagicDNSReverseRoutesOutsideCGNAT
		// covers what headscale sends for one.
		if c.Error {
			assert.Contains(t, c.Input.APIResponseBody.Message, "must be within CGNAT range", c.TestID)

			continue
		}

		var policy struct {
			NodeAttrs []struct {
				IPPool []netip.Prefix `json:"ipPool"`
			} `json:"nodeAttrs"`
		}
		require.NoError(t, json.Unmarshal([]byte(c.Input.FullPolicy), &policy), c.TestID)

		var pools []netip.Prefix
		for _, attr := range policy.NodeAttrs {
			pools = append(pools, attr.IPPool...)
		}

		if len(pools) == 0 {
			pools = []netip.Prefix{tsaddr.CGNATRange()}
		}

		// SaaS sends every node the same DNS config.
		var want []string

		for i, name := range slices.Sorted(maps.Keys(c.Captures)) {
			nm := c.Captures[name].Netmap
			require.NotNil(t, nm, "%s/%s", c.TestID, name)

			got := reverseRoutes(nm.DNS.Routes)
			if i == 0 {
				want = got
			}

			require.Equal(t, want, got, "%s: %s got other reverse routes", c.TestID, name)
		}

		for _, pool := range pools {
			t.Run(c.TestID+"/"+pool.String(), func(t *testing.T) {
				t.Parallel()

				nm := dnsNetmap(t, pool, c.Input.Tailnet.DNS.MagicDNS)
				assert.Equal(t, want, reverseRoutes(nm.DNS.Routes))
			})
		}
	}
}

// TestMagicDNSReverseRoutesOutsideCGNAT: SaaS has no prefix outside the
// Tailscale ranges (dns-reverse-e1/e2), so clients add no reverse routes for
// one and headscale must. An octet-aligned prefix gets one name, not 256.
func TestMagicDNSReverseRoutesOutsideCGNAT(t *testing.T) {
	t.Parallel()

	for prefix, want := range map[string][]string{
		"172.16.0.0/16": {"16.172.in-addr.arpa."},
		"10.0.0.0/23":   {"0.0.10.in-addr.arpa.", "1.0.10.in-addr.arpa."},
	} {
		t.Run(prefix, func(t *testing.T) {
			t.Parallel()

			nm := dnsNetmap(t, netip.MustParsePrefix(prefix), true)
			assert.Equal(t, want, reverseRoutes(nm.DNS.Routes))
		})
	}
}
