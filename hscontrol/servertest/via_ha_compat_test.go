// This file implements data-driven via+HA compatibility tests using
// golden data captured from Tailscale SaaS (v37-v46). These scenarios
// exercise the interaction between via grant steering and HA primary
// route election with varying combinations of shared/unique via tags,
// regular grants, and multiple HA pairs.
//
// Test data source: ../policy/v2/testdata/grant_results/via-grant-v{37..46}.hujson
// Source format:    github.com/juanfont/headscale/hscontrol/types/testcapture

package servertest_test

import (
	"context"
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
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// viaHACompatTests lists golden captures that exercise via+HA interactions.
var viaHACompatTests = []struct {
	id   string
	desc string
}{
	{"via-grant-v37", "crossed same prefix, different via tags"},
	{"via-grant-v38", "HA baseline, no via grants"},
	{"via-grant-v39", "crossed via same prefix, different HA members"},
	{"via-grant-v40", "one client via, one client regular"},
	{"via-grant-v41", "via HA pair + non-via router same prefix"},
	{"via-grant-v42", "crossed via+regular across two HA pairs"},
	{"via-grant-v43", "partial via, partial HA, cross pairs"},
	{"via-grant-v44", "four-way HA, mixed via steering"},
	{"via-grant-v45", "via+regular overlap, 4-way HA"},
	{"via-grant-v46", "kitchen sink: mixed via+regular+HA"},
}

// TestViaGrantHACompat loads golden captures from Tailscale SaaS that
// test via grant steering combined with HA primary route election.
// Each capture uses an inline topology with 4-6 nodes (instead of the
// shared 15-node grant topology used by TestViaGrantMapCompat).
func TestViaGrantHACompat(t *testing.T) {
	t.Parallel()

	for _, tc := range viaHACompatTests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				"..", "policy", "v2", "testdata", "grant_results", tc.id+".hujson",
			)

			c, err := testcapture.Read(path)
			require.NoError(t, err, "failed to read %s", path)

			if c.Error {
				t.Skipf("test %s is an error case", tc.id)

				return
			}

			runViaHACompat(t, c)
		})
	}
}

func runViaHACompat(t *testing.T, c *testcapture.Capture) {
	t.Helper()

	srv := servertest.NewServer(t)
	tagUser := srv.CreateUser(t, "tag-user")

	policyJSON := convertCapturePolicy(t, c)

	changed, err := srv.State().SetPolicy(policyJSON)
	require.NoError(t, err, "failed to set policy")

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	// Create nodes in SaaS node ID order so headscale assigns
	// sequential DB IDs in the same relative order.
	clients := map[string]*servertest.TestClient{}
	order := captureNodeOrder(t, c)

	for _, name := range order {
		topoNode, exists := c.Topology.Nodes[name]
		if !exists || len(topoNode.Tags) == 0 {
			continue
		}

		if _, inCaptures := c.Captures[name]; !inCaptures {
			continue
		}

		clients[name] = servertest.NewClient(t, srv, name,
			servertest.WithUser(tagUser),
			servertest.WithTags(topoNode.Tags...),
		)
	}

	require.NotEmpty(t, clients, "no relevant nodes created")

	// Advertise and approve routes in SaaS node ID order.
	for _, name := range order {
		cl, ok := clients[name]
		if !ok {
			continue
		}

		topoNode := c.Topology.Nodes[name]

		var routes []netip.Prefix
		for _, r := range topoNode.RoutableIPs {
			routes = append(routes, netip.MustParsePrefix(r))
		}

		if len(routes) == 0 {
			continue
		}

		cl.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-" + name,
			Hostname:     name,
			RoutableIPs:  routes,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		require.NoError(t, cl.Direct().SendUpdate(ctx),
			"route advertisement for %s should succeed", name)

		cancel()

		var approved []netip.Prefix
		for _, r := range topoNode.ApprovedRoutes {
			approved = append(approved, netip.MustParsePrefix(r))
		}

		nodeID := findNodeID(t, srv, name)

		_, routeChange, err := srv.State().SetApprovedRoutes(nodeID, approved)
		require.NoError(t, err)
		srv.App.Change(routeChange)
	}

	// Wait for peers.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		expected := 0

		for _, peer := range capture.Netmap.Peers {
			peerName := extractHostname(peer.Name())
			if _, isOurs := clients[peerName]; isOurs {
				expected++
			}
		}

		if expected > 0 {
			cl.WaitForPeers(t, expected, 30*time.Second)
		}
	}

	// Ensure all nodes have an initial netmap.
	for name, cl := range clients {
		cl.WaitForCondition(t, name+" initial netmap", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	}

	// Compare each viewer's MapResponse against golden netmap.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		t.Run(viewerName, func(t *testing.T) {
			compareCaptureNetmap(t, cl, capture, clients)
		})
	}
}

// compareCaptureNetmap compares headscale's MapResponse against a
// testcapture.Node's netmap data. Same logic as compareNetmap but
// reads from typed testcapture fields instead of goldenFile strings.
func compareCaptureNetmap(
	t *testing.T,
	viewer *servertest.TestClient,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
) {
	t.Helper()

	nm := viewer.Netmap()
	require.NotNil(t, nm, "viewer has no netmap")

	// Build peer summaries from golden data.
	wantPeers := map[string]capturePeerSummary{}

	for _, peer := range want.Netmap.Peers {
		peerName := extractHostname(peer.Name())
		if _, isOurs := clients[peerName]; !isOurs {
			continue
		}

		var (
			tsIPs         []netip.Prefix
			routePrefixes []string
		)

		for i := range peer.AllowedIPs().Len() {
			pfx := peer.AllowedIPs().At(i)
			if isTailscaleIP(pfx) {
				tsIPs = append(tsIPs, pfx)
			} else {
				routePrefixes = append(routePrefixes, pfx.String())
			}
		}

		slices.Sort(routePrefixes)

		var primaryRoutes []string

		for i := range peer.PrimaryRoutes().Len() {
			primaryRoutes = append(primaryRoutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(primaryRoutes)

		wantPeers[peerName] = capturePeerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: primaryRoutes,
		}
	}

	// Build peer summaries from headscale MapResponse.
	gotPeers := map[string]capturePeerSummary{}

	for _, peer := range nm.Peers {
		peerName := extractHostname(peer.Name())
		if _, isOurs := clients[peerName]; !isOurs {
			continue
		}

		var (
			tsIPs         []netip.Prefix
			routePrefixes []string
		)

		for i := range peer.AllowedIPs().Len() {
			pfx := peer.AllowedIPs().At(i)
			if isTailscaleIP(pfx) {
				tsIPs = append(tsIPs, pfx)
			} else {
				routePrefixes = append(routePrefixes, pfx.String())
			}
		}

		slices.Sort(routePrefixes)

		var primaryRoutes []string

		for i := range peer.PrimaryRoutes().Len() {
			primaryRoutes = append(primaryRoutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(primaryRoutes)

		gotPeers[peerName] = capturePeerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: primaryRoutes,
		}
	}

	// Compare peer visibility.
	for name, wantPeer := range wantPeers {
		gotPeer, visible := gotPeers[name]
		if !visible {
			t.Errorf("peer %s: visible in SaaS, missing in headscale (routes=%v)",
				name, wantPeer.RoutePrefixes)

			continue
		}

		assert.Equalf(t, wantPeer.RoutePrefixes, gotPeer.RoutePrefixes,
			"peer %s: route prefixes in AllowedIPs mismatch", name)

		assert.Lenf(t, gotPeer.TailscaleIPs, len(wantPeer.TailscaleIPs),
			"peer %s: Tailscale IP count mismatch", name)

		assert.ElementsMatchf(t, wantPeer.PrimaryRoutes, gotPeer.PrimaryRoutes,
			"peer %s: PrimaryRoutes mismatch", name)
	}

	// Check for extra peers.
	for name := range gotPeers {
		if _, expected := wantPeers[name]; !expected {
			t.Errorf("peer %s: visible in headscale but NOT in SaaS", name)
		}
	}

	// Baseline PacketFilter sanity: count rules. Full per-rule dst-prefix
	// comparison is done by the tailscale_routes_data compat test; here
	// we only catch gross drift.
	if len(want.PacketFilterRules) > 0 {
		gotLen := nm.PacketFilterRules.Len()
		assert.Equalf(t, len(want.PacketFilterRules), gotLen,
			"PacketFilter rule count mismatch (SaaS=%d, headscale=%d)",
			len(want.PacketFilterRules), gotLen,
		)
	}
}

type capturePeerSummary struct {
	TailscaleIPs  []netip.Prefix
	RoutePrefixes []string
	PrimaryRoutes []string
}

// captureNodeOrder returns node names from a testcapture.Capture
// sorted by SaaS node creation time, for deterministic DB ID assignment.
// SaaS elects HA primaries by registration order (first registered wins),
// which correlates with Created timestamp, not with the random snowflake
// node ID.
func captureNodeOrder(t *testing.T, c *testcapture.Capture) []string {
	t.Helper()

	type entry struct {
		name    string
		created time.Time
	}

	var entries []entry

	for name, node := range c.Captures {
		if node.Netmap == nil {
			continue
		}

		created := node.Netmap.SelfNode.Created()
		if created.IsZero() {
			continue
		}

		entries = append(entries, entry{name: name, created: created})
	}

	require.NotEmpty(t, entries, "no captures with SelfNode.Created found")

	slices.SortFunc(entries, func(a, b entry) int {
		return a.created.Compare(b.created)
	})

	names := make([]string, len(entries))
	for i, e := range entries {
		names[i] = e.name
	}

	return names
}

// convertCapturePolicy converts a testcapture's policy for headscale,
// replacing SaaS emails with headscale user format. Fails the test if
// none of the known SaaS emails are present: that would mean the
// capture was regenerated with a new tag-owner identity and this
// function needs updating.
func convertCapturePolicy(t *testing.T, c *testcapture.Capture) []byte {
	t.Helper()

	s := c.Input.FullPolicy

	substituted := false

	for _, email := range []string{
		"odin@example.com",
		"thor@example.org",
		"freya@example.com",
	} {
		if strings.Contains(s, email) {
			substituted = true
			s = strings.ReplaceAll(s, email, "tag-user@")
		}
	}

	require.True(
		t,
		substituted,
		"%s: no known SaaS tag-owner email found in policy; update convertCapturePolicy",
		c.TestID,
	)

	return []byte(s)
}
