package servertest_test

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

// goldenFile represents a golden capture from Tailscale SaaS with full
// netmap data per node.
type goldenFile struct {
	TestID string `json:"test_id"`
	Error  bool   `json:"error"`
	Input  struct {
		FullPolicy json.RawMessage `json:"full_policy"`
	} `json:"input"`
	Topology struct {
		Nodes map[string]goldenNode `json:"nodes"`
	} `json:"topology"`
	Captures map[string]goldenCapture `json:"captures"`
}

type goldenNode struct {
	Hostname         string   `json:"hostname"`
	Tags             []string `json:"tags"`
	IPv4             string   `json:"ipv4"`
	IPv6             string   `json:"ipv6"`
	AdvertisedRoutes []string `json:"advertised_routes"`
	IsExitNode       bool     `json:"is_exit_node"`
}

type goldenCapture struct {
	PacketFilterRules json.RawMessage        `json:"packet_filter_rules"`
	Netmap            *goldenNetmap          `json:"netmap"`
	Whois             map[string]goldenWhois `json:"whois"`
}

type goldenNetmap struct {
	Peers             []goldenPeer    `json:"Peers"`
	PacketFilterRules json.RawMessage `json:"PacketFilterRules"`
}

type goldenPeer struct {
	Name          string   `json:"Name"`
	AllowedIPs    []string `json:"AllowedIPs"`
	PrimaryRoutes []string `json:"PrimaryRoutes"`
	Tags          []string `json:"Tags"`
}

type goldenWhois struct {
	PeerName string           `json:"peer_name"`
	Response *json.RawMessage `json:"response"`
}

// viaCompatTests lists golden captures that exercise via grant steering.
var viaCompatTests = []struct {
	id   string
	desc string
}{
	{"GRANT-V29", "crossed subnet steering: group-a via router-a, group-b via router-b"},
	{"GRANT-V30", "crossed mixed: subnet via router-a/b, exit via exit-b/a"},
	{"GRANT-V31", "peer connectivity + via exit A/B steering"},
	{"GRANT-V36", "full complex: peer connectivity + crossed subnet + crossed exit"},
}

// TestViaGrantMapCompat loads golden captures from Tailscale SaaS and
// compares headscale's MapResponse structure against the captured netmap.
//
// The comparison is IP-independent: it validates peer visibility, route
// prefixes in AllowedIPs, and PrimaryRoutes — not literal Tailscale IP
// addresses which differ between Tailscale SaaS and headscale allocation.
//
// CROSS-DEPENDENCY WARNING:
// This test reads golden files from ../policy/v2/testdata/grant_results/
// (specifically GRANT-V29, V30, V31, V36). These files are shared with
// TestGrantsCompat in the policy/v2 package. Any changes to the file
// format, field structure, or naming must be coordinated with BOTH tests.
//
// Fields consumed by this test (but NOT by TestGrantsCompat):
//   - captures[name].netmap (Peers, AllowedIPs, PrimaryRoutes, PacketFilterRules)
//   - topology.nodes[name].tags (used for servertest node creation)
//
// Fields consumed by TestGrantsCompat (but NOT by this test):
//   - captures[name].packet_filter_rules (golden filter rule comparison)
//   - input.api_response_code/body (error case handling)
func TestViaGrantMapCompat(t *testing.T) {
	t.Parallel()

	for _, tc := range viaCompatTests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				"..", "policy", "v2", "testdata", "grant_results", tc.id+".hujson",
			)
			data, err := os.ReadFile(path)
			require.NoError(t, err, "failed to read golden file %s", path)

			ast, err := hujson.Parse(data)
			require.NoError(t, err, "failed to parse HuJSON in %s", path)
			ast.Standardize()

			var gf goldenFile
			require.NoError(t, json.Unmarshal(ast.Pack(), &gf))

			if gf.Error {
				t.Skipf("test %s is an error case", tc.id)
				return
			}

			runViaMapCompat(t, gf)
		})
	}
}

// taggedNodes are the nodes we create in the servertest.
var taggedNodes = []string{
	"exit-a", "exit-b", "exit-node",
	"group-a-client", "group-b-client",
	"router-a", "router-b",
	"subnet-router", "tagged-client",
	"tagged-server", "tagged-prod",
	"multi-exit-router",
}

func runViaMapCompat(t *testing.T, gf goldenFile) {
	t.Helper()

	srv := servertest.NewServer(t)
	tagUser := srv.CreateUser(t, "tag-user")

	policyJSON := convertViaPolicy(gf.Input.FullPolicy)

	changed, err := srv.State().SetPolicy(policyJSON)
	require.NoError(t, err, "failed to set policy")

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	// Create tagged clients matching the golden topology.
	clients := map[string]*servertest.TestClient{}

	for _, name := range taggedNodes {
		topoNode, exists := gf.Topology.Nodes[name]
		if !exists || len(topoNode.Tags) == 0 {
			continue
		}

		if _, inCaptures := gf.Captures[name]; !inCaptures {
			continue
		}

		clients[name] = servertest.NewClient(t, srv, name,
			servertest.WithUser(tagUser),
			servertest.WithTags(topoNode.Tags...),
		)
	}

	require.NotEmpty(t, clients, "no relevant nodes created")

	// Determine which routes each node should advertise. If the golden
	// topology has explicit advertised_routes, use those. Otherwise infer
	// from the policy's autoApprovers.routes: if a node's tags match an
	// approver tag for a route prefix, the node should advertise it.
	nodeRoutes := inferNodeRoutes(gf)

	// Advertise and approve routes FIRST. Via grants depend on routes
	// being advertised for compileViaGrant to produce filter rules.
	for name, c := range clients {
		routes := nodeRoutes[name]
		if len(routes) == 0 {
			continue
		}

		c.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-" + name,
			Hostname:     name,
			RoutableIPs:  routes,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		_ = c.Direct().SendUpdate(ctx)

		cancel()

		nodeID := findNodeID(t, srv, name)
		_, routeChange, err := srv.State().SetApprovedRoutes(nodeID, routes)
		require.NoError(t, err)
		srv.App.Change(routeChange)
	}

	// Wait for peers based on golden netmap expected counts.
	for viewerName, c := range clients {
		capture := gf.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		expected := 0

		for _, peer := range capture.Netmap.Peers {
			peerName := extractHostname(peer.Name)
			if _, isOurs := clients[peerName]; isOurs {
				expected++
			}
		}

		if expected > 0 {
			c.WaitForPeers(t, expected, 30*time.Second)
		}
	}

	// Ensure all nodes have received at least one MapResponse,
	// including nodes with 0 expected peers that skipped WaitForPeers.
	for name, c := range clients {
		c.WaitForCondition(t, name+" initial netmap", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	}

	// Compare each viewer's MapResponse against the golden netmap.
	for viewerName, c := range clients {
		capture := gf.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		t.Run(viewerName, func(t *testing.T) {
			nm := c.Netmap()
			require.NotNil(t, nm, "netmap is nil")

			compareNetmap(t, nm, capture.Netmap, clients)
		})
	}
}

// compareNetmap compares the headscale MapResponse against the golden
// netmap data in an IP-independent way. It validates:
//   - Peer visibility (which peers are present, by hostname)
//   - Route prefixes in AllowedIPs (non-Tailscale-IP entries like 10.44.0.0/16)
//   - Number of Tailscale IPs per peer (should be 2: one v4 + one v6)
//   - PrimaryRoutes per peer
//   - PacketFilter rule count
func compareNetmap(
	t *testing.T,
	got *netmap.NetworkMap,
	want *goldenNetmap,
	clients map[string]*servertest.TestClient,
) {
	t.Helper()

	// Build golden peer map (only peers in our client set).
	wantPeers := map[string]goldenPeer{}

	for _, p := range want.Peers {
		name := extractHostname(p.Name)
		if _, isOurs := clients[name]; isOurs {
			wantPeers[name] = p
		}
	}

	// Build headscale peer map.
	gotPeers := map[string]peerSummary{}

	for _, peer := range got.Peers {
		name := ""

		if peer.Hostinfo().Valid() {
			name = peer.Hostinfo().Hostname()
		}

		if name == "" {
			for n := range clients {
				if strings.Contains(peer.Name(), n+".") {
					name = n

					break
				}
			}
		}

		if name == "" {
			continue
		}

		// Separate AllowedIPs into Tailscale IPs (node addresses)
		// and route prefixes (subnets, exit routes).
		var tsIPs []netip.Prefix

		var routePrefixes []string

		for i := range peer.AllowedIPs().Len() {
			prefix := peer.AllowedIPs().At(i)
			if isTailscaleIP(prefix) {
				tsIPs = append(tsIPs, prefix)
			} else {
				routePrefixes = append(routePrefixes, prefix.String())
			}
		}

		slices.Sort(routePrefixes)

		var proutes []string
		for i := range peer.PrimaryRoutes().Len() {
			proutes = append(proutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(proutes)

		gotPeers[name] = peerSummary{
			TailscaleIPs:  tsIPs,
			RoutePrefixes: routePrefixes,
			PrimaryRoutes: proutes,
		}
	}

	// Compare peer visibility: golden peers must be present.
	for name, wantPeer := range wantPeers {
		gotPeer, visible := gotPeers[name]
		if !visible {
			wantRoutes := extractRoutePrefixes(wantPeer.AllowedIPs)
			t.Errorf("peer %s: visible in Tailscale SaaS (routes=%v), missing in headscale",
				name, wantRoutes)

			continue
		}

		// Compare route prefixes in AllowedIPs (IP-independent).
		wantRoutes := extractRoutePrefixes(wantPeer.AllowedIPs)
		slices.Sort(wantRoutes)

		assert.Equalf(t, wantRoutes, gotPeer.RoutePrefixes,
			"peer %s: route prefixes in AllowedIPs mismatch", name)

		// Tailscale IPs: count should match, and they must belong to
		// this peer (not some other node's IPs).
		wantTSIPCount := countTailscaleIPs(wantPeer.AllowedIPs)

		assert.Lenf(t, gotPeer.TailscaleIPs, wantTSIPCount,
			"peer %s: Tailscale IP count mismatch", name)

		// Verify the Tailscale IPs are actually this peer's addresses.
		if peerClient, ok := clients[name]; ok {
			peerNM := peerClient.Netmap()
			if peerNM != nil && peerNM.SelfNode.Valid() {
				peerAddrs := map[netip.Prefix]bool{}

				addrs := peerNM.SelfNode.Addresses()
				for i := range addrs.Len() {
					peerAddrs[addrs.At(i)] = true
				}

				for _, tsIP := range gotPeer.TailscaleIPs {
					assert.Truef(t, peerAddrs[tsIP],
						"peer %s: AllowedIPs contains Tailscale IP %s which is NOT this peer's address (peer has %v)",
						name, tsIP, peerAddrs)
				}
			}
		}

		// Compare PrimaryRoutes.
		assert.ElementsMatchf(t, wantPeer.PrimaryRoutes, gotPeer.PrimaryRoutes,
			"peer %s: PrimaryRoutes mismatch", name)
	}

	// Check for extra peers headscale shows that Tailscale SaaS doesn't.
	for name := range gotPeers {
		if _, expected := wantPeers[name]; !expected {
			t.Errorf("peer %s: visible in headscale but NOT in Tailscale SaaS", name)
		}
	}

	// Compare PacketFilter rule count.
	var wantFilterRules []tailcfg.FilterRule
	if len(want.PacketFilterRules) > 0 &&
		string(want.PacketFilterRules) != "null" {
		_ = json.Unmarshal(want.PacketFilterRules, &wantFilterRules)
	}

	assert.Lenf(t, got.PacketFilter, len(wantFilterRules),
		"PacketFilter rule count mismatch")
}

type peerSummary struct {
	TailscaleIPs  []netip.Prefix // Tailscale address entries from AllowedIPs
	RoutePrefixes []string       // non-Tailscale-IP AllowedIPs (sorted)
	PrimaryRoutes []string       // sorted
}

// isTailscaleIP returns true if the prefix is a single-host Tailscale
// address (/32 for IPv4 in CGNAT range, /128 for IPv6 in Tailscale ULA).
func isTailscaleIP(prefix netip.Prefix) bool {
	addr := prefix.Addr()

	if addr.Is4() && prefix.Bits() == 32 {
		// CGNAT range 100.64.0.0/10
		return addr.As4()[0] == 100 && (addr.As4()[1]&0xC0) == 64
	}

	if addr.Is6() && prefix.Bits() == 128 {
		// Tailscale ULA fd7a:115c:a1e0::/48
		b := addr.As16()

		return b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c //nolint:gosec // As16 returns [16]byte, indexing [0..3] is safe
	}

	return false
}

// extractRoutePrefixes returns the non-Tailscale-IP entries from an
// AllowedIPs list (subnet routes, exit routes, etc.).
func extractRoutePrefixes(allowedIPs []string) []string {
	var routes []string

	for _, aip := range allowedIPs {
		prefix, err := netip.ParsePrefix(aip)
		if err != nil {
			continue
		}

		if !isTailscaleIP(prefix) {
			routes = append(routes, aip)
		}
	}

	return routes
}

// countTailscaleIPs returns the number of Tailscale IP entries in an
// AllowedIPs list.
func countTailscaleIPs(allowedIPs []string) int {
	count := 0

	for _, aip := range allowedIPs {
		prefix, err := netip.ParsePrefix(aip)
		if err != nil {
			continue
		}

		if isTailscaleIP(prefix) {
			count++
		}
	}

	return count
}

// inferNodeRoutes determines which routes each node should advertise.
// If the golden topology has explicit advertised_routes, those are used.
// Otherwise, routes are inferred from the golden netmap data: if a node
// appears as a peer with route prefixes in AllowedIPs, it should
// advertise those routes.
func inferNodeRoutes(gf goldenFile) map[string][]netip.Prefix {
	result := map[string][]netip.Prefix{}

	// First use explicit advertised_routes from topology.
	for name, node := range gf.Topology.Nodes {
		for _, r := range node.AdvertisedRoutes {
			result[name] = append(result[name], netip.MustParsePrefix(r))
		}
	}

	// If any node already has routes, the topology is populated — use as-is.
	for _, routes := range result {
		if len(routes) > 0 {
			return result
		}
	}

	// Infer from the golden netmap: scan all captures for peers with
	// route prefixes in AllowedIPs. If node X appears as a peer with
	// route prefix 10.44.0.0/16, then X should advertise that route.
	for _, capture := range gf.Captures {
		if capture.Netmap == nil {
			continue
		}

		for _, peer := range capture.Netmap.Peers {
			peerName := extractHostname(peer.Name)
			routes := extractRoutePrefixes(peer.AllowedIPs)

			for _, r := range routes {
				prefix, err := netip.ParsePrefix(r)
				if err != nil {
					continue
				}

				if !slices.Contains(result[peerName], prefix) {
					result[peerName] = append(result[peerName], prefix)
				}
			}
		}
	}

	return result
}

// extractHostname extracts the hostname from a Tailscale FQDN like
// "router-a.tail78f774.ts.net.".
func extractHostname(fqdn string) string {
	if before, _, ok := strings.Cut(fqdn, "."); ok {
		return before
	}

	return fqdn
}

// convertViaPolicy converts Tailscale SaaS policy emails to headscale format.
func convertViaPolicy(raw json.RawMessage) []byte {
	s := string(raw)
	s = strings.ReplaceAll(s, "kratail2tid@passkey", "tag-user@")
	s = strings.ReplaceAll(s, "kristoffer@dalby.cc", "tag-user@")
	s = strings.ReplaceAll(s, "monitorpasskeykradalby@passkey", "tag-user@")

	return []byte(s)
}
