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
	SelfNode          json.RawMessage `json:"SelfNode"`
	Peers             []goldenPeer    `json:"Peers"`
	PacketFilter      json.RawMessage `json:"PacketFilter"`
	PacketFilterRules json.RawMessage `json:"PacketFilterRules"`
	DNS               json.RawMessage `json:"DNS"`
	SSHPolicy         json.RawMessage `json:"SSHPolicy"`
	Domain            string          `json:"Domain"`
	UserProfiles      json.RawMessage `json:"UserProfiles"`
}

type goldenPeer struct {
	Name           string   `json:"Name"`
	Addresses      []string `json:"Addresses"`
	AllowedIPs     []string `json:"AllowedIPs"`
	PrimaryRoutes  []string `json:"PrimaryRoutes"`
	Tags           []string `json:"Tags"`
	ExitNodeOption *bool    `json:"ExitNodeOption"`
	Online         *bool    `json:"Online"`
	Cap            int      `json:"Cap"`
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
// compares headscale's full MapResponse against the captured netmap.
//
// For each viewing node, it compares:
//   - Peer set (which peers are visible)
//   - Per-peer AllowedIPs (via steering changes which routes appear on which peer)
//   - Per-peer PrimaryRoutes (which node is primary for a subnet)
//   - PacketFilter rule count
func TestViaGrantMapCompat(t *testing.T) {
	t.Parallel()

	for _, tc := range viaCompatTests {
		t.Run(tc.id, func(t *testing.T) {
			t.Parallel()

			path := filepath.Join(
				"..", "policy", "v2", "testdata", "grant_results", tc.id+".json",
			)
			data, err := os.ReadFile(path)
			require.NoError(t, err, "failed to read golden file %s", path)

			var gf goldenFile
			require.NoError(t, json.Unmarshal(data, &gf))

			if gf.Error {
				t.Skipf("test %s is an error case", tc.id)
				return
			}

			runViaMapCompat(t, gf)
		})
	}
}

// taggedNodes are the nodes we create in the servertest. User-owned nodes
// are excluded because the servertest uses a single user for all tagged
// nodes, which doesn't map to the multi-user Tailscale topology.
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

	// Compute expected peer counts from golden netmap.
	expectedPeerCounts := map[string]int{}

	for viewerName := range clients {
		capture := gf.Captures[viewerName]
		if capture.Netmap != nil {
			// Count peers from golden netmap that are in our client set.
			count := 0

			for _, peer := range capture.Netmap.Peers {
				peerName := extractHostname(peer.Name)
				if _, isOurs := clients[peerName]; isOurs {
					count++
				}
			}

			expectedPeerCounts[viewerName] = count
		}
	}

	// Wait for expected peers.
	for name, c := range clients {
		expected := expectedPeerCounts[name]
		if expected > 0 {
			c.WaitForPeers(t, expected, 30*time.Second)
		}
	}

	// Advertise and approve routes.
	for name, c := range clients {
		topoNode := gf.Topology.Nodes[name]
		if len(topoNode.AdvertisedRoutes) == 0 {
			continue
		}

		var routes []netip.Prefix
		for _, r := range topoNode.AdvertisedRoutes {
			routes = append(routes, netip.MustParsePrefix(r))
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

	// Wait for route propagation.
	for _, c := range clients {
		c.WaitForCondition(t, "routes settled", 15*time.Second,
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

			compareNetmap(t, viewerName, nm, capture.Netmap, clients)
		})
	}
}

func compareNetmap(
	t *testing.T,
	_ string, // viewerName unused but kept for signature clarity
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

		var aips []string
		for i := range peer.AllowedIPs().Len() {
			aips = append(aips, peer.AllowedIPs().At(i).String())
		}

		slices.Sort(aips)

		var proutes []string
		for i := range peer.PrimaryRoutes().Len() {
			proutes = append(proutes, peer.PrimaryRoutes().At(i).String())
		}

		slices.Sort(proutes)

		gotPeers[name] = peerSummary{
			AllowedIPs:    aips,
			PrimaryRoutes: proutes,
		}
	}

	// Compare peer visibility.
	for name, wantPeer := range wantPeers {
		gotPeer, visible := gotPeers[name]
		if !visible {
			t.Errorf("peer %s: visible in Tailscale SaaS (AllowedIPs=%v), missing in headscale",
				name, wantPeer.AllowedIPs)

			continue
		}

		// Compare AllowedIPs.
		wantAIPs := make([]string, len(wantPeer.AllowedIPs))
		copy(wantAIPs, wantPeer.AllowedIPs)
		slices.Sort(wantAIPs)

		assert.Equalf(t, wantAIPs, gotPeer.AllowedIPs,
			"peer %s: AllowedIPs mismatch", name)

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
	AllowedIPs    []string
	PrimaryRoutes []string
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
