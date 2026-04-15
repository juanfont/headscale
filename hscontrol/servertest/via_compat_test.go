// This file implements data-driven via grant compatibility tests using
// golden data captured from Tailscale SaaS (v29, v30, v31, v33, v35,
// v36). These scenarios exercise via grant steering with peer
// connectivity and cross-subnet forwarding.
//
// Test data source: ../policy/v2/testdata/grant_results/via-grant-v{29,30,31,33,35,36}.hujson
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

// viaCompatTests lists golden captures that exercise via grant steering.
var viaCompatTests = []struct {
	id   string
	desc string
}{
	{"via-grant-v29", "crossed subnet steering: group-a via router-a, group-b via router-b"},
	{"via-grant-v30", "crossed mixed: subnet via router-a/b, exit via exit-b/a"},
	{"via-grant-v31", "peer connectivity + via exit A/B steering"},
	{"via-grant-v33", "single via grant + HA primary election"},
	{"via-grant-v35", "via grant with unadvertised destination"},
	{"via-grant-v36", "full complex: peer connectivity + crossed subnet + crossed exit"},
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
// (specifically via-grant-v29, v30, v31, v33, v35, v36). These files are shared
// with TestGrantsCompat in the policy/v2 package. Any changes to the
// file format, field structure, or naming must be coordinated with
// BOTH tests.
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

			c, err := testcapture.Read(path)
			require.NoError(t, err, "failed to read %s", path)

			if c.Error {
				t.Skipf("test %s is an error case", tc.id)

				return
			}

			runViaMapCompat(t, c)
		})
	}
}

func runViaMapCompat(t *testing.T, c *testcapture.Capture) {
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

	// Create tagged clients matching the golden topology.
	// Nodes are created in SaaS registration order so headscale assigns
	// sequential DB IDs in the same relative order. This matters for
	// PrimaryRoutes election which uses lowest-node-ID-wins — the
	// tiebreaker must pick the same node as SaaS.
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

	// Determine which routes each node should advertise. If the golden
	// topology has explicit routable_ips, use those. Otherwise infer
	// from the netmap peer AllowedIPs and packet filter dst prefixes.
	nodeRoutes := inferNodeRoutes(t, c)

	// Build approved routes from topology. The topology's approved_routes
	// field records what SaaS actually approved (which may be a subset of
	// routable_ips). Using this instead of approving all advertised routes
	// ensures exit routes are only approved when SaaS approved them.
	nodeApproved := map[string][]netip.Prefix{}

	for name, node := range c.Topology.Nodes {
		for _, r := range node.ApprovedRoutes {
			nodeApproved[name] = append(
				nodeApproved[name], netip.MustParsePrefix(r),
			)
		}
	}

	// Advertise and approve routes in SaaS registration order. Via
	// grants depend on routes being advertised for compileViaGrant to
	// produce filter rules. The order matters because PrimaryRoutes
	// election is sticky — the first node to register a prefix becomes
	// primary.
	for _, name := range order {
		cl, ok := clients[name]
		if !ok {
			continue
		}

		routes := nodeRoutes[name]
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

		nodeID := findNodeID(t, srv, name)
		_, routeChange, err := srv.State().SetApprovedRoutes(
			nodeID, nodeApproved[name],
		)
		require.NoError(t, err)
		srv.App.Change(routeChange)
	}

	// Wait for peers based on golden netmap expected counts.
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

	// Ensure all nodes have received at least one MapResponse,
	// including nodes with 0 expected peers that skipped WaitForPeers.
	for name, cl := range clients {
		cl.WaitForCondition(t, name+" initial netmap", 15*time.Second,
			func(nm *netmap.NetworkMap) bool {
				return nm != nil
			})
	}

	// Compare each viewer's MapResponse against the golden netmap.
	for viewerName, cl := range clients {
		capture := c.Captures[viewerName]
		if capture.Netmap == nil {
			continue
		}

		t.Run(viewerName, func(t *testing.T) {
			nm := cl.Netmap()
			require.NotNil(t, nm, "netmap is nil")

			compareNetmap(t, nm, capture, clients)
		})
	}
}

// compareNetmap compares the headscale MapResponse against the
// captured netmap data in an IP-independent way. It validates:
//   - Peer visibility (which peers are present, by hostname)
//   - Route prefixes in AllowedIPs (non-Tailscale-IP entries like 10.44.0.0/16)
//   - Number of Tailscale IPs per peer (should be 2: one v4 + one v6)
//   - PrimaryRoutes per peer
//   - PacketFilter rule count and non-Tailscale dst prefixes
func compareNetmap(
	t *testing.T,
	got *netmap.NetworkMap,
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
) {
	t.Helper()

	require.NotNil(t, want.Netmap, "golden Netmap is nil")

	// Build golden peer map (only peers in our client set).
	wantPeers := map[string]tailcfg.NodeView{}

	for _, p := range want.Netmap.Peers {
		name := extractHostname(p.Name())
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
			wantRoutes := extractRoutePrefixesView(wantPeer.AllowedIPs())
			t.Errorf("peer %s: visible in Tailscale SaaS (routes=%v), missing in headscale",
				name, wantRoutes)

			continue
		}

		// Compare route prefixes in AllowedIPs (IP-independent).
		wantRoutes := extractRoutePrefixesView(wantPeer.AllowedIPs())
		slices.Sort(wantRoutes)

		assert.Equalf(t, wantRoutes, gotPeer.RoutePrefixes,
			"peer %s: route prefixes in AllowedIPs mismatch", name)

		// Tailscale IPs: count should match, and they must belong to
		// this peer (not some other node's IPs).
		wantTSIPCount := countTailscaleIPsView(wantPeer.AllowedIPs())

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
		var wantPRoutes []string
		for i := range wantPeer.PrimaryRoutes().Len() {
			wantPRoutes = append(wantPRoutes, wantPeer.PrimaryRoutes().At(i).String())
		}

		assert.ElementsMatchf(t, wantPRoutes, gotPeer.PrimaryRoutes,
			"peer %s: PrimaryRoutes mismatch", name)
	}

	// Check for extra peers headscale shows that Tailscale SaaS doesn't.
	for name := range gotPeers {
		if _, expected := wantPeers[name]; !expected {
			t.Errorf("peer %s: visible in headscale but NOT in Tailscale SaaS", name)
		}
	}

	// Compare PacketFilter rules (IP-independent).
	wantFilterRules := want.PacketFilterRules

	if !assert.Lenf(t, got.PacketFilter, len(wantFilterRules),
		"PacketFilter rule count mismatch") {
		return
	}

	// Resolve SaaS IPs → peer name and HS IPs → peer name so we can
	// compare rule sources structurally. Tailscale IPs in SaaS vs HS
	// allocations never match literally, but each IP belongs to a
	// peer with a stable hostname.
	saasAddrs := saasAddrsByPeer(want, clients)
	hsAddrs := hsAddrsByPeer(clients)

	// Compare destination prefixes per rule — subnet CIDRs like
	// 10.44.0.0/16 are stable between Tailscale SaaS and headscale.
	// Source IPs are re-keyed per peer identity before comparison.
	for i := range wantFilterRules {
		wantRule := wantFilterRules[i]
		gotMatch := got.PacketFilter[i]

		wantSrcIdents := canonicaliseSrcStrings(t, wantRule.SrcIPs, saasAddrs, i)
		gotSrcIdents := canonicaliseSrcPrefixes(t, gotMatch.Srcs, hsAddrs, i)

		assert.Equalf(t, wantSrcIdents, gotSrcIdents,
			"PacketFilter[%d]: source peer identities mismatch", i)

		// Destination prefixes: extract non-Tailscale-IP CIDRs
		// from both golden and headscale rules and compare.
		var wantDstPrefixes []string

		for _, dp := range wantRule.DstPorts {
			pfx, err := parsePrefixOrAddr(dp.IP)
			require.NoErrorf(t, err,
				"golden DstPorts[%d].IP %q should parse as prefix or addr", i, dp.IP)

			if !isTailscaleIP(pfx) {
				wantDstPrefixes = append(wantDstPrefixes, pfx.String())
			}
		}

		var gotDstPrefixes []string

		for _, dst := range gotMatch.Dsts {
			pfx := dst.Net
			if !isTailscaleIP(pfx) {
				gotDstPrefixes = append(gotDstPrefixes, pfx.String())
			}
		}

		slices.Sort(wantDstPrefixes)
		slices.Sort(gotDstPrefixes)

		assert.Equalf(t, wantDstPrefixes, gotDstPrefixes,
			"PacketFilter[%d]: non-Tailscale destination prefixes mismatch", i)
	}
}

// saasAddrsByPeer builds a map from SaaS Tailscale address to peer
// hostname using each capture's SelfNode.Addresses. Peers not in
// clients are skipped.
func saasAddrsByPeer(
	want testcapture.Node,
	clients map[string]*servertest.TestClient,
) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	if want.Netmap == nil {
		return out
	}

	// Walk peers listed in this netmap.
	for _, peer := range want.Netmap.Peers {
		name := extractHostname(peer.Name())
		if _, isOurs := clients[name]; !isOurs {
			continue
		}

		for i := range peer.Addresses().Len() {
			pfx := peer.Addresses().At(i)
			if isTailscaleIP(pfx) {
				out[pfx.Addr()] = name
			}
		}
	}

	// The viewer's own SelfNode addresses also appear as possible src.
	if want.Netmap.SelfNode.Valid() {
		name := extractHostname(want.Netmap.SelfNode.Name())

		if _, isOurs := clients[name]; isOurs {
			addrs := want.Netmap.SelfNode.Addresses()
			for i := range addrs.Len() {
				pfx := addrs.At(i)
				if isTailscaleIP(pfx) {
					out[pfx.Addr()] = name
				}
			}
		}
	}

	return out
}

// hsAddrsByPeer builds a map from headscale Tailscale address to peer
// hostname by walking each live client's self addresses.
func hsAddrsByPeer(clients map[string]*servertest.TestClient) map[netip.Addr]string {
	out := map[netip.Addr]string{}

	for name, cl := range clients {
		nm := cl.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		addrs := nm.SelfNode.Addresses()
		for i := range addrs.Len() {
			pfx := addrs.At(i)
			if isTailscaleIP(pfx) {
				out[pfx.Addr()] = name
			}
		}
	}

	return out
}

// canonicaliseSrcStrings converts a SrcIPs slice (as produced by the
// SaaS wire format) into a sorted list of canonical identifiers: "*"
// for wildcard, "peer:<name>" for each Tailscale address or prefix
// that resolves to a known peer, or the raw CIDR string for
// non-Tailscale prefixes. A Tailscale prefix wider than /32 (IPv4)
// or /128 (IPv6) expands to the union of its contained peers.
// Unresolvable Tailscale-range sources fail the test.
func canonicaliseSrcStrings(
	t *testing.T,
	srcs []string,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
) []string {
	t.Helper()

	seen := map[string]struct{}{}

	for _, src := range srcs {
		if src == "*" {
			seen["*"] = struct{}{}

			continue
		}

		pfx, err := parsePrefixOrAddr(src)
		require.NoErrorf(t, err,
			"PacketFilter[%d]: unparseable SrcIP %q", ruleIndex, src)

		addIdentsForSrc(t, pfx, addrToPeer, ruleIndex, seen)
	}

	return sortedKeys(seen)
}

// canonicaliseSrcPrefixes is the headscale-side counterpart of
// canonicaliseSrcStrings, reading already-parsed netip.Prefix values
// from tailcfg.Match.Srcs.
func canonicaliseSrcPrefixes(
	t *testing.T,
	srcs []netip.Prefix,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
) []string {
	t.Helper()

	seen := map[string]struct{}{}

	for _, pfx := range srcs {
		if pfx.Bits() == 0 && pfx.Addr().IsUnspecified() {
			seen["*"] = struct{}{}

			continue
		}

		addIdentsForSrc(t, pfx, addrToPeer, ruleIndex, seen)
	}

	return sortedKeys(seen)
}

// addIdentsForSrc resolves one source prefix into canonical identity
// tokens and inserts them into seen. A non-Tailscale prefix passes
// through literally; a Tailscale-range prefix expands to the union
// of peer names whose addresses fall within it.
func addIdentsForSrc(
	t *testing.T,
	pfx netip.Prefix,
	addrToPeer map[netip.Addr]string,
	ruleIndex int,
	seen map[string]struct{},
) {
	t.Helper()

	if !prefixInTailscaleRange(pfx) {
		seen[pfx.String()] = struct{}{}

		return
	}

	matched := false

	for addr, name := range addrToPeer {
		if pfx.Contains(addr) {
			seen["peer:"+name] = struct{}{}
			matched = true
		}
	}

	require.Truef(t, matched,
		"PacketFilter[%d]: Tailscale-range SrcIP %s does not cover any known peer; addrToPeer=%v",
		ruleIndex, pfx, addrToPeer)
}

// prefixInTailscaleRange reports whether a prefix lies entirely
// within the Tailscale CGNAT range (100.64.0.0/10) or Tailscale ULA
// range (fd7a:115c:a1e0::/48), regardless of prefix length.
func prefixInTailscaleRange(p netip.Prefix) bool {
	addr := p.Addr()

	if addr.Is4() {
		return addr.As4()[0] == 100 && (addr.As4()[1]&0xC0) == 64
	}

	if addr.Is6() {
		b := addr.As16()

		return b[0] == 0xfd && b[1] == 0x7a && b[2] == 0x11 && b[3] == 0x5c //nolint:gosec // As16 returns [16]byte, indexing [0..3] is safe
	}

	return false
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}

	slices.Sort(out)

	return out
}

type peerSummary struct {
	TailscaleIPs  []netip.Prefix // Tailscale address entries from AllowedIPs
	RoutePrefixes []string       // non-Tailscale-IP AllowedIPs (sorted)
	PrimaryRoutes []string       // sorted
}

// parsePrefixOrAddr parses a string as a netip.Prefix. If the string
// is a bare IP address (no slash), it is converted to a single-host
// prefix (/32 for IPv4, /128 for IPv6). Golden data DstPorts.IP can
// contain either form.
func parsePrefixOrAddr(s string) (netip.Prefix, error) {
	pfx, err := netip.ParsePrefix(s)
	if err == nil {
		return pfx, nil
	}

	addr, addrErr := netip.ParseAddr(s)
	if addrErr != nil {
		return netip.Prefix{}, err // return original prefix error
	}

	return netip.PrefixFrom(addr, addr.BitLen()), nil
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

// extractRoutePrefixesView returns the non-Tailscale-IP entries from
// a typed AllowedIPs view (subnet routes, exit routes, etc.).
func extractRoutePrefixesView(allowedIPs interface {
	Len() int
	At(i int) netip.Prefix
},
) []string {
	var routes []string

	for i := range allowedIPs.Len() {
		pfx := allowedIPs.At(i)
		if !isTailscaleIP(pfx) {
			routes = append(routes, pfx.String())
		}
	}

	return routes
}

// countTailscaleIPsView returns the number of Tailscale IP entries
// in a typed AllowedIPs view.
func countTailscaleIPsView(allowedIPs interface {
	Len() int
	At(i int) netip.Prefix
},
) int {
	count := 0

	for i := range allowedIPs.Len() {
		if isTailscaleIP(allowedIPs.At(i)) {
			count++
		}
	}

	return count
}

// inferNodeRoutes determines which routes each node should advertise.
// If the topology has explicit routable_ips, those are used. Otherwise
// routes are inferred from the netmap peer AllowedIPs and packet
// filter destination prefixes.
func inferNodeRoutes(t *testing.T, c *testcapture.Capture) map[string][]netip.Prefix {
	t.Helper()

	result := map[string][]netip.Prefix{}

	// First use explicit routable_ips from topology.
	for name, node := range c.Topology.Nodes {
		for _, r := range node.RoutableIPs {
			result[name] = append(result[name], netip.MustParsePrefix(r))
		}
	}

	// If any node already has routes, the topology is populated — use as-is.
	for _, routes := range result {
		if len(routes) > 0 {
			return result
		}
	}

	// Tier 2: infer from each capture's netmap — scan peers with
	// route prefixes in AllowedIPs. If node X appears as a peer with
	// route prefix 10.44.0.0/16, then X should advertise that route.
	for _, node := range c.Captures {
		if node.Netmap == nil {
			continue
		}

		for _, peer := range node.Netmap.Peers {
			peerName := extractHostname(peer.Name())

			for i := range peer.AllowedIPs().Len() {
				pfx := peer.AllowedIPs().At(i)
				if isTailscaleIP(pfx) {
					continue
				}

				if !slices.Contains(result[peerName], pfx) {
					result[peerName] = append(result[peerName], pfx)
				}
			}
		}
	}

	// Tier 3: infer from packet_filter_rules DstPorts — secondary HA
	// routers whose routes don't appear in AllowedIPs (only the
	// primary gets the route in AllowedIPs) DO receive filter rules
	// for those routes.
	for nodeName, node := range c.Captures {
		for _, rule := range node.PacketFilterRules {
			for _, dp := range rule.DstPorts {
				if dp.IP == "*" {
					continue
				}

				prefix, err := parsePrefixOrAddr(dp.IP)
				require.NoErrorf(t, err,
					"golden DstPorts.IP %q for %s unparseable", dp.IP, nodeName)

				if isTailscaleIP(prefix) {
					continue
				}

				if !slices.Contains(result[nodeName], prefix) {
					result[nodeName] = append(
						result[nodeName], prefix,
					)
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
