package mapper

import (
	stdcmp "cmp"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/views"
)

var iap = func(ipStr string) *netip.Addr {
	ip := netip.MustParseAddr(ipStr)
	return &ip
}

func TestDNSConfigMapResponse(t *testing.T) {
	tests := []struct {
		magicDNS bool
		want     *tailcfg.DNSConfig
	}{
		{
			magicDNS: true,
			want: &tailcfg.DNSConfig{
				Routes: map[string][]*dnstype.Resolver{},
				Domains: []string{
					"foobar.headscale.net",
				},
				Proxied: true,
			},
		},
		{
			magicDNS: false,
			want: &tailcfg.DNSConfig{
				Domains: []string{"foobar.headscale.net"},
				Proxied: false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("with-magicdns-%v", tt.magicDNS), func(t *testing.T) {
			mach := func(hostname, username string, userid uint) *types.Node {
				return &types.Node{
					Hostname: hostname,
					UserID:   new(userid),
					User: &types.User{
						Name: username,
					},
				}
			}

			baseDomain := "foobar.headscale.net"

			dnsConfigOrig := tailcfg.DNSConfig{
				Routes:  make(map[string][]*dnstype.Resolver),
				Domains: []string{baseDomain},
				Proxied: tt.magicDNS,
			}

			nodeInShared1 := mach("test_get_shared_nodes_1", "shared1", 1)

			got := generateDNSConfig(
				&types.Config{
					TailcfgDNSConfig: &dnsConfigOrig,
				},
				nodeInShared1.View(),
				nil,
			)

			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Errorf("expandAlias() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNextDNSCapMapRendering(t *testing.T) {
	t.Parallel()

	mkConfig := func(addrs ...string) *types.Config {
		resolvers := make([]*dnstype.Resolver, len(addrs))
		for i, a := range addrs {
			resolvers[i] = &dnstype.Resolver{Addr: a}
		}

		return &types.Config{
			TailcfgDNSConfig: &tailcfg.DNSConfig{
				Resolvers: resolvers,
			},
		}
	}

	mkNode := func() types.NodeView {
		return (&types.Node{
			ID:       1,
			Hostname: "node1",
			IPv4:     iap("100.64.0.1"),
			Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
		}).View()
	}

	// resolverAddr extracts the first resolver's address with a
	// bounds check. Without it, a regression that drops the
	// resolver list would nil-panic instead of failing cleanly.
	resolverAddr := func(t *testing.T, got *tailcfg.DNSConfig) string {
		t.Helper()

		if got == nil {
			t.Fatalf("generateDNSConfig returned nil")
		}

		if len(got.Resolvers) == 0 {
			t.Fatalf("generateDNSConfig returned no Resolvers")
		}

		return got.Resolvers[0].Addr
	}

	t.Run("no_capmap_metadata_appended", func(t *testing.T) {
		t.Parallel()

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/abc"),
			mkNode(),
			nil,
		)

		want := "https://dns.nextdns.io/abc?device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("profile_overrides_global", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:override": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/override?device_ip=100.64.0.1&device_model=linux&device_name=node1"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("no_device_info_skips_metadata", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc":            []tailcfg.RawMessage{},
			"nextdns:no-device-info": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.nextdns.io/global"),
			mkNode(),
			capMap,
		)

		want := "https://dns.nextdns.io/abc"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("addr = %q, want %q", addr, want)
		}
	})

	t.Run("non_nextdns_resolver_untouched", func(t *testing.T) {
		t.Parallel()

		capMap := tailcfg.NodeCapMap{
			"nextdns:abc": []tailcfg.RawMessage{},
		}

		got := generateDNSConfig(
			mkConfig("https://dns.example.org/dns-query"),
			mkNode(),
			capMap,
		)

		want := "https://dns.example.org/dns-query"
		if addr := resolverAddr(t, got); addr != want {
			t.Errorf("non-nextdns resolver was rewritten: %q", addr)
		}
	})
}

// nextDNSResolverSkipReasons lists checks where headscale's DoH address
// differs from SaaS, keyed <test_id>/<check>.
var nextDNSResolverSkipReasons = map[string]string{
	"nodeattrs-nextdns-d10-resolver-default/device_id":   nextDNSDeviceID,
	"nodeattrs-nextdns-d11-resolver-profile/device_id":   nextDNSDeviceID,
	"nodeattrs-nextdns-d13-resolver-malformed/device_id": nextDNSDeviceID,
}

const nextDNSDeviceID = "NEXTDNS_DEVICE_ID: SaaS adds the node's stable ID to the DoH query as device_id; headscale does not"

// TestNextDNSResolverCompat compares the NextDNS DoH address every node gets
// with what SaaS sent: the global profile, a per-node profile, and a
// malformed one, which SaaS skips. The captured self CapMap stands in for
// the policy, so only the resolver rewrite is compared.
//
// Test data source: ../policy/v2/testdata/nodeattrs_results/, shared with
// TestNodeAttrsCompat, which compares the same captures' CapMaps.
func TestNextDNSResolverCompat(t *testing.T) {
	t.Parallel()

	for _, id := range []string{
		"nodeattrs-nextdns-d10-resolver-default",
		"nodeattrs-nextdns-d11-resolver-profile",
		"nodeattrs-nextdns-d13-resolver-malformed",
	} {
		t.Run(id, func(t *testing.T) {
			t.Parallel()

			c, err := testcapture.Read(filepath.Join(
				"..", "policy", "v2", "testdata", "nodeattrs_results", id+".hujson",
			))
			require.NoError(t, err)

			resolvers := make([]*dnstype.Resolver, 0, len(c.Input.Tailnet.DNS.Nameservers))
			for _, ns := range c.Input.Tailnet.DNS.Nameservers {
				resolvers = append(resolvers, &dnstype.Resolver{Addr: ns})
			}

			cfg := &types.Config{TailcfgDNSConfig: &tailcfg.DNSConfig{Resolvers: resolvers}}

			// Mismatches by check, one entry per node.
			diffs := map[string][]string{}

			for i, name := range slices.Sorted(maps.Keys(c.Captures)) {
				self := c.Captures[name].Netmap.SelfNode
				topo := c.Topology.Nodes[name]

				// The capture fleet runs tailscaled on Linux; the self
				// Hostinfo SaaS echoes back leaves the OS out.
				node := &types.Node{
					ID:       types.NodeID(i + 1), //nolint:gosec
					Hostname: topo.Hostname,
					IPv4:     iap(topo.IPv4),
					IPv6:     iap(topo.IPv6),
					Hostinfo: &tailcfg.Hostinfo{OS: "linux"},
				}

				capMap := tailcfg.NodeCapMap{}
				for k, v := range self.CapMap().All() {
					capMap[k] = v.AsSlice()
				}

				got := generateDNSConfig(cfg, node.View(), capMap)
				want := c.Captures[name].Netmap.DNS.Resolvers

				wantAddr, wantQuery, wantID := splitDoHAddrs(t, want, self.StableID())
				gotAddr, gotQuery, gotID := splitDoHAddrs(t, got.Resolvers, node.ID.StableID())

				for check, diff := range map[string]string{
					"path":      cmp.Diff(wantAddr, gotAddr),
					"query":     cmp.Diff(wantQuery, gotQuery),
					"device_id": cmp.Diff(wantID, gotID),
				} {
					if diff != "" {
						diffs[check] = append(diffs[check], name+" (-tailscale +headscale):\n"+diff)
					}
				}
			}

			for _, check := range []string{"path", "query", "device_id"} {
				t.Run(check, func(t *testing.T) {
					key := id + "/" + check
					reason, listed := nextDNSResolverSkipReasons[key]

					switch {
					case listed && len(diffs[check]) == 0:
						t.Errorf("matches SaaS; delete the skip entry %q (%s)", key, reason)
					case listed:
						t.Skip(reason)
					case len(diffs[check]) > 0:
						t.Error(strings.Join(diffs[check], "\n"))
					}
				})
			}
		})
	}
}

// splitDoHAddrs returns each resolver's address without its query, the query
// without device_id, and device_id, read as "self" when it is selfID.
func splitDoHAddrs(
	t *testing.T,
	rs []*dnstype.Resolver,
	selfID tailcfg.StableNodeID,
) ([]string, []url.Values, []string) {
	t.Helper()

	addrs := make([]string, 0, len(rs))
	queries := make([]url.Values, 0, len(rs))
	ids := make([]string, 0, len(rs))

	for _, r := range rs {
		u, err := url.Parse(r.Addr)
		require.NoError(t, err)

		q := u.Query()

		id := q.Get("device_id")
		if id == string(selfID) {
			id = "self"
		}

		q.Del("device_id")

		u.RawQuery = ""

		addrs, queries, ids = append(addrs, u.String()), append(queries, q), append(ids, id)
	}

	return addrs, queries, ids
}

// TestBuildFromChangeFiltersPeerPatchesByVisibility proves that incremental
// peer-change patches (online/offline, endpoint, key-expiry) are restricted to
// the recipient's ACL-visible peer set, the same NodeStore peer map
// buildTailPeers is fed from. Without it, a node receives the
// existence, presence, and addresses of peers its policy forbids accessing.
func TestBuildFromChangeFiltersPeerPatchesByVisibility(t *testing.T) {
	tmp := t.TempDir()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user1 := database.CreateUserForTest("u1")
	user2 := database.CreateUserForTest("u2")
	n1 := database.CreateRegisteredNodeForTest(user1, "n1")
	n1b := database.CreateRegisteredNodeForTest(user1, "n1b")
	n2 := database.CreateRegisteredNodeForTest(user2, "n2")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Each user may reach only its own devices, so n1 cannot access n2.
	policy := `{"acls":[
		{"action":"accept","src":["u1@"],"dst":["u1@:*"]},
		{"action":"accept","src":["u2@"],"dst":["u2@:*"]}
	]}`
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)

	m := &mapper{state: s, cfg: cfg}

	// n2 (user2) comes online; n1 (user1) must NOT receive its patch.
	leakChange := change.NodeOnline(n2.ID)
	resp, err := m.buildFromChange(n1.ID, tailcfg.CurrentCapabilityVersion, &leakChange)
	require.NoError(t, err)
	require.NotNil(t, resp)

	for _, p := range resp.PeersChangedPatch {
		assert.NotEqual(t, n2.ID.NodeID(), p.NodeID,
			"n1 must not receive an online patch for n2, which its policy forbids accessing")
	}

	// Control: n1b (same user) coming online IS visible to n1.
	okChange := change.NodeOnline(n1b.ID)
	resp2, err := m.buildFromChange(n1.ID, tailcfg.CurrentCapabilityVersion, &okChange)
	require.NoError(t, err)
	require.NotNil(t, resp2)

	var gotVisible bool

	for _, p := range resp2.PeersChangedPatch {
		if p.NodeID == n1b.ID.NodeID() {
			gotVisible = true
		}
	}

	assert.True(t, gotVisible,
		"n1 must receive the online patch for visible same-user peer n1b")
}

// TestBuildFromChangeFiltersUserProfilesByVisibility proves the incremental
// PeersChanged path restricts UserProfiles to the recipient's ACL-visible
// peers, like the full-map path (whose ListPeers returns the
// BuildPeerMap-filtered set). Without it, a changed node broadcast to all
// nodes leaks its owner's identity (login name, display name, avatar) to
// recipients whose policy forbids accessing that node.
func TestBuildFromChangeFiltersUserProfilesByVisibility(t *testing.T) {
	tmp := t.TempDir()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user1 := database.CreateUserForTest("u1")
	user2 := database.CreateUserForTest("u2")
	n1 := database.CreateRegisteredNodeForTest(user1, "n1")
	n2 := database.CreateRegisteredNodeForTest(user2, "n2")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// Each user may reach only its own devices, so n1 cannot access n2.
	policy := `{"acls":[
		{"action":"accept","src":["u1@"],"dst":["u1@:*"]},
		{"action":"accept","src":["u2@"],"dst":["u2@:*"]}
	]}`
	_, err = s.SetPolicy([]byte(policy))
	require.NoError(t, err)

	m := &mapper{state: s, cfg: cfg}

	// n2 (user2) is added and broadcast. n1 (user1) cannot access it, so n1
	// must NOT receive user2's profile.
	c := change.NodeAdded(n2.ID)
	resp, err := m.buildFromChange(n1.ID, tailcfg.CurrentCapabilityVersion, &c)
	require.NoError(t, err)
	require.NotNil(t, resp)

	for _, up := range resp.UserProfiles {
		assert.NotEqual(t, user2.TailscaleUserProfile().ID, up.ID,
			"n1 must not receive user2's profile; n2 is not ACL-visible to n1")
	}
}

// TestBuildFromChangeVisibilityMatchesFullMap is the consolidation guard for
// PR #3304: the incremental change paths (peer patches via NodeOnline, changed
// peers via NodeAdded) must expose exactly the same ACL-visible peer set as the
// full-map path under every policy shape, and a cross-user UserProfile must not
// leak. If a future refactor lets one path drift from another, this fails.
//
// It pins two behaviours of the snapshot peer map every path reads: deny-all
// (empty matchers) must hide every peer on the incremental path rather than
// fall open to "no matchers => all visible", and per-node policies
// (autogroup:self) must agree across paths.
func TestBuildFromChangeVisibilityMatchesFullMap(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user1 := database.CreateUserForTest("u1")
	user2 := database.CreateUserForTest("u2")
	n1 := database.CreateRegisteredNodeForTest(user1, "n1")
	n1b := database.CreateRegisteredNodeForTest(user1, "n1b")
	n2 := database.CreateRegisteredNodeForTest(user2, "n2")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	m := &mapper{state: s, cfg: cfg}
	capVer := tailcfg.CurrentCapabilityVersion

	// fullVisible returns the peer IDs n1 sees in the full map.
	fullVisible := func(t *testing.T) map[tailcfg.NodeID]bool {
		t.Helper()

		resp, err := m.fullMapResponse(n1.ID, capVer)
		require.NoError(t, err)

		got := map[tailcfg.NodeID]bool{}
		for _, p := range resp.Peers {
			got[p.ID] = true
		}

		return got
	}
	// patchReaches reports whether a NodeOnline patch for id is delivered to n1.
	patchReaches := func(t *testing.T, id types.NodeID) bool {
		t.Helper()

		c := change.NodeOnline(id)
		resp, err := m.buildFromChange(n1.ID, capVer, &c)
		require.NoError(t, err)

		if resp == nil {
			return false
		}

		for _, p := range resp.PeersChangedPatch {
			if p.NodeID == id.NodeID() {
				return true
			}
		}

		return false
	}
	// changedReaches reports whether a NodeAdded changed-peer for id reaches n1.
	changedReaches := func(t *testing.T, id types.NodeID) bool {
		t.Helper()

		c := change.NodeAdded(id)
		resp, err := m.buildFromChange(n1.ID, capVer, &c)
		require.NoError(t, err)

		if resp == nil {
			return false
		}

		for _, p := range resp.PeersChanged {
			if p.ID == id.NodeID() {
				return true
			}
		}

		return false
	}
	// profileReaches reports whether want's profile is delivered to n1 when n
	// is added. Use a cross-user node so the result is not masked by n1's own
	// always-present user profile.
	profileReaches := func(t *testing.T, n *types.Node, want tailcfg.UserID) bool {
		t.Helper()

		c := change.NodeAdded(n.ID)
		resp, err := m.buildFromChange(n1.ID, capVer, &c)
		require.NoError(t, err)

		if resp == nil {
			return false
		}

		for _, up := range resp.UserProfiles {
			if up.ID == want {
				return true
			}
		}

		return false
	}

	// wantFull pins the actual peer-visibility semantics so the cross-path
	// check below cannot pass vacuously (e.g. if every path broke to zero
	// identically).
	// Note deny_all: an empty ACL set yields no peer adjacency, so nothing is
	// visible on any path. user_isolation and autogroup_self remain the
	// discriminating cases that prove filtering works.
	tests := []struct {
		name     string
		policy   string
		wantFull int
	}{
		{"allow_all", `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`, 2},
		{
			"user_isolation",
			`{"acls":[
				{"action":"accept","src":["u1@"],"dst":["u1@:*"]},
				{"action":"accept","src":["u2@"],"dst":["u2@:*"]}
			]}`,
			1,
		},
		{"deny_all", `{"acls":[]}`, 0},
		{
			"autogroup_self",
			`{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
			1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := s.SetPolicy([]byte(tt.policy))
			require.NoError(t, err)

			full := fullVisible(t)
			require.Lenf(t, full, tt.wantFull,
				"%s: unexpected full-map visible peer count", tt.name)

			for _, peer := range []*types.Node{n1b, n2} {
				want := full[peer.ID.NodeID()]
				assert.Equalf(t, want, patchReaches(t, peer.ID),
					"%s: NodeOnline patch for %s must reach n1 iff full-map shows it",
					tt.name, peer.Hostname)
				assert.Equalf(t, want, changedReaches(t, peer.ID),
					"%s: NodeAdded changed-peer for %s must reach n1 iff full-map shows it",
					tt.name, peer.Hostname)
			}
			// Cross-user profile (user2) must appear iff n2 is visible to n1.
			assert.Equalf(t, full[n2.ID.NodeID()], profileReaches(t, n2, user2.TailscaleUserProfile().ID),
				"%s: user2 profile must be sent iff n2 is visible to n1", tt.name)
		})
	}
}

// TestFullMapResponseSurvivesPeerWithInvalidData proves a single node with
// stored data that cannot be sent must not break map generation for its peers.
//
// A node whose stored GivenName is empty (ErrNodeHasNoGivenName) or yields an
// FQDN longer than MaxHostnameLength (ErrHostnameTooLong) makes GetFQDN, and
// therefore TailNode, return an error. buildTailPeers used to abort the entire
// peer list on the first such error, so MapResponseBuilder.Build() failed for
// every node that could see the bad peer; on the initial-connection path that
// surfaced as "PollNetMap: ... unexpected EOF" and the "Unable to connect to
// the Tailscale coordination server" health warning. A legacy DB row loads
// verbatim (NewNodeStore reads db.ListNodes() without re-sanitising names), so
// the bad peer persists across restart. The build for an unaffected viewer
// must succeed: the bad peer is dropped, valid peers and self survive.
//
// A key expiry outside the years [0,9999] in UTC is the same class, caught
// later: TailNode sends it in UTC and json.Marshal refuses it.
func TestFullMapResponseSurvivesPeerWithInvalidData(t *testing.T) {
	// Each expiry is in range in its own zone and out of range in UTC.
	west := time.FixedZone("", -(23*60+59)*60)
	east := time.FixedZone("", (23*60+59)*60)

	for _, tt := range []struct {
		name   string
		column string
		value  any
	}{
		{"empty given name", "given_name", ""},
		{
			"over-long fqdn", "given_name",
			strings.Repeat("a", types.MaxHostnameLength+1),
		},
		{
			"expiry after year 9999", "expiry",
			time.Date(9999, time.December, 31, 23, 59, 59, 0, west),
		},
		{
			"expiry before year 0", "expiry",
			time.Date(0, time.January, 1, 0, 0, 0, 0, east),
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			tmp := t.TempDir()
			p4 := netip.MustParsePrefix("100.64.0.0/10")
			p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
			cfg := &types.Config{
				Database: types.DatabaseConfig{
					Type:   types.DatabaseSqlite,
					Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
				},
				PrefixV4:     &p4,
				PrefixV6:     &p6,
				IPAllocation: types.IPAllocationStrategySequential,
				BaseDomain:   "headscale.test",
				Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
				DERP: types.DERPConfig{
					DERPMap: &tailcfg.DERPMap{
						Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
					},
				},
				Tuning: types.Tuning{
					NodeStoreBatchSize:    state.TestBatchSize,
					NodeStoreBatchTimeout: state.TestBatchTimeout,
				},
			}

			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			user := database.CreateUserForTest("u1")
			n1 := database.CreateRegisteredNodeForTest(user, "n1")     // viewer, valid
			bad := database.CreateRegisteredNodeForTest(user, "bad")   // peer, bad data
			good := database.CreateRegisteredNodeForTest(user, "good") // peer, valid control

			// Simulate a legacy/corrupt row that v29 loads verbatim.
			require.NoError(t, database.DB.
				Model(&types.Node{}).
				Where("id = ?", bad.ID).
				Update(tt.column, tt.value).Error)
			require.NoError(t, database.Close())

			s, err := state.NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			// Allow-all so n1 sees both peers; the bad one must still be dropped.
			_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
			require.NoError(t, err)

			m := &mapper{state: s, cfg: cfg}
			capVer := tailcfg.CurrentCapabilityVersion

			resp, err := m.fullMapResponse(n1.ID, capVer)
			require.NoError(t, err,
				"n1's map must build despite a peer with invalid data")
			require.NotNil(t, resp)
			require.NotNil(t, resp.Node, "n1 must receive its own self node")

			_, err = json.Marshal(resp)
			require.NoError(t, err,
				"n1's map must encode despite a peer with invalid data")

			peers := map[tailcfg.NodeID]bool{}
			for _, p := range resp.Peers {
				peers[p.ID] = true
			}

			assert.False(t, peers[bad.ID.NodeID()],
				"the peer with invalid data must be dropped")
			assert.True(t, peers[good.ID.NodeID()], "valid peers must remain in the map")
		})
	}
}

// TestGenerateDNSConfigNilHostinfoNoPanic proves generateDNSConfig does not
// panic when a node's Hostinfo is nil (e.g. a legacy DB row with a NULL
// host_info column). addNextDNSMetadata dereferenced node.Hostinfo().OS()
// without the .Valid() guard its siblings (RequestTags, TailNode) apply, so
// building such a node's map crashed the server whenever a NextDNS resolver
// was configured.
func TestGenerateDNSConfigNilHostinfoNoPanic(t *testing.T) {
	node := (&types.Node{
		Hostname: "legacy-node",
		IPv4:     iap("100.64.0.1"),
		// Hostinfo intentionally nil, as a legacy NULL host_info row loads.
	}).View()

	cfg := &types.Config{
		TailcfgDNSConfig: &tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "https://dns.nextdns.io/abc"}},
		},
	}

	require.NotPanics(t, func() {
		generateDNSConfig(cfg, node, nil)
	}, "generateDNSConfig must not panic when a node has nil Hostinfo")
}

// policyShapes covers the paths that decide which peers the mapper sends: a
// global filter with matchers, a per-node (autogroup:self) filter, a policy
// that leaves every node with zero matchers, and no rules at all. The
// zero-matcher shape is the interesting one: it must hide every peer, not
// fall open to "no matchers => all visible".
var policyShapes = []struct {
	name   string
	policy string
}{
	{
		name:   "allow all",
		policy: `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`,
	},
	{
		name:   "autogroup self",
		policy: `{"acls":[{"action":"accept","src":["autogroup:member"],"dst":["autogroup:self:*"]}]}`,
	},
	{
		name:   "no rules",
		policy: `{"acls":[]}`,
	},
	{
		name:   "empty policy",
		policy: `{}`,
	},
}

// assertSelfNotAPeer fails when a [tailcfg.MapResponse] addressed to nodeID
// mentions nodeID in any peer-carrying field.
//
// The Tailscale client merges [tailcfg.MapResponse.PeersChanged] straight into
// its peer map (controlclient updatePeersStateFromResponse) and keeps the self
// node in a separate field, so a node present in its own peer list is rendered
// twice by clients that concatenate peers with self.
func assertSelfNotAPeer(t *testing.T, nodeID types.NodeID, resp *tailcfg.MapResponse, what string) {
	t.Helper()

	if resp == nil {
		return
	}

	self := nodeID.NodeID()

	for _, p := range resp.Peers {
		assert.NotEqualf(t, self, p.ID, "%s: node %d listed in its own Peers", what, nodeID)
	}

	for _, p := range resp.PeersChanged {
		assert.NotEqualf(t, self, p.ID, "%s: node %d listed in its own PeersChanged", what, nodeID)
	}

	for _, p := range resp.PeersChangedPatch {
		assert.NotEqualf(t, self, p.NodeID, "%s: node %d patched in its own PeersChangedPatch", what, nodeID)
	}

	for _, id := range resp.PeersRemoved {
		assert.NotEqualf(t, self, id, "%s: node %d listed in its own PeersRemoved", what, nodeID)
	}
}

// TestMapResponseNeverContainsSelfAsPeer drives the [change.Change] shapes the
// server emits through the response builder for every node, under each policy
// shape, and asserts the recipient is never present in its own peer fields.
func TestMapResponseNeverContainsSelfAsPeer(t *testing.T) {
	for _, tt := range policyShapes {
		t.Run(tt.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 2, 3, largeBufferSize)
			defer cleanup()

			_, err := testData.State.SetPolicy([]byte(tt.policy))
			require.NoError(t, err)

			batcher := unwrapBatcher(testData.Batcher)

			allIDs := make([]types.NodeID, 0, len(testData.Nodes))

			for i := range testData.Nodes {
				tn := &testData.Nodes[i]
				require.NoError(t, testData.Batcher.AddNode(tn.n.ID, tn.ch, 100, nil))
				allIDs = append(allIDs, tn.n.ID)
			}

			for _, recipient := range allIDs {
				changes := map[string]change.Change{
					"full self":     change.FullSelf(recipient),
					"full update":   change.FullUpdate(),
					"policy change": change.PolicyChange(),
					"self added":    change.NodeAdded(recipient),
					"self online":   change.NodeOnline(recipient),
					"self offline":  change.NodeOffline(recipient),
					// A batch naming every node, the recipient included.
					// change.PeersChanged carries no OriginNode, so the
					// self-update short circuit in buildFromChange never fires
					// and the peer lookup is the only thing left to drop self.
					"all peers changed": change.PeersChanged("all peers", allIDs...),
				}

				for name, ch := range changes {
					resp, err := batcher.MapResponseFromChange(recipient, ch)
					require.NoError(t, err, "%s for node %d", name, recipient)
					assertSelfNotAPeer(t, recipient, resp, name)
				}
			}
		})
	}
}

// TestNoSelfAsPeerDuringRealNodeChurn exercises the change flow poll.go drives
// (connect, disconnect, reconnect, policy reload, key expiry) and scans every
// delivered [tailcfg.MapResponse] for the recipient's own node.
func TestNoSelfAsPeerDuringRealNodeChurn(t *testing.T) {
	// How long a node's stream must stay silent before the churn counts as
	// settled and the scan moves on to the next node.
	const quietPeriod = 500 * time.Millisecond

	for _, tt := range policyShapes {
		t.Run(tt.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 2, 3, largeBufferSize)
			defer cleanup()

			_, err := testData.State.SetPolicy([]byte(tt.policy))
			require.NoError(t, err)

			batcher := testData.Batcher

			for i := range testData.Nodes {
				tn := &testData.Nodes[i]
				require.NoError(t, batcher.AddNode(tn.n.ID, tn.ch, 100, nil))
			}

			// Drop and re-add every node but the first, then reload the
			// policy and expire the one node that never reconnected.
			for i := 1; i < len(testData.Nodes); i++ {
				tn := &testData.Nodes[i]
				batcher.RemoveNode(tn.n.ID, tn.ch)
				require.NoError(t, batcher.AddNode(tn.n.ID, tn.ch, 100, nil))
			}

			_, err = testData.State.SetPolicy([]byte(tt.policy))
			require.NoError(t, err)

			expiry := time.Now().Add(time.Hour)

			_, c, err := testData.State.SetNodeExpiry(testData.Nodes[0].n.ID, &expiry)
			require.NoError(t, err)
			batcher.AddWork(c)

			for i := range testData.Nodes {
				tn := &testData.Nodes[i]

				for quiet := false; !quiet; {
					select {
					case resp := <-tn.ch:
						assertSelfNotAPeer(t, tn.n.ID, resp, "churn")
					case <-time.After(quietPeriod):
						quiet = true
					}
				}
			}
		})
	}
}

// TestBackfillNodeIPsReachesBackfilledNode proves the node that receives a
// backfilled address learns it too. Peers pick it up from the policy
// refresh, but that refresh carries no self node, so the node itself kept
// serving its old addresses until an unrelated self update.
func TestBackfillNodeIPsReachesBackfilledNode(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("u1")
	nodes := database.CreateRegisteredNodesForTest(user, 2, "bf")
	target := nodes[0].ID
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", target).Update("ipv6", nil).Error)
	// Backfill copies the stored Hostinfo, which a registered client always has.
	require.NoError(t, database.DB.Model(&types.Node{}).Where("1 = 1").Update("host_info", "{}").Error)
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	backfilled, cs, err := s.BackfillNodeIPs()
	require.NoError(t, err)
	require.NotEmpty(t, backfilled)

	stored, ok := s.GetNodeByID(target)
	require.True(t, ok)
	require.True(t, stored.IPv6().Valid(), "backfill must assign an IPv6 address")

	m := &mapper{state: s, cfg: cfg}
	nc := newMockNodeConnection(target)

	var self *tailcfg.Node

	for _, ch := range change.FilterForNode(target, cs) {
		resps, err := generateMapResponse(nc, m, ch)
		require.NoError(t, err)

		for _, resp := range resps {
			if resp.Node != nil {
				self = resp.Node
			}
		}
	}

	require.NotNil(t, self, "the backfilled node must receive its own node")
	assert.Contains(t, self.Addresses, netip.PrefixFrom(stored.IPv6().Get(), 128))
}

var errInjectedExpiry = errors.New("injected expiry failure")

// TestFailedExpiryOfPrimaryAnnouncesBackup expires the primary of an HA
// route while the database write fails. The NodeStore already moved the
// route to the backup, so the change returned with the error must still
// tell a client about the new primary, as the successful path does;
// otherwise the client drops the old primary's route with no replacement.
func TestFailedExpiryOfPrimaryAnnouncesBackup(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	route := netip.MustParsePrefix("10.77.0.0/24")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("u1")
	nodes := database.CreateRegisteredNodesForTest(user, 3, "ha")

	for _, n := range nodes[:2] {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
		n.ApprovedRoutes = []netip.Prefix{route}
		require.NoError(t, database.DB.Save(n).Error)
	}

	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	primary, backup, client := nodes[0].ID, nodes[1].ID, nodes[2].ID
	for _, id := range []types.NodeID{primary, backup, client} {
		s.Connect(id)
	}

	require.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(primary))

	require.NoError(t, s.DB().DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedExpiry)
			}
		}))
	t.Cleanup(func() { _ = s.DB().DB.Callback().Update().Remove("fail_node_update") })

	past := time.Now().Add(-time.Hour)
	_, c, err := s.SetNodeExpiry(primary, &past)
	require.ErrorIs(t, err, errInjectedExpiry)
	require.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(backup),
		"the NodeStore moved the route to the backup")

	m := &mapper{state: s, cfg: cfg}
	nc := newMockNodeConnection(client)

	var backupRoutes []netip.Prefix

	for _, ch := range change.FilterForNode(client, []change.Change{c}) {
		resps, err := generateMapResponse(nc, m, ch)
		require.NoError(t, err)

		for _, resp := range resps {
			for _, p := range append(resp.Peers, resp.PeersChanged...) {
				if p.ID == backup.NodeID() {
					backupRoutes = p.PrimaryRoutes
				}
			}
		}
	}

	assert.Contains(t, backupRoutes, route, "the client must learn the backup is primary: %s", c.Type())
}

// TestGenerateMapResponseDebugOnlyOnFullMaps pins where [tailcfg.Debug] rides:
// on every full map (the initial map and FullUpdate renders), so a client that
// connects or reconnects is told to stop log uploads, and on nothing else. The
// renders run through [generateMapResponse], the path the batcher uses, so a
// branch that bypasses buildFromChange cannot silently drop or add it.
func TestGenerateMapResponseDebugOnlyOnFullMaps(t *testing.T) {
	tmp := t.TempDir()
	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tmp + "/h.db"},
		},
		PrefixV4:     &p4,
		PrefixV6:     &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		DERP: types.DERPConfig{
			DERPMap: &tailcfg.DERPMap{
				Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{999: {RegionID: 999}},
			},
		},
		// Without these the DERP map and DNS config renders carry
		// nothing and no frame is generated at all.
		TailcfgDNSConfig: &tailcfg.DNSConfig{Proxied: true},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("u1")
	n1 := database.CreateRegisteredNodeForTest(user, "n1")
	n2 := database.CreateRegisteredNodeForTest(user, "n2")
	require.NoError(t, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	s.SetDERPMap(cfg.DERP.DERPMap)

	_, err = s.SetPolicy([]byte(`{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`))
	require.NoError(t, err)

	m := &mapper{state: s, cfg: cfg}

	kinds := []struct {
		name string
		c    change.Change
		full bool
	}{
		{"full_update", change.FullUpdate(), true},
		{"full_self", change.FullSelf(n1.ID), true},
		{"user_removed", change.UserRemoved(), true},
		{"self_update", change.SelfUpdate(n1.ID), false},
		{"self_node_added", change.NodeAdded(n1.ID), false},
		{"policy_change", change.PolicyChange(), false},
		{"derp_map", change.DERPMap(), false},
		{"dns_config", change.DNSConfig(), false},
		{"peer_added", change.NodeAdded(n2.ID), false},
		{"peer_online", change.NodeOnline(n2.ID), false},
	}

	for _, logTail := range []bool{false, true} {
		for _, k := range kinds {
			t.Run(fmt.Sprintf("logtail=%t/%s", logTail, k.name), func(t *testing.T) {
				cfg.LogTail.Enabled = logTail

				resps, err := generateMapResponse(newMockNodeConnection(n1.ID), m, k.c)
				require.NoError(t, err)
				require.Len(t, resps, 1)

				var want *tailcfg.Debug
				if k.full && !logTail {
					want = &tailcfg.Debug{DisableLogTail: true}
				}

				assert.Equal(t, want, resps[0].Debug)
			})
		}
	}
}

// TestCertDomains pins the name sent in DNSConfig.CertDomains: the
// client only runs `tailscale cert` for a name it finds there exactly,
// compared against its own MagicDNS name without the trailing dot.
func TestCertDomains(t *testing.T) {
	enabled := types.DNSConfig{Certificates: types.CertificatesConfig{Enabled: true}}

	acmeDNS, err := dns.NewProvider("acmedns", map[string]any{"config": map[string]any{
		"laptop.ts.example.com": map[string]any{
			"username":   "user",
			"password":   "pass",
			"subdomain":  "reg",
			"server_url": "https://auth.acme-dns.io",
		},
	}}, func(string) (any, bool) { return nil, false })
	require.NoError(t, err)

	tests := []struct {
		name       string
		node       *types.Node
		dns        types.DNSConfig
		provider   dns.Provider
		baseDomain string
		want       []string
	}{
		{
			name:     "own acme-dns registration",
			node:     &types.Node{GivenName: "laptop"},
			dns:      enabled,
			provider: acmeDNS,
			want:     []string{"laptop.ts.example.com"},
		},
		{
			// Without a registration of its own, the node's challenge would
			// be answered from a record another name's challenge shares.
			name:     "no acme-dns registration of its own",
			node:     &types.Node{GivenName: "desktop"},
			dns:      enabled,
			provider: acmeDNS,
		},
		{
			name: "user owned",
			node: &types.Node{GivenName: "laptop", UserID: new(uint(1))},
			dns:  enabled,
			want: []string{"laptop.ts.example.com"},
		},
		{
			name: "tagged",
			node: &types.Node{GivenName: "server", Tags: []string{"tag:server"}},
			dns:  enabled,
			want: []string{"server.ts.example.com"},
		},
		{
			name: "disabled",
			node: &types.Node{GivenName: "laptop"},
		},
		{
			// The operator gave this name, in another case, to a service; a
			// node naming itself grafana must not get a certificate for it.
			name: "extra record name",
			node: &types.Node{GivenName: "grafana"},
			dns:  enabled,
		},
		{
			// A wildcard order for *.svc shares its challenge record with
			// svc, so svc must not get one covering grafana.svc.
			name: "extra record below name",
			node: &types.Node{GivenName: "svc"},
			dns:  enabled,
		},
		{
			name: "label suffix of extra record",
			node: &types.Node{GivenName: "fana"},
			dns:  enabled,
			want: []string{"fana.ts.example.com"},
		},
		{
			// Renames are lowercased now; an older mixed-case name could
			// share its challenge record with another node's name.
			name: "mixed case name",
			node: &types.Node{GivenName: "Laptop"},
			dns:  enabled,
		},
		{
			name:       "challenge name too long",
			node:       &types.Node{GivenName: strings.Repeat("a", 63)},
			dns:        enabled,
			baseDomain: strings.Repeat("b.", 87) + "example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseDomain := tt.baseDomain
			if baseDomain == "" {
				baseDomain = "ts.example.com"
			}

			cfg := &types.Config{
				BaseDomain:   baseDomain,
				DNSConfig:    tt.dns,
				DNSChallenge: types.DNSChallengeConfig{Provider: tt.provider},
				TailcfgDNSConfig: &tailcfg.DNSConfig{
					Proxied: true,
					ExtraRecords: []tailcfg.DNSRecord{
						{Name: "Grafana.ts.example.com", Type: "A", Value: "100.64.0.3"},
						{Name: "grafana.svc.ts.example.com.", Type: "A", Value: "100.64.0.4"},
					},
				},
			}

			got := generateDNSConfig(cfg, tt.node.View(), nil)
			assert.Equal(t, tt.want, got.CertDomains)
			assert.Nil(t, cfg.TailcfgDNSConfig.CertDomains, "global DNS config must stay untouched")
		})
	}
}

// profileUserOriginal freezes the user profile helpers from 1096abfc8.
// This package cannot call the test-only originals in types.
type profileUserOriginal types.User

func (u *profileUserOriginal) StringID() string {
	if u == nil {
		return ""
	}

	return strconv.FormatUint(uint64(u.ID), 10)
}

func (u *profileUserOriginal) Username() string {
	return stdcmp.Or(
		u.Email,
		u.Name,
		u.ProviderIdentifier.String,
		u.StringID(),
	)
}

func (u *profileUserOriginal) Display() string {
	return stdcmp.Or(u.DisplayName, u.Username())
}

func (u *profileUserOriginal) TailscaleUserProfile() tailcfg.UserProfile {
	return tailcfg.UserProfile{
		ID:            tailcfg.UserID(u.ID), //nolint:gosec // UserID is bounded
		LoginName:     u.Username(),
		DisplayName:   u.Display(),
		ProfilePicURL: u.ProfilePicURL,
	}
}

// userProfileOriginal reads the view without cloning or calling changed helpers.
func userProfileOriginal(view *types.UserView) tailcfg.UserProfile {
	u := profileUserOriginal{
		Model:              view.Model(),
		Name:               view.Name(),
		Email:              view.Email(),
		DisplayName:        view.DisplayName(),
		ProviderIdentifier: view.ProviderIdentifier(),
		ProfilePicURL:      view.ProfilePicURL(),
	}

	return u.TailscaleUserProfile()
}

// generateUserProfilesOriginal freezes 1096abfc8, including its profile helpers.
func generateUserProfilesOriginal(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userMap[user.Model().ID] = &user

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

		userMap[peerUser.Model().ID] = &peerUser
	}

	var profiles []tailcfg.UserProfile

	for _, id := range slices.Sorted(maps.Keys(userMap)) {
		profiles = append(profiles, userProfileOriginal(userMap[id]))
	}

	return profiles
}

// generateUserProfilesPointerMap freezes the map work but uses current name helpers,
// so map-only benchmarks do not include the frozen profile's view adapter.
func generateUserProfilesPointerMap(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userMap[user.Model().ID] = &user

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

		userMap[peerUser.Model().ID] = &peerUser
	}

	var profiles []tailcfg.UserProfile

	for _, id := range slices.Sorted(maps.Keys(userMap)) {
		profiles = append(profiles, userMap[id].TailscaleUserProfile())
	}

	return profiles
}

func checkUserProfilesOriginal(
	t *testing.T,
	node types.NodeView,
	peers views.Slice[types.NodeView],
) {
	t.Helper()

	want := generateUserProfilesOriginal(node, peers)
	require.Equal(t, want, generateUserProfiles(node, peers))
	require.Equal(t, want, generateUserProfilesPointerMap(node, peers))
}

func TestGenerateUserProfilesMatchesOriginal(t *testing.T) {
	first := &types.User{
		ID: 7, Name: "first", DisplayName: "First",
		Email: "first@example.com", ProfilePicURL: "https://example.com/first",
	}
	last := &types.User{
		ID: 7, Name: "last", DisplayName: "Last",
		Email: "last@example.com", ProfilePicURL: "https://example.com/last",
	}
	other := &types.User{ID: 100}
	node := (&types.Node{ID: 1, UserID: new(first.ID), User: first}).View()
	duplicate := (&types.Node{ID: 2, UserID: new(last.ID), User: last}).View()
	peer := (&types.Node{ID: 3, UserID: new(other.ID), User: other}).View()
	orphan := (&types.Node{ID: 4}).View()
	missingUser := (&types.Node{ID: 5, UserID: new(first.ID)}).View()
	tagged := (&types.Node{ID: 6, Tags: []string{"tag:server"}}).View()
	taggedCreator := (&types.Node{
		ID: 7, Tags: []string{"tag:server"}, UserID: new(first.ID), User: first,
	}).View()
	zeroUser := (&types.Node{ID: 8, User: &types.User{}}).View()

	for _, tt := range []struct {
		name  string
		node  types.NodeView
		peers []types.NodeView
	}{
		{name: "nil_peers", node: node},
		{name: "empty_peers", node: node, peers: []types.NodeView{}},
		{name: "unowned_requester", node: orphan, peers: []types.NodeView{peer}},
		{name: "missing_requester_user", node: missingUser, peers: []types.NodeView{peer}},
		{name: "invalid_peer_after_unowned_requester", node: orphan, peers: []types.NodeView{{}}},
		{name: "invalid_owner_peers", node: node, peers: []types.NodeView{orphan, missingUser}},
		{name: "same_owner", node: node, peers: []types.NodeView{node, node, node}},
		{name: "last_peer_wins", node: node, peers: []types.NodeView{peer, node, duplicate}},
		{name: "reverse_duplicate_order", node: node, peers: []types.NodeView{duplicate, peer, node}},
		{name: "zero_id_and_no_user_id", node: zeroUser, peers: []types.NodeView{peer, node}},
		{name: "tagged_requester", node: tagged},
		{name: "tagged_requester_with_creator", node: taggedCreator},
		{name: "tagged_peers", node: node, peers: []types.NodeView{tagged, taggedCreator}},
		{
			name: "mixed_unsorted_owners", node: node,
			peers: []types.NodeView{taggedCreator, peer, orphan, zeroUser, tagged, duplicate},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			checkUserProfilesOriginal(t, tt.node, views.SliceOf(tt.peers))
		})
	}

	require.Equal(t, []tailcfg.UserProfile{
		{
			ID:            7,
			LoginName:     last.Email,
			DisplayName:   last.DisplayName,
			ProfilePicURL: last.ProfilePicURL,
		},
		{ID: 100, LoginName: "100", DisplayName: "100"},
	}, generateUserProfiles(node, views.SliceOf([]types.NodeView{peer, node, duplicate})))
	require.Equal(t, []tailcfg.UserProfile{
		{
			ID:          types.TaggedDevicesUserID,
			LoginName:   "tagged-devices",
			DisplayName: "Tagged Devices",
		},
	}, generateUserProfiles(taggedCreator, views.SliceOf([]types.NodeView{tagged})))
	require.Nil(t, generateUserProfiles(orphan, views.SliceOf([]types.NodeView{peer})))

	for _, tt := range []struct {
		name  string
		node  types.NodeView
		peers []types.NodeView
	}{
		{name: "invalid_requester"},
		{name: "invalid_peer", node: node, peers: []types.NodeView{{}}},
		{name: "invalid_peer_after_valid", node: node, peers: []types.NodeView{peer, {}}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			peers := views.SliceOf(tt.peers)

			require.Panics(t, func() { generateUserProfilesOriginal(tt.node, peers) })
			require.Panics(t, func() { generateUserProfiles(tt.node, peers) })
			require.Panics(t, func() { generateUserProfilesPointerMap(tt.node, peers) })
			require.Panics(t, func() { generateUserProfiles(tt.node, peers) })
		})
	}
}

func TestGenerateUserProfilesFallbacksMatchOriginal(t *testing.T) {
	for _, id := range []uint{0, 99, 100, 101, ^uint(0)} {
		for mask := range 32 {
			t.Run(fmt.Sprintf("ID=%d/fields=%02d", id, mask), func(t *testing.T) {
				u := &types.User{
					ID:                 id,
					ProfilePicURL:      "https://example.com/avatar",
					ProviderIdentifier: sql.NullString{Valid: mask&8 != 0},
				}

				if mask&1 != 0 {
					u.Email = "email@example.com"
				}

				if mask&2 != 0 {
					u.Name = "username"
				}

				if mask&4 != 0 {
					u.ProviderIdentifier.String = "https://issuer.example.com/subject"
				}

				if mask&16 != 0 {
					u.DisplayName = "Display Name"
				}

				node := (&types.Node{User: u}).View()
				checkUserProfilesOriginal(t, node, views.Slice[types.NodeView]{})

				tagged := (&types.Node{Tags: []string{"tag:server"}}).View()
				checkUserProfilesOriginal(
					t,
					tagged,
					views.SliceOf([]types.NodeView{node}),
				)
			})
		}
	}
}

func userProfilesFixture(
	peerCount, ownerCount int,
	names string,
) (types.NodeView, views.Slice[types.NodeView]) {
	users := make([]types.User, ownerCount)
	for i := range users {
		users[i].ID = uint(i + 1000)
		if names == "named" {
			users[i].Name = fmt.Sprintf("user-%d", i)
			users[i].Email = fmt.Sprintf("user-%d@example.com", i)
			users[i].DisplayName = fmt.Sprintf("User %d", i)
		}

		users[i].ProfilePicURL = "https://example.com/avatar"
	}

	peers := make([]types.NodeView, peerCount)
	for i := range peers {
		u := &users[i%ownerCount]
		peers[i] = (&types.Node{UserID: new(u.ID), User: u}).View()
	}

	return (&types.Node{UserID: new(users[0].ID), User: &users[0]}).View(), views.SliceOf(
		peers,
	)
}

func TestGenerateUserProfilesTailnetsMatchOriginal(t *testing.T) {
	for _, peerCount := range []int{8, 128, 1024, 8192} {
		for _, ownerCount := range []int{1, peerCount} {
			for _, names := range []string{"named", "numeric"} {
				t.Run(
					fmt.Sprintf("peers=%d/owners=%d/%s", peerCount, ownerCount, names),
					func(t *testing.T) {
						node, peers := userProfilesFixture(peerCount, ownerCount, names)
						checkUserProfilesOriginal(t, node, peers)
					},
				)
			}
		}
	}
}

func BenchmarkGenerateUserProfiles(b *testing.B) {
	for _, peerCount := range []int{8, 128, 1024, 8192} {
		for _, ownerCount := range []int{1, peerCount} {
			for _, names := range []string{"named", "numeric"} {
				b.Run(
					fmt.Sprintf("peers=%d/owners=%d/%s", peerCount, ownerCount, names),
					func(b *testing.B) {
						node, peers := userProfilesFixture(peerCount, ownerCount, names)
						require.Equal(
							b,
							generateUserProfilesOriginal(node, peers),
							generateUserProfiles(node, peers),
						)
						require.Equal(
							b,
							generateUserProfilesPointerMap(node, peers),
							generateUserProfiles(node, peers),
						)

						b.Run("frozen-original", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfilesOriginal(node, peers)
							}
						})
						b.Run("current", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfiles(node, peers)
							}
						})
						b.Run("pointer-map", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfilesPointerMap(node, peers)
							}
						})
						b.Run("value-map", func(b *testing.B) {
							b.ReportAllocs()

							for b.Loop() {
								_ = generateUserProfiles(node, peers)
							}
						})
					},
				)
			}
		}
	}
}

// Frozen from d00f135bf before selected capability snapshots; only names and cmp alias differ.
func (b *MapResponseBuilder) buildTailPeersCapMapsReference(peers views.Slice[types.NodeView]) ([]*tailcfg.Node, error) {
	node, ok := b.mapper.state.GetNodeByID(b.nodeID)
	if !ok {
		return nil, ErrNodeNotFoundMapper
	}

	// [State.RoutesForPeer] needs the unreduced matchers: every rule where the
	// node is source or destination, not only the [State.FilterForNode] rules
	// where it is destination.
	matchers, err := b.mapper.state.MatchersForNode(node)
	if err != nil {
		return nil, err
	}

	// Snapshot the per-node policy CapMap once per peer-list build
	// instead of locking the policy manager per peer. The per-call
	// path used to take pm.mu N times for an N-peer response.
	allCapMaps := b.mapper.state.NodeCapMaps()

	// Build tail nodes with per-peer via-aware route function.
	tailPeers := make([]*tailcfg.Node, 0, peers.Len())

	for _, peer := range peers.All() {
		// Pass the peer's policy CapMap as selfPolicyCaps so per-peer
		// address-shape rules (today: disable-ipv4) apply consistently
		// in the viewer's netmap. The CapMap merge into tn.CapMap is
		// overwritten by the PeerCapMap call below; only the address
		// filtering side-effect inside TailNode survives.
		tn, err := peer.TailNode(b.capVer, func(_ types.NodeID) []netip.Prefix {
			return b.mapper.state.RoutesForPeer(node, peer, matchers)
		}, b.mapper.cfg, allCapMaps[peer.ID()])
		if err != nil {
			// One peer with invalid data (e.g. an empty or over-long
			// GivenName that fails GetFQDN) must not blank out the map for
			// every node that can see it. Drop the offending peer, log it
			// with the identity an operator needs to fix it, and keep
			// building from the remaining valid peers.
			log.Warn().Caller().
				Err(err).
				Uint64(zf.NodeID, peer.ID().Uint64()).
				Str(zf.NodeHostname, peer.Hostname()).
				Uint64("map.viewer.node.id", b.nodeID.Uint64()).
				Msgf("dropping peer %d from map response: invalid node data; fix with `headscale nodes rename %d <name>`", peer.ID(), peer.ID())

			continue
		}

		// [tailcfg.Node.CapMap] on a peer carries the small set of
		// caps the Tailscale client reads from the peer view rather
		// than the self view (suggest-exit-node, dns-subdomain-resolve
		// — see [tailcfg.NodeAttrSuggestExitNode] and
		// [tailcfg.NodeAttrDNSSubdomainResolve]).
		// The Tailscale-hosted control plane stamps these only when
		// the peer satisfies the cap's emission condition; every other
		// cap stays off the peer view, leaving CapMap empty for most
		// peers. [policyv2.PeerCapMap] encodes those conditions.
		tn.CapMap = policyv2.PeerCapMap(peer, allCapMaps[peer.ID()])
		tn.Hostinfo = types.PeerHostinfo(tn.Hostinfo)

		if peer.IsExpired() {
			if peer.ActiveSessions() > 0 {
				tn.Online, tn.LastSeen = new(true), nil
			}

			tn.Endpoints, tn.HomeDERP = nil, 0
		}

		tailPeers = append(tailPeers, tn)
	}

	// Peers is always returned sorted by Node.ID.
	slices.SortStableFunc(tailPeers, func(a, b *tailcfg.Node) int {
		return stdcmp.Compare(a.ID, b.ID)
	})

	return tailPeers, nil
}

func (b *MapResponseBuilder) withPeersCapMapsReference(peers views.Slice[types.NodeView]) *MapResponseBuilder {
	tailPeers, err := b.buildTailPeersCapMapsReference(peers)
	if err != nil {
		b.addError(err)
		return b
	}

	b.resp.Peers = tailPeers

	return b
}

func (m *mapper) fullMapResponseCapMapsReference(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	peers := m.state.ListPeers(nodeID)

	return m.NewMapResponseBuilder(nodeID).
		WithDebugType(fullResponseDebug).
		WithCapabilityVersion(capVer).
		WithSelfNode().
		WithDERPMap().
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig().
		WithSSHPolicy().
		WithDNSConfig().
		WithUserProfiles(peers).
		WithPacketFilters().
		withPeersCapMapsReference(peers).
		Build()
}

// A star policy gives the viewer all peers without retaining a dense N² peer map.
func capMapsMapperFixture(tb testing.TB, n int, attrs string) (*mapper, []types.NodeView) {
	tb.Helper()

	p4 := netip.MustParsePrefix("100.64.0.0/10")
	p6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")
	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{Path: tb.TempDir() + "/caps.db"},
		},
		PrefixV4: &p4, PrefixV6: &p6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy:       types.PolicyConfig{Mode: types.PolicyModeDB},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    state.TestBatchSize,
			NodeStoreBatchTimeout: state.TestBatchTimeout,
		},
	}
	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(tb, err)

	user := database.CreateUserForTest("capuser")
	nodes := make(types.Nodes, n)
	ip4, ip6 := netip.MustParseAddr("100.64.0.1"), netip.MustParseAddr("fd7a:115c:a1e0::1")

	for i := range nodes {
		name := fmt.Sprintf("capnode%d", i+1)

		nodes[i] = &types.Node{
			ID: types.NodeID(i + 1), Hostname: name, GivenName: name,
			UserID: &user.ID, User: user,
			IPv4: new(ip4), IPv6: new(ip6),
			Hostinfo: &tailcfg.Hostinfo{},
		}
		if i%8 == 1 {
			routes := []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0"), netip.MustParsePrefix("::/0")}
			nodes[i].ApprovedRoutes = routes
			nodes[i].Hostinfo.RoutableIPs = routes
		}

		ip4, ip6 = ip4.Next(), ip6.Next()
	}

	require.NoError(tb, database.DB.Omit("User").CreateInBatches(nodes, 100).Error)
	_, err = database.SetPolicy(`{
		"acls":[{"action":"accept","src":["100.64.0.1"],"dst":["*:*"]}],
		"nodeAttrs":` + attrs + `}`)
	require.NoError(tb, err)
	require.NoError(tb, database.Close())

	s, err := state.NewState(cfg)
	require.NoError(tb, err)
	tb.Cleanup(func() { require.NoError(tb, s.Close()) })
	s.SetDERPMap(&tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{}})
	stored := s.ListNodes().AsSlice()
	slices.SortFunc(stored, func(a, b types.NodeView) int { return stdcmp.Compare(a.ID(), b.ID()) })
	require.Len(tb, stored, n)

	return &mapper{state: s, cfg: cfg}, stored
}

func TestBuildTailPeersCapMapsReference(t *testing.T) {
	for _, attrs := range []struct {
		name, policy string
	}{
		{"empty", `[]`},
		{"partial", `[{"target":["100.64.0.2"],"attr":["disable-ipv4","suggest-exit-node"]}]`},
		{"all", `[{"target":["*"],"attr":["disable-ipv4","suggest-exit-node"]}]`},
	} {
		t.Run(attrs.name, func(t *testing.T) {
			m, nodes := capMapsMapperFixture(t, 5, attrs.policy)
			duplicate := nodes[1].AsStruct()
			duplicate.GivenName = "same-id-different-name"
			missing := nodes[2].AsStruct()
			missing.ID = 999
			invalid := nodes[3].AsStruct()

			invalid.GivenName = ""
			for _, selection := range []struct {
				name  string
				peers []types.NodeView
			}{
				{"nil", nil},
				{"empty", []types.NodeView{}},
				{"one", nodes[1:2]},
				{"full", nodes[1:]},
				{"missing", []types.NodeView{missing.View()}},
				{"duplicates", []types.NodeView{nodes[3], duplicate.View(), nodes[1], nodes[2], nodes[1]}},
				{"invalid-name", []types.NodeView{invalid.View(), nodes[1]}},
			} {
				t.Run(selection.name, func(t *testing.T) {
					peers := views.SliceOf(selection.peers)
					before, err := json.Marshal(m.state.NodeCapMaps())
					require.NoError(t, err)

					builder := m.NewMapResponseBuilder(nodes[0].ID()).WithCapabilityVersion(tailcfg.CurrentCapabilityVersion)
					want, wantErr := builder.buildTailPeersCapMapsReference(peers)
					got, gotErr := builder.buildTailPeers(peers)
					require.Equal(t, wantErr, gotErr)
					require.Equal(t, want, got, "nil/empty, ordering, duplicates, routes and peer caps must match")
					require.NotNil(t, got)

					for _, peer := range got {
						if peer.ID == nodes[1].ID().NodeID() {
							require.Contains(t, peer.CapMap, nodecap.SuggestExitNode)

							if attrs.name != "empty" {
								require.Equal(t, []netip.Prefix{netip.PrefixFrom(nodes[1].IPv6().Get(), 128)}, peer.Addresses)
								require.NotContains(t, peer.CapMap, nodecap.Cap("disable-ipv4"), "self caps must not leak into the peer view")
							}
						}

						if peer.CapMap != nil {
							peer.CapMap["caller-only"] = nil
							delete(peer.CapMap, nodecap.SuggestExitNode)
						}
					}

					after, err := json.Marshal(m.state.NodeCapMaps())
					require.NoError(t, err)
					require.Equal(t, before, after, "rendering must not mutate manager-owned inner maps")

					again, err := builder.buildTailPeers(peers)
					require.NoError(t, err)
					require.Equal(t, want, again, "output mutations must not affect later builds")
				})
			}

			builder := m.NewMapResponseBuilder(999)
			want, wantErr := builder.buildTailPeersCapMapsReference(views.SliceOf(nodes))
			got, gotErr := builder.buildTailPeers(views.SliceOf(nodes))
			require.Equal(t, want, got)
			require.Equal(t, wantErr, gotErr)
			require.ErrorIs(t, gotErr, ErrNodeNotFoundMapper)

			for _, pol := range []string{
				"",
				`{"nodeAttrs":[{"target":["*"],"attr":["randomize-client-port"]}]}`,
				`{"randomizeClientPort":true}`,
			} {
				if pol != "" {
					_, err := m.state.SetPolicy([]byte(pol))
					require.NoError(t, err)
				}

				want, err := m.fullMapResponseCapMapsReference(nodes[0].ID(), tailcfg.CurrentCapabilityVersion)
				require.NoError(t, err)
				got, err := m.fullMapResponse(nodes[0].ID(), tailcfg.CurrentCapabilityVersion)
				require.NoError(t, err)

				want.ControlTime, got.ControlTime = nil, nil
				require.Equal(t, want, got)
			}
		})
	}
}

var (
	capMapsBuilderBenchmarkSink  []*tailcfg.Node
	capMapsResponseBenchmarkSink *tailcfg.MapResponse
)

func BenchmarkBuildTailPeersCapMaps(b *testing.B) {
	previousLevel := zerolog.GlobalLevel()

	zerolog.SetGlobalLevel(zerolog.InfoLevel)
	b.Cleanup(func() { zerolog.SetGlobalLevel(previousLevel) })

	for _, n := range []int{100, 1000, 10000} {
		for _, attrs := range []struct{ name, policy string }{
			{"empty", `[]`},
			{"partial", `[{"target":["100.64.0.2"],"attr":["disable-ipv4"]}]`},
			{"all", `[{"target":["*"],"attr":["disable-ipv4"]}]`},
		} {
			b.Run(fmt.Sprintf("N%d/%s", n, attrs.name), func(b *testing.B) {
				m, nodes := capMapsMapperFixture(b, n, attrs.policy)
				builder := m.NewMapResponseBuilder(nodes[0].ID()).WithCapabilityVersion(tailcfg.CurrentCapabilityVersion)

				allPeers := views.SliceOf(nodes[1:])
				for _, k := range []int{0, 1, 8, allPeers.Len()} {
					peers := allPeers.Slice(0, k)
					b.Run(fmt.Sprintf("K%d/reference", k), func(b *testing.B) {
						b.ReportAllocs()

						for b.Loop() {
							var err error

							capMapsBuilderBenchmarkSink, err = builder.buildTailPeersCapMapsReference(peers)
							if err != nil {
								b.Fatal(err)
							}
						}
					})
					b.Run(fmt.Sprintf("K%d/selected", k), func(b *testing.B) {
						b.ReportAllocs()

						for b.Loop() {
							var err error

							capMapsBuilderBenchmarkSink, err = builder.buildTailPeers(peers)
							if err != nil {
								b.Fatal(err)
							}
						}
					})
				}

				b.Run("fullresponse/reference", func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						var err error

						capMapsResponseBenchmarkSink, err = m.fullMapResponseCapMapsReference(nodes[0].ID(), tailcfg.CurrentCapabilityVersion)
						if err != nil {
							b.Fatal(err)
						}
					}
				})
				b.Run("fullresponse/selected", func(b *testing.B) {
					b.ReportAllocs()

					for b.Loop() {
						var err error

						capMapsResponseBenchmarkSink, err = m.fullMapResponse(nodes[0].ID(), tailcfg.CurrentCapabilityVersion)
						if err != nil {
							b.Fatal(err)
						}
					}
				})
			})
		}
	}
}
