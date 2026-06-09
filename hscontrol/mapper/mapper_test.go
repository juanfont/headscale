package mapper

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
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

// TestBuildFromChangeFiltersPeerPatchesByVisibility proves that incremental
// peer-change patches (online/offline, endpoint, key-expiry) are restricted to
// the recipient's ACL-visible peer set, the same way buildTailPeers filters
// full peer objects via policy.ReduceNodes. Without it, a node receives the
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
				Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}},
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
				Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}},
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
// It pins two behaviours the scattered per-path filters get wrong today and the
// consolidation onto the snapshot peer map must fix: deny-all (empty matchers)
// must hide every peer on the incremental path rather than fall open to "no
// matchers => all visible", and per-node policies (autogroup:self) must agree
// across paths.
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
				Regions: map[int]*tailcfg.DERPRegion{999: {RegionID: 999}},
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

	// wantFull pins the actual peer-visibility semantics so the invariant below
	// cannot pass vacuously (e.g. if every path broke to zero identically).
	// Note deny_all: an empty ACL set compiles to zero matchers, which headscale
	// treats as "no visibility restriction" — all peers are visible on every
	// path (the packet filter denies traffic separately). user_isolation and
	// autogroup_self are the discriminating cases that prove filtering works.
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
		{"deny_all", `{"acls":[]}`, 2},
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
