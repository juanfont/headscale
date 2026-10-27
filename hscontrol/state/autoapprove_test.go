package state

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// TestRouteApprovalWaitsForAnnouncement: approvers run when the announced
// set changes, over every announced route, and neither on a policy reload
// nor on a report that keeps the routes.
func TestRouteApprovalWaitsForAnnouncement(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")
	added := netip.MustParsePrefix("10.0.1.0/24")

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	report := func(hostname string, routes ...netip.Prefix) {
		t.Helper()

		_, err := s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
			NodeKey:  nv.NodeKey(),
			DiscoKey: nv.DiscoKey(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname, RoutableIPs: routes},
		})
		require.NoError(t, err)
	}
	approved := func() []netip.Prefix {
		t.Helper()

		current, ok := s.GetNodeByID(nodeID)
		require.True(t, ok)

		return current.ApprovedRoutes().AsSlice()
	}

	report("router", route)
	require.Empty(t, approved())

	_, err := s.db.SetPolicy(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`)
	require.NoError(t, err)

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	assert.Empty(t, approved(), "a reload approves nothing")

	report("router-renamed", route)
	assert.Empty(t, approved(), "a report that keeps the routes approves nothing")

	report("router-renamed", route, added)
	assert.ElementsMatch(t, []netip.Prefix{route, added}, approved(),
		"a new announcement runs approvers over every announced route")
}

// TestAutoApproveKeepsCurrentManualRoutes: registration approval runs on
// the node the writer replaces, so an admin write that lands after the
// caller read its view survives.
func TestAutoApproveKeepsCurrentManualRoutes(t *testing.T) {
	manual := netip.MustParsePrefix("10.0.0.0/24")
	automatic := netip.MustParsePrefix("10.1.0.0/24")
	addition := netip.MustParsePrefix("10.2.0.0/24")

	for _, tt := range []struct {
		name        string
		replacement []netip.Prefix
		want        []netip.Prefix
	}{
		{name: "revoke", want: []netip.Prefix{automatic}},
		{name: "add", replacement: []netip.Prefix{manual, addition}, want: []netip.Prefix{manual, automatic, addition}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			_, err := s.SetPolicy([]byte(`{
				"autoApprovers": {"routes": {"10.1.0.0/24": ["persist-user@"]}},
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`))
			require.NoError(t, err)

			_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
				n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{manual, automatic}}
			})
			require.True(t, ok)

			stale, _, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{manual})
			require.NoError(t, err)

			_, _, err = s.SetApprovedRoutes(nodeID, tt.replacement)
			require.NoError(t, err)

			_, err = s.AutoApproveRoutes(stale)
			require.NoError(t, err)

			current, ok := s.GetNodeByID(nodeID)
			require.True(t, ok)
			assert.ElementsMatch(t, tt.want, current.ApprovedRoutes().AsSlice())

			stored, err := s.db.GetNodeByID(nodeID)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, stored.ApprovedRoutes.List())
		})
	}
}

// TestRegistrationApprovesOnlyWithNewNodeKey: a registration runs route
// auto-approval when it brings a new node key or a change to the announced
// routes, not on a login that keeps both.
func TestRegistrationApprovesOnlyWithNewNodeKey(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("approve-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["approve-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	route := netip.MustParsePrefix("10.0.1.0/24")
	machineKey := key.NewMachine().Public()
	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{route}},
	}

	node, _, err := s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, approvedRoutes(t, s, node.ID()), "a new node")

	_, _, err = s.SetApprovedRoutes(node.ID(), nil)
	require.NoError(t, err)

	_, _, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Empty(t, approvedRoutes(t, s, node.ID()), "the same node key")

	added := netip.MustParsePrefix("10.0.2.0/24")
	req.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{route, added}}
	_, _, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route, added}, approvedRoutes(t, s, node.ID()), "a new announced route")

	_, _, err = s.SetApprovedRoutes(node.ID(), nil)
	require.NoError(t, err)

	req.NodeKey = key.NewNode().Public()
	_, _, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{route, added}, approvedRoutes(t, s, node.ID()), "a new node key")
}

// TestRegistrationApprovalComparesReplacedNode: registration approval compares
// with the node the writer replaced, so an announcement and an admin revoke
// that land after the lookup leave an unchanged re-registration approving
// nothing.
func TestRegistrationApprovalComparesReplacedNode(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("approve-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["approve-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	c := registerForPAKRereg(t, s, pak)
	stale, stalePAK := c.lookup(t, pak.Key)

	route := netip.MustParsePrefix("10.0.1.0/24")
	hi := &tailcfg.Hostinfo{Hostname: "h0", RoutableIPs: []netip.Prefix{route}}

	_, err = s.UpdateNodeFromMapRequest(c.node.ID(), tailcfg.MapRequest{NodeKey: c.regReq.NodeKey, Hostinfo: hi})
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, approvedRoutes(t, s, c.node.ID()), "the announcement approves")

	_, _, err = s.SetApprovedRoutes(c.node.ID(), nil)
	require.NoError(t, err)

	req := c.regReq
	req.Hostinfo = hi.Clone()
	node, replaced, err := s.reregisterNodeWithPAK(stale, stalePAK, req, c.machineKey, hi.Hostname, req.Hostinfo)
	require.NoError(t, err)

	_, _, err = s.approveRoutesAfterRegistration(replaced, node, change.Change{})
	require.NoError(t, err)
	assert.Empty(t, approvedRoutes(t, s, c.node.ID()), "the admin revoke stands")
}

func approvedRoutes(t *testing.T, s *State, id types.NodeID) []netip.Prefix {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	return nv.ApprovedRoutes().AsSlice()
}

// TestWithdrawnRouteKeepsOnlyAdminApprovals: a route only auto-approval
// granted is dropped once the router stops announcing it and approved again
// when it comes back; a route an admin approved stays, also when
// autoApprovers cover it, and so does every approval made before the upgrade.
func TestWithdrawnRouteKeepsOnlyAdminApprovals(t *testing.T) {
	auto := netip.MustParsePrefix("10.0.1.0/24")
	admin := netip.MustParsePrefix("10.0.2.0/24")

	for _, tt := range []struct {
		name  string
		setup func(t *testing.T, s *State, id types.NodeID) // after announcing both routes
		want  []netip.Prefix                                // approved after the withdrawal
	}{
		{name: "auto only", want: nil},
		{
			name: "admin overlap",
			setup: func(t *testing.T, s *State, id types.NodeID) {
				t.Helper()

				_, _, err := s.SetApprovedRoutes(id, []netip.Prefix{auto, admin})
				require.NoError(t, err)
			},
			want: []netip.Prefix{auto, admin},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath, s, id := persistTestSetup(t)

			// Stored, so the restart below keeps it.
			_, err := s.db.SetPolicy(`{
				"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
				"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
			}`)
			require.NoError(t, err)
			_, err = s.ReloadPolicy()
			require.NoError(t, err)

			announce(t, s, id, auto, admin)
			require.ElementsMatch(t, []netip.Prefix{auto, admin}, approvedRoutes(t, s, id))

			if tt.setup != nil {
				tt.setup(t, s, id)
			}

			// The marks are stored, so a restart between keeps them.
			require.NoError(t, s.Close())
			s = persistTestReopen(t, dbPath)

			announce(t, s, id)
			assert.ElementsMatch(t, tt.want, approvedRoutes(t, s, id), "after the withdrawal")

			stored, err := s.db.GetNodeByID(id)
			require.NoError(t, err)
			assert.ElementsMatch(t, tt.want, stored.ApprovedRoutes.List())

			announce(t, s, id, auto, admin)
			assert.ElementsMatch(t, []netip.Prefix{auto, admin}, approvedRoutes(t, s, id), "announced again")
		})
	}

	t.Run("approved before the upgrade", func(t *testing.T) {
		dbPath, s, id := persistTestSetup(t)
		require.NoError(t, s.Close())

		// A row as the migration leaves it: approved, with no marks.
		database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
		require.NoError(t, err)
		require.NoError(t, database.DB.Exec(
			`UPDATE nodes SET approved_routes = ?, auto_approved_routes = NULL, host_info = ? WHERE id = ?`,
			`["10.0.1.0/24"]`, `{"RoutableIPs":["10.0.1.0/24"]}`, id).Error)
		require.NoError(t, database.Close())

		s = persistTestReopen(t, dbPath)

		_, err = s.SetPolicy([]byte(`{
			"autoApprovers": {"routes": {"10.0.0.0/16": ["persist-user@"]}},
			"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
		}`))
		require.NoError(t, err)

		announce(t, s, id)
		assert.Equal(t, []netip.Prefix{auto}, approvedRoutes(t, s, id))
	})
}

// announce sends a map request in which node id announces routes.
func announce(t *testing.T, s *State, id types.NodeID, routes ...netip.Prefix) {
	t.Helper()

	nv, ok := s.GetNodeByID(id)
	require.True(t, ok)

	_, err := s.UpdateNodeFromMapRequest(id, tailcfg.MapRequest{
		NodeKey:  nv.NodeKey(),
		DiscoKey: nv.DiscoKey(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: nv.Hostname(), RoutableIPs: routes},
	})
	require.NoError(t, err)
}

// TestRegistrationDropsWithdrawnAutoApprovals: a registration that stops
// announcing an auto-approved route drops its approval too.
func TestRegistrationDropsWithdrawnAutoApprovals(t *testing.T) {
	s := newRetagTestState(t)
	user := s.CreateUserForTest("withdraw-user")

	_, err := s.SetPolicy([]byte(`{
		"autoApprovers": {"routes": {"10.0.0.0/16": ["withdraw-user@"]}},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	kept := netip.MustParsePrefix("10.0.1.0/24")
	withdrawn := netip.MustParsePrefix("10.0.2.0/24")
	machineKey := key.NewMachine().Public()
	req := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{kept, withdrawn}},
	}

	node, _, err := s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{kept, withdrawn}, approvedRoutes(t, s, node.ID()))

	req.Hostinfo = &tailcfg.Hostinfo{Hostname: "router", RoutableIPs: []netip.Prefix{kept}}
	_, _, err = s.HandleNodeFromPreAuthKey(req, machineKey)
	require.NoError(t, err)
	assert.Equal(t, []netip.Prefix{kept}, approvedRoutes(t, s, node.ID()))
}
