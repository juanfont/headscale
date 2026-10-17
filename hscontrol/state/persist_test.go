package state

import (
	"database/sql"
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/views"
	"zombiezen.com/go/postgrestest"
)

// persistTestSetup pre-creates a sqlite database on disk with a single
// registered node, then constructs a State that loads it. The on-disk
// path is returned so the test can close the State and re-open one
// against the same file to simulate a server restart. The caller owns
// the returned State and must Close it; persistTestReopen handles the
// second State's lifecycle for the restart simulation.
func persistTestSetup(t *testing.T) (string, *State, types.NodeID) {
	t.Helper()

	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("persist-user")
	node := database.CreateRegisteredNodeForTest(user, "persist-node")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)

	return dbPath, s, node.ID
}

// persistTestReopen constructs a fresh State pointed at the same
// sqlite file and registers a cleanup to close it at the end of the
// test. Use it to simulate a server restart after the first State has
// been explicitly closed by the caller.
func persistTestReopen(t *testing.T, dbPath string) *State {
	t.Helper()

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return s
}

func persistTestConfig(dbPath string) *types.Config {
	prefixV4 := netip.MustParsePrefix("100.64.0.0/10")
	prefixV6 := netip.MustParsePrefix("fd7a:115c:a1e0::/48")

	return &types.Config{
		Database: types.DatabaseConfig{
			Type: types.DatabaseSqlite,
			Sqlite: types.SqliteConfig{
				Path: dbPath,
			},
		},
		PrefixV4:     &prefixV4,
		PrefixV6:     &prefixV6,
		IPAllocation: types.IPAllocationStrategySequential,
		BaseDomain:   "headscale.test",
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			NodeStoreBatchSize:    TestBatchSize,
			NodeStoreBatchTimeout: TestBatchTimeout,
		},
	}
}

func TestLoadedDuplicateNamesAreResolvedInMemory(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)
	cfg.TailcfgDNSConfig = &tailcfg.DNSConfig{ExtraRecords: []tailcfg.DNSRecord{
		{Name: "grafana." + cfg.BaseDomain, Type: "A", Value: "100.64.0.100"},
	}}
	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("loaded-name-user")
	long := strings.Repeat("a", 63)
	stored := []string{"db", "db", "DB", "", "grafana", "db-1", "x", "x", "x-1", long, strings.ToUpper(long)}
	want := []string{"db", "db-2", "DB-3", "", "grafana", "db-1", "x", "x-2", "x-1", long, strings.ToUpper(long[:61]) + "-1"}

	ids := make([]types.NodeID, 0, len(stored))
	for _, name := range stored {
		node := database.CreateNodeForTest(user)
		require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", node.ID).
			Update("given_name", name).Error)
		ids = append(ids, node.ID)
	}

	require.NoError(t, database.Close())

	for range 2 {
		s, err := NewState(cfg)
		require.NoError(t, err)

		for i, id := range ids {
			node, ok := s.GetNodeByID(id)
			require.True(t, ok)
			assert.Equal(t, want[i], node.GivenName())

			row, err := s.db.GetNodeByID(id)
			require.NoError(t, err)
			assert.Equal(t, stored[i], row.GivenName,
				"startup must not write the repair")
		}

		require.NoError(t, s.Close())
	}
}

func TestRegistrationPersistsResolvedGivenName(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("registration-name-user")
	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	want := []string{"db", "db-1", "node"}
	ids := make([]types.NodeID, 0, len(want))

	for i, hostname := range []string{"db", "db", "!!!"} {
		node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
		}, key.NewMachine().Public())
		require.NoError(t, err)

		ids = append(ids, node.ID())
		require.Equal(t, want[i], node.GivenName())
		row, err := s.db.GetNodeByID(node.ID())
		require.NoError(t, err)
		assert.Equal(t, want[i], row.GivenName)
	}

	require.NoError(t, s.Close())

	reopened := persistTestReopen(t, dbPath)
	for i, id := range ids {
		node, ok := reopened.GetNodeByID(id)
		require.True(t, ok)
		assert.Equal(t, want[i], node.GivenName())
	}
}

// TestPersistEmptyApprovedRoutes covers the State.SetApprovedRoutes
// path. The gRPC handler builds the slice via append from a nil
// declaration, so when the operator passes `-r ""` the persist layer
// receives a nil []netip.Prefix. GORM's struct Updates skips nil
// slices, so the column would stay populated with the previously
// approved routes and a restart would re-apply them.
func TestPersistEmptyApprovedRoutes(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	route := netip.MustParsePrefix("10.0.0.0/8")

	_, _, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{route})
	require.NoError(t, err)

	gotAfterApprove, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.Prefix{route}, gotAfterApprove.ApprovedRoutes.List(),
		"approved_routes should hold the seeded route")

	var noRoutes []netip.Prefix

	_, _, err = s.SetApprovedRoutes(nodeID, noRoutes)
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.ApprovedRoutes,
		"approved_routes should be empty after rejecting all routes, got %v",
		gotAfterClear.ApprovedRoutes)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok, "node should be loaded from DB after restart")
	assert.Empty(t, nv.AsStruct().ApprovedRoutes,
		"after restart, NodeStore should reflect the cleared routes")
}

// TestPersistEmptyTags exercises the same persist path for the tags
// column. State.SetNodeTags rejects an empty slice at the API level
// (tags are one-way), so the test drives the bug surface directly via
// NodeStore + persistNodeAndRefreshPolicy, which is the same code path the public
// SetApprovedRoutes call exercises.
func TestPersistEmptyTags(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:test"}
	})
	require.True(t, ok)

	seeded, ok := s.nodeStore.GetNode(nodeID)
	require.True(t, ok)

	_, _, err := s.persistNodeAndRefreshPolicy(seeded, s.polMan.NodesGeneration())
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:test"}, gotAfterSeed.Tags.List(),
		"tags should hold the seeded value")

	cleared, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = nil
	})
	require.True(t, ok)

	_, _, err = s.persistNodeAndRefreshPolicy(cleared, s.polMan.NodesGeneration())
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.Tags,
		"tags should be empty after clear, got %v", gotAfterClear.Tags)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, nv.AsStruct().Tags,
		"after restart, NodeStore should reflect the cleared tags")
}

// TestPersistEmptyEndpoints covers the endpoints column. Endpoints
// arrive via MapRequest in production; the test reaches the persist
// layer directly because the bug is in serialization, not in
// upstream parsing.
func TestPersistEmptyEndpoints(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	endpoint := netip.MustParseAddrPort("198.51.100.1:41641")

	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Endpoints = []netip.AddrPort{endpoint}
	})
	require.True(t, ok)

	seeded, ok := s.nodeStore.GetNode(nodeID)
	require.True(t, ok)

	_, _, err := s.persistNodeAndRefreshPolicy(seeded, s.polMan.NodesGeneration())
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{endpoint}, gotAfterSeed.Endpoints.List(),
		"endpoints should hold the seeded value")

	cleared, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Endpoints = nil
	})
	require.True(t, ok)

	_, _, err = s.persistNodeAndRefreshPolicy(cleared, s.polMan.NodesGeneration())
	require.NoError(t, err)

	gotAfterClear, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Empty(t, gotAfterClear.Endpoints,
		"endpoints should be empty after clear, got %v", gotAfterClear.Endpoints)

	require.NoError(t, s.Close())

	s2 := persistTestReopen(t, dbPath)

	nv, ok := s2.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, nv.AsStruct().Endpoints,
		"after restart, NodeStore should reflect the cleared endpoints")
}

// TestRegistrationRejectsNodeKeyClaimedByAnotherMachine proves a new
// registration cannot claim a NodeKey already bound to a different machine.
// NodeKeys are public (peers learn them from the netmap), so without this
// check an authenticated party can register a node carrying a victim's
// NodeKey. That poisons the NodeStore NodeKey index (a map keyed on NodeKey,
// last writer wins), so the victim's MapRequest resolves to the attacker's
// node and is rejected by getAndValidateNode's MachineKey check (noise.go) —
// a denial of service against the victim. getAndValidateNode already enforces
// a 1:1 NodeKey<->MachineKey binding at poll time; this enforces the same
// invariant at registration time.
func TestRegistrationRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("nk-user")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	sharedNodeKey := key.NewNode()

	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        sharedNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// A different machine tries to register carrying the victim's NodeKey.
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        sharedNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "attacker",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.Error(t, err,
		"registering a NodeKey already bound to another machine must be rejected")
}

// TestRegistrationKeepsRequestTagsIntact guards the node's reported
// Hostinfo.RequestTags against the in-place sort/compact that derives the
// approved tag set: the two must not share a backing array.
func TestRegistrationKeepsRequestTagsIntact(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("tagger")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{"tagOwners":{"tag:a":["tagger@"],"tag:b":["tagger@"]}}`))
	require.NoError(t, err)

	node, err := s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "node",
		Hostinfo:       &tailcfg.Hostinfo{RequestTags: []string{"tag:b", "tag:a", "tag:a"}},
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	assert.Equal(t, []string{"tag:a", "tag:b"}, node.Tags().AsSlice())
	assert.Equal(t, []string{"tag:b", "tag:a", "tag:a"}, node.Hostinfo().RequestTags().AsSlice(),
		"reported RequestTags rewritten by tag approval")
}

// TestReauthRejectsNodeKeyClaimedByAnotherMachine proves the re-auth/update
// path enforces the same 1:1 NodeKey<->MachineKey binding as the create path
// (TestRegistrationRejectsNodeKeyClaimedByAnotherMachine) and the poll path
// (getAndValidateNode). Without it, a node re-authenticating could rotate its
// NodeKey to a victim's, poisoning the NodeStore NodeKey index so the victim's
// MapRequest resolves to the attacker's node and is rejected — a DoS.
func TestReauthRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	attacker := database.CreateUserForTest("attacker")
	victim := database.CreateUserForTest("victim")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	victimNodeKey := key.NewNode()
	attackerMachine := key.NewMachine()

	// Victim's node holds victimNodeKey.
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *victim,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        victimNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker registers its own node.
	attackerNode, err := s.createAndSaveNewNode(newNodeParams{
		User:           *attacker,
		MachineKey:     attackerMachine.Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "attacker",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker re-authenticates its own node but supplies the victim's NodeKey.
	_, _, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode: attackerNode,
		RegData: &types.RegistrationData{
			MachineKey: attackerMachine.Public(),
			NodeKey:    victimNodeKey.Public(),
			Hostname:   "attacker",
			Hostinfo:   &tailcfg.Hostinfo{},
		},
		Hostname:       "attacker",
		User:           attacker,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.Error(t, err,
		"re-auth claiming a NodeKey bound to another machine must be rejected")
}

// TestReauthPreservesEndpointsWhenClientOmitsThem proves the re-auth/update
// path keeps a node's live WireGuard endpoints when the originating
// RegisterRequest carried none. Web/OIDC relogins report endpoints via
// MapRequest, not register, so RegData.Endpoints is empty; wiping the stored
// endpoints would advertise the re-keyed node to peers endpoint-less, which
// drives head/unstable tailscale clients into one-way disco-deafness.
func TestReauthPreservesEndpointsWhenClientOmitsThem(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("user")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	machine := key.NewMachine()
	endpoints := []netip.AddrPort{
		netip.MustParseAddrPort("192.168.1.5:41641"),
		netip.MustParseAddrPort("10.0.0.5:41641"),
	}

	// Node is registered and has reported live endpoints (as after its first
	// MapRequest).
	node, err := s.createAndSaveNewNode(newNodeParams{
		User:           *user,
		MachineKey:     machine.Public(),
		NodeKey:        key.NewNode().Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "node",
		Endpoints:      endpoints,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)
	require.Equal(t, endpoints, node.Endpoints().AsSlice(),
		"precondition: node has live endpoints")

	// Node re-authenticates, rotating its NodeKey. The RegisterRequest carries
	// no endpoints.
	updated, _, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
		ExistingNode: node,
		RegData: &types.RegistrationData{
			MachineKey: machine.Public(),
			NodeKey:    key.NewNode().Public(),
			Hostname:   "node",
			Hostinfo:   &tailcfg.Hostinfo{},
			Endpoints:  nil,
		},
		Hostname:       "node",
		User:           user,
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	assert.Equal(t, endpoints, updated.Endpoints().AsSlice(),
		"re-auth without reported endpoints must preserve the node's live endpoints")
}

// TestReauthChange covers the decision both re-auth paths share: a keys-only
// relogin must be an incremental peer patch (so the tailscale client takes its
// fast patch path), never a whole-node add (which strands a re-keyed,
// momentarily-endpoint-less peer disco-deaf); a relogin peers read as before
// sends nothing; a policy change forces a full recompute; a new node is a
// whole-node add.
func TestReauthChange(t *testing.T) {
	n := types.Node{
		ID:       7,
		NodeKey:  key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
	}
	node := n.View()

	keys := reauthChange(node, reloginKeys, false)
	assert.Len(t, keys.PeerPatches, 1, "relogin must be a peer patch")
	assert.Empty(t, keys.PeersChanged, "relogin must not be a whole-node add")

	assert.True(t, reauthChange(node, reloginNone, false).IsEmpty(),
		"a relogin peers read as before must send nothing")

	added := reauthChange(node, reloginWhole, false)
	assert.Empty(t, added.PeerPatches)
	assert.Len(t, added.PeersChanged, 1, "a new node must be a whole-node add")

	pol := reauthChange(node, reloginKeys, true)
	assert.Empty(t, pol.PeerPatches, "a policy change must not be a peer patch")
	assert.Empty(t, pol.PeersChanged)
	assert.False(t, pol.IsEmpty(), "a policy change must be non-empty")
}

// TestReloginChanged covers which relogins may ride the key-rotation patch:
// one that flips Expired or changes Hostinfo peers read must not, as
// [tailcfg.PeerChange] carries neither (#3531); one on the same keys and
// expiry needs nothing at all.
func TestReloginChanged(t *testing.T) {
	now := time.Now()
	past, future := now.Add(-time.Minute), now.Add(time.Hour)

	node := func(expiry time.Time, hi tailcfg.Hostinfo) types.NodeView {
		n := types.Node{
			NodeKey:  key.NewNode().Public(),
			DiscoKey: key.NewDisco().Public(),
			Expiry:   &expiry,
			Hostinfo: &hi,
		}

		return n.View()
	}

	hi := tailcfg.Hostinfo{Hostname: "node", OS: "linux"}
	withOSVersion, withService := hi, hi
	withOSVersion.OSVersion = "6.1"
	withService.Services = []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 4242}}

	same := node(future, hi)
	renewedNode := same.AsStruct()
	renewedNode.Expiry = new(future.Add(time.Hour))
	renewed := renewedNode.View()

	tests := []struct {
		name          string
		before, after types.NodeView
		want          relogin
	}{
		{name: "keys", before: node(future, hi), after: node(future, hi), want: reloginKeys},
		{name: "hostinfo peers do not read", before: node(future, hi), after: node(future, withOSVersion), want: reloginKeys},
		{name: "un-expired", before: node(past, hi), after: node(future, hi), want: reloginWhole},
		{name: "hostinfo peers read", before: node(future, hi), after: node(future, withService), want: reloginWhole},
		{name: "same keys", before: same, after: same, want: reloginNone},
		{name: "same keys, new expiry", before: same, after: renewed, want: reloginKeys},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, reloginChanged(tt.before, tt.after, now))
		})
	}
}

// TestPreAuthKeyReauthRejectsNodeKeyClaimedByAnotherMachine is the pre-auth-key
// analogue of TestReauthRejectsNodeKeyClaimedByAnotherMachine: re-registering
// via a pre-auth key must enforce the same 1:1 NodeKey<->MachineKey binding the
// auth path and poll-time validation enforce, so a node cannot rotate its key
// to a victim's and poison the NodeStore NodeKey index.
func TestPreAuthKeyReauthRejectsNodeKeyClaimedByAnotherMachine(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	attacker := s.CreateUserForTest("attacker")
	victim := s.CreateUserForTest("victim")

	victimMachine := key.NewMachine()
	victimNodeKey := key.NewNode()
	_, err = s.createAndSaveNewNode(newNodeParams{
		User:           *victim,
		MachineKey:     victimMachine.Public(),
		NodeKey:        victimNodeKey.Public(),
		DiscoKey:       key.NewDisco().Public(),
		Hostname:       "victim",
		RegisterMethod: util.RegisterMethodCLI,
	})
	require.NoError(t, err)

	// Attacker registers its own node with a reusable pre-auth key.
	pak, err := s.CreatePreAuthKey(attacker.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	attackerMachine := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "attacker"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	_, _, err = s.HandleNodeFromPreAuthKey(regReq, attackerMachine.Public())
	require.NoError(t, err)

	// Attacker re-registers its own node but supplies the victim's NodeKey.
	attack := regReq
	attack.NodeKey = victimNodeKey.Public()
	_, _, err = s.HandleNodeFromPreAuthKey(attack, attackerMachine.Public())
	require.ErrorIs(t, err, ErrNodeKeyInUse,
		"pre-auth-key re-registration claiming another machine's NodeKey must be rejected")

	// The victim still owns its NodeKey.
	owner, ok := s.GetNodeByNodeKey(victimNodeKey.Public())
	require.True(t, ok)
	require.Equal(t, victimMachine.Public(), owner.MachineKey(),
		"victim's NodeKey index entry must be untouched")
}

var (
	errInjectedNodeUpdate       = errors.New("injected node update failure")
	errInjectedNodeDelete       = errors.New("injected node delete failure")
	errInjectedPolicyNodeUpdate = errors.New("injected policy node update failure")
)

type failingSetNodesPolicyManager struct {
	policy.PolicyManager
}

func (failingSetNodesPolicyManager) SetNodes(views.Slice[types.NodeView]) (bool, error) {
	return false, errInjectedPolicyNodeUpdate
}

func TestDeleteNodeTwiceReleasesAddressOnce(t *testing.T) {
	prefix := netip.MustParsePrefix("100.64.0.0/30")
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.PrefixV4 = &prefix
	cfg.PrefixV6 = nil
	cfg.IPAllocation = types.IPAllocationStrategyRandom

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("delete-user")
	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)
	node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "delete-node"},
	}, key.NewMachine().Public())
	require.NoError(t, err)

	stale := node

	_, _, err = s.ipAlloc.Next()
	require.NoError(t, err)
	_, err = s.DeleteNode(node)
	require.NoError(t, err)
	reissued, _, err := s.ipAlloc.Next()
	require.NoError(t, err)
	require.Equal(t, node.IPv4().Get(), *reissued)

	changes, err := s.DeleteNode(stale)
	require.NoError(t, err)
	assert.Empty(t, changes)

	_, _, err = s.ipAlloc.Next()
	require.ErrorIs(t, err, db.ErrCouldNotAllocateIP)
}

func TestPersistDuringDeleteDoesNotResurrectNode(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	s.nodeStore.Stop()

	entered, release := make(chan struct{}), make(chan struct{})

	var enteredOnce sync.Once

	s.nodeStore = NewNodeStore(
		types.Nodes{node.AsStruct()},
		func(nodes []types.NodeView) map[types.NodeID][]types.NodeID {
			if len(nodes) == 0 {
				enteredOnce.Do(func() { close(entered) })
				<-release
			}

			return nil
		},
		TestBatchSize,
		TestBatchTimeout,
	)
	s.nodeStore.Start()

	var releaseOnce sync.Once

	t.Cleanup(func() { releaseOnce.Do(func() { close(release) }) })

	deleteDone := make(chan error, 1)

	go func() {
		_, err := s.DeleteNode(node)
		deleteDone <- err
	}()

	<-entered

	persistDone := make(chan error, 1)

	go func() {
		_, err := s.persistNode(node)
		persistDone <- err
	}()

	select {
	case err := <-persistDone:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Error("persist blocked behind the NodeStore delete")
	}

	_, err := s.db.GetNodeByID(nodeID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
	releaseOnce.Do(func() { close(release) })
	require.NoError(t, <-deleteDone)
}

func TestDeleteNodeKeepsStoreOnDBFailure(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	require.NoError(t, s.db.DB.Callback().Delete().Before("gorm:delete").
		Register("fail_node_delete", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeDelete)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Delete().Remove("fail_node_delete") })

	c, err := s.DeleteNode(node)
	require.NoError(t, s.db.DB.Callback().Delete().Remove("fail_node_delete"))
	require.ErrorIs(t, err, errInjectedNodeDelete)
	assert.Empty(t, c, "an uncommitted deletion must not stop the node's session")

	_, ok = s.GetNodeByID(nodeID)
	assert.True(t, ok, "a database failure must leave the in-memory node available")

	_, err = s.db.GetNodeByID(nodeID)
	assert.NoError(t, err, "a failed deletion must leave the durable node row available")
}

func TestDeleteNodeReturnsRemovalOnPolicyFailure(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("persist-user")
	nodeID := database.CreateRegisteredNodeForTest(user, "persist-node").ID
	peerID := database.CreateRegisteredNodeForTest(user, "persist-peer").ID

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	// Fail the writer's refresh too: it shares the policy manager, and a
	// refresh it applied is not retried by the caller.
	nodes := make(types.Nodes, 0, s.nodeStore.ListNodes().Len())
	for _, nv := range s.nodeStore.ListNodes().All() {
		nodes = append(nodes, nv.AsStruct())
	}

	s.nodeStore.Stop()
	s.polMan = failingSetNodesPolicyManager{PolicyManager: s.polMan}
	s.nodeStore = NewNodeStore(nodes, policyPeersFunc(s.polMan), TestBatchSize, TestBatchTimeout)
	s.nodeStore.Start()

	cs, err := s.DeleteNode(node)
	require.ErrorIs(t, err, errInjectedPolicyNodeUpdate)
	require.GreaterOrEqual(t, len(cs), 2)
	assert.Equal(t, []types.NodeID{nodeID}, cs[0].DeletedNodes,
		"a committed deletion must identify the session to stop")
	assert.Equal(t, peerID, cs[1].TargetNode,
		"a committed deletion must still notify peers")
	assert.Equal(t, []types.NodeID{nodeID}, cs[1].PeersRemoved,
		"a committed deletion must still notify peers")

	_, ok = s.GetNodeByID(nodeID)
	assert.False(t, ok, "a committed deletion must remove the in-memory node")

	_, err = s.db.GetNodeByID(nodeID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound,
		"a committed deletion must remove the durable node row")
}

// TestPreAuthKeyReauthRevertsNodeStoreOnDBFailure ensures a failed database
// write during pre-auth-key re-registration does not leave the NodeStore
// holding a node key that was never persisted: a restart would reload the old
// row and the client's current key would no longer resolve, locking it out.
// TestConcurrentDeleteNodesShareNodeStoreBatch deletes two nodes at once with
// a NodeStore that applies a batch only when it holds two writes. Holding
// persistMu across the NodeStore write gave every delete a batch, and so a
// peer map build, of its own; under churn that serialised deletion behind one
// rebuild each.
func TestConcurrentDeleteNodesShareNodeStoreBatch(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")
	cfg.Tuning.NodeStoreBatchSize = 2
	cfg.Tuning.NodeStoreBatchTimeout = time.Hour

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("delete-batch-user")
	nodes := database.CreateNodesForTest(user, 2, "delete-batch-node")

	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	var wg sync.WaitGroup

	for _, n := range nodes {
		node, ok := s.GetNodeByID(n.ID)
		require.True(t, ok)

		wg.Go(func() {
			_, err := s.DeleteNode(node)
			assert.NoError(t, err)
		})
	}

	done := make(chan struct{})

	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("concurrent deletes must be able to share a NodeStore batch")
	}

	for _, n := range nodes {
		_, ok := s.GetNodeByID(n.ID)
		assert.False(t, ok, "deleted node must be gone from the NodeStore")
	}
}

func TestPreAuthKeyReauthRevertsNodeStoreOnDBFailure(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("reauth-user")

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()
	regReq := tailcfg.RegisterRequest{
		Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
		NodeKey:  key.NewNode().Public(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: "reauth-node"},
		Expiry:   time.Now().Add(24 * time.Hour),
	}
	node, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
	require.NoError(t, err)

	origNodeKey := node.NodeKey()

	// Fail the node row update so the re-registration's database write errors
	// after the NodeStore has already been mutated. A session connects during
	// the write; the rollback must not undo it.
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				s.Connect(node.ID())

				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))

	reReg := regReq
	reReg.NodeKey = key.NewNode().Public() // rotate -> NodeStore mutation, then DB write fails
	_, _, err = s.HandleNodeFromPreAuthKey(reReg, machineKey.Public())
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))
	require.Error(t, err, "re-registration must fail when the database write fails")

	got, ok := s.nodeStore.GetNode(node.ID())
	require.True(t, ok)
	require.Equal(t, origNodeKey, got.NodeKey(),
		"NodeStore must revert to the persisted node key when the write fails")

	online, known := got.IsOnline().GetOk()
	require.True(t, known)
	require.True(t, online, "rollback dropped the session that connected during the write")
}

// TestConcurrentPreAuthKeyRegistrationSameMachineKey ensures concurrent
// registrations of the same machine key resolve to a single node. Without
// serialising the find-then-create section, each request sees "no existing
// node" and creates its own, leaving duplicate nodes and IP allocations for
// one machine.
func TestConcurrentPreAuthKeyRegistrationSameMachineKey(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("concurrent-user")

	pak, err := s.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	machineKey := key.NewMachine()

	const n = 12

	var wg sync.WaitGroup

	start := make(chan struct{})
	errs := make(chan error, n)

	for range n {
		wg.Go(func() {
			regReq := tailcfg.RegisterRequest{
				Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
				NodeKey:  key.NewNode().Public(),
				Hostinfo: &tailcfg.Hostinfo{Hostname: "concurrent-node"},
				Expiry:   time.Now().Add(24 * time.Hour),
			}

			<-start

			_, _, err := s.HandleNodeFromPreAuthKey(regReq, machineKey.Public())
			errs <- err
		})
	}

	close(start)
	wg.Wait()
	close(errs)

	for err := range errs {
		require.NoError(t, err)
	}

	require.Equal(t, 1, s.ListNodes().Len(),
		"concurrent registrations of one machine key must yield a single node")
	require.Zero(t, s.registerLocks.Size(),
		"registration locks must not outlive the registrations using them")
}

// TestRejectedRegistrationLeavesNoRegisterLock pins that a refused
// registration keeps nothing. The lock is taken before the pre-auth key is
// checked, so a client without a credential reaches it with as many machine
// keys as it likes.
func TestRejectedRegistrationLeavesNoRegisterLock(t *testing.T) {
	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	for range 100 {
		_, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:    &tailcfg.RegisterResponseAuth{AuthKey: "not-a-key"},
			NodeKey: key.NewNode().Public(),
		}, key.NewMachine().Public())
		require.Error(t, err)
	}

	require.Zero(t, s.registerLocks.Size())
}

// TestLockRegistrationSerialisesSameMachineKey pins that dropping unused
// locks never lets two registrations of one machine key run at once.
func TestLockRegistrationSerialisesSameMachineKey(t *testing.T) {
	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	machineKey := key.NewMachine().Public()

	var (
		wg      sync.WaitGroup
		holders atomic.Int32
		overlap atomic.Bool
	)

	for range 64 {
		wg.Go(func() {
			defer s.lockRegistration(machineKey)()

			if holders.Add(1) != 1 {
				overlap.Store(true)
			}

			runtime.Gosched()
			holders.Add(-1)
		})
	}

	wg.Wait()

	require.False(t, overlap.Load(), "two registrations held the lock at once")
	require.Zero(t, s.registerLocks.Size())
}

// TestUpdatePolicyManagerUsersUnchangedKeepsSnapshot ensures re-sending the
// same user list does not rebuild peer adjacency, while a real user change
// does.
func TestUpdatePolicyManagerUsersUnchangedKeepsSnapshot(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	require.NoError(t, s.UpdatePolicyManagerUsersForTest())

	before := s.nodeStore.data.Load()

	require.NoError(t, s.UpdatePolicyManagerUsersForTest())
	require.Same(t, before, s.nodeStore.data.Load(),
		"unchanged users must not rebuild the peer map")

	_, _, err := s.CreateUser(types.User{Name: "second"})
	require.NoError(t, err)
	require.NotSame(t, before, s.nodeStore.data.Load(),
		"a user change must rebuild the peer map")
}

// TestSingleUsePreAuthKeyUsedInNodeStore asserts that consuming a single-use
// key marks it used in both the database and the node's cached AuthKey, on
// first registration and when re-registering with a fresh single-use key.
func TestSingleUsePreAuthKeyUsedInNodeStore(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"

	s, err := NewState(persistTestConfig(dbPath))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("single-use")
	machine := key.NewMachine()

	register := func(t *testing.T) types.NodeView {
		t.Helper()

		pak, err := s.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
		require.NoError(t, err)

		node, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
			Auth:     &tailcfg.RegisterResponseAuth{AuthKey: pak.Key},
			NodeKey:  key.NewNode().Public(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: "single-use"},
			Expiry:   time.Now().Add(24 * time.Hour),
		}, machine.Public())
		require.NoError(t, err)

		cached, ok := s.GetNodeByID(node.ID())
		require.True(t, ok)
		require.True(t, cached.AuthKey().Valid())
		assert.Equal(t, pak.ID, cached.AuthKey().ID())
		assert.True(t, cached.AuthKey().Used(), "NodeStore copy must be marked used")

		stored, err := s.db.GetPreAuthKeyByID(pak.ID)
		require.NoError(t, err)
		assert.True(t, stored.Used, "database row must be marked used")

		return cached
	}

	first := register(t)
	second := register(t)
	assert.Equal(t, first.ID(), second.ID(), "second key re-registers the same node")
}

// TestPersistNodeAndRefreshPolicyEmptyForPayloadOnlyChange proves
// persistNodeAndRefreshPolicy returns an empty change when the write did not
// touch anything policy reads, so each caller can tell a genuinely empty
// write apart and pick its own wire change (see
// TestPersistCallerChangeDecisions).
func TestPersistNodeAndRefreshPolicyEmptyForPayloadOnlyChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	genBefore := s.polMan.NodesGeneration()

	view, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{Hostname: "payload-only"}
	})
	require.True(t, ok)

	_, c, err := s.persistNodeAndRefreshPolicy(view, genBefore)
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "a payload-only write must not fabricate a change")
}

// TestPersistCallerChangeDecisions proves each persistNodeAndRefreshPolicy
// caller picks its own wire change when persist reports none. A caller that
// returns nothing silently stops a node's peers from learning about it, so
// every case here checks the exact change, not just that persist succeeded.
func TestPersistCallerChangeDecisions(t *testing.T) {
	taggingPolicy := `{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`

	tests := []struct {
		name             string
		policy           string
		setup            func(t *testing.T, s *State, nodeID types.NodeID)
		run              func(t *testing.T, s *State, nodeID types.NodeID) change.Change
		wantType         string
		wantOriginNode   bool
		wantPeersChanged bool
	}{
		{
			name: "RenameNode resends the whole node when the rename does not affect policy",
			run: func(t *testing.T, s *State, nodeID types.NodeID) change.Change {
				t.Helper()

				_, c, err := s.RenameNode(nodeID, "renamed")
				require.NoError(t, err)

				return c
			},
			wantType:         "peers",
			wantOriginNode:   true,
			wantPeersChanged: true,
		},
		{
			name:   "SetNodeTags reports a policy change for a real tag assignment",
			policy: taggingPolicy,
			run: func(t *testing.T, s *State, nodeID types.NodeID) change.Change {
				t.Helper()

				_, c, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)

				return c
			},
			wantType:         "policy",
			wantOriginNode:   true,
			wantPeersChanged: false,
		},
		{
			name:   "SetNodeTags resends the whole node when re-applying identical tags",
			policy: taggingPolicy,
			setup: func(t *testing.T, s *State, nodeID types.NodeID) {
				t.Helper()

				_, _, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)
			},
			run: func(t *testing.T, s *State, nodeID types.NodeID) change.Change {
				t.Helper()

				_, c, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
				require.NoError(t, err)

				return c
			},
			wantType:         "peers",
			wantOriginNode:   true,
			wantPeersChanged: true,
		},
		{
			name: "SetApprovedRoutes of an unannounced route resends only the node",
			run: func(t *testing.T, s *State, nodeID types.NodeID) change.Change {
				t.Helper()

				_, c, err := s.SetApprovedRoutes(nodeID, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
				require.NoError(t, err)

				return c
			},
			wantType:         "peers",
			wantOriginNode:   true,
			wantPeersChanged: true,
		},
		{
			name: "SaveNode reports no change for a payload-only save",
			run: func(t *testing.T, s *State, nodeID types.NodeID) change.Change {
				t.Helper()

				current, ok := s.nodeStore.GetNode(nodeID)
				require.True(t, ok)

				n := current.AsStruct()
				n.Hostinfo = &tailcfg.Hostinfo{Hostname: "saved-payload"}

				_, c, err := s.SaveNode(n.View())
				require.NoError(t, err)

				return c
			},
			wantType:         "empty",
			wantOriginNode:   false,
			wantPeersChanged: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, s, nodeID := persistTestSetup(t)
			t.Cleanup(func() { _ = s.Close() })

			if tt.policy != "" {
				_, err := s.SetPolicy([]byte(tt.policy))
				require.NoError(t, err)
			}

			if tt.setup != nil {
				tt.setup(t, s, nodeID)
			}

			c := tt.run(t, s, nodeID)

			assert.Equal(t, tt.wantType, c.Type())

			if tt.wantOriginNode {
				assert.Equal(t, nodeID, c.OriginNode)
			} else {
				assert.Zero(t, c.OriginNode)
			}

			if tt.wantPeersChanged {
				assert.Equal(t, []types.NodeID{nodeID}, c.PeersChanged)
			} else {
				assert.Empty(t, c.PeersChanged)
			}
		})
	}
}

// TestRetryAfterFailedPersistReportsPolicyChange proves a policy move made by
// a write whose database persist failed is still reported. The NodeStore write
// already fed the policy manager, so an identical retry sees nothing new; if
// neither call reported the move, clients would keep the filter and SSH
// policy the write revoked.
func TestRetryAfterFailedPersistReportsPolicyChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]
	}`))
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_node_update") })

	_, failedC, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.ErrorIs(t, err, errInjectedNodeUpdate)
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))

	_, c, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.NoError(t, err)
	assert.True(t, failedC.IncludePolicy || c.IncludePolicy,
		"the failed call or its retry must report the policy move: failed %s, retry %s",
		failedC.Type(), c.Type())
	assert.Equal(t, nodeID, c.OriginNode)

	if !failedC.IsEmpty() {
		assert.Equal(t, nodeID, failedC.OriginNode,
			"a failed call's change must still refresh the tagged node's self view")
	}
}

// TestFailedPersistPolicyChangeSurvivesDroppedChange covers a policy move
// whose write failed to persist, followed by an unrelated map request whose
// change never reaches the batcher (its initial map failed) and then a
// successful retry. The changes that do get published must still carry the
// policy, or clients keep the filter and SSH policy the write revoked.
func TestFailedPersistPolicyChangeSurvivesDroppedChange(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:self:*"]}]
	}`))
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_node_update") })

	_, failedC, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.ErrorIs(t, err, errInjectedNodeUpdate)
	require.NoError(t, s.db.DB.Callback().Update().Remove("fail_node_update"))

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	// The map request's change is dropped, as when its initial map fails.
	_, err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey:  nv.NodeKey(),
		DiscoKey: nv.DiscoKey(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: nv.Hostname()},
	})
	require.NoError(t, err)

	_, retryC, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.NoError(t, err)

	assert.True(t, failedC.IncludePolicy || retryC.IncludePolicy,
		"published changes must carry the policy move: failed %s, retry %s",
		failedC.Type(), retryC.Type())
}

// TestReloadPolicyOverlappingWrites has a second policy write complete after
// the reload of the first one loaded its document and before it installs it.
// The first reload must not put the older document back over the newer one.
func TestReloadPolicyOverlappingWrites(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	const (
		first  = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
		second = `{"acls": [{"action": "accept", "src": ["persist-user@"], "dst": ["persist-user@:22"]}]}`
	)

	_, err := s.SetPolicyInDB(second)
	require.NoError(t, err)
	_, err = s.ReloadPolicy()
	require.NoError(t, err)

	want, _ := s.Filter()

	_, err = s.SetPolicyInDB(first)
	require.NoError(t, err)

	var reads atomic.Int32

	written := make(chan struct{})

	require.NoError(t, s.db.DB.Callback().Query().After("gorm:query").
		Register("write_after_load", func(tx *gorm.DB) {
			if tx.Statement.Table != "policies" || reads.Add(1) != 1 {
				return
			}

			go func() {
				defer close(written)

				_, err := s.SetPolicyInDB(second)
				assert.NoError(t, err)
				_, err = s.ReloadPolicy()
				assert.NoError(t, err)
			}()

			// Give the second write time to finish, unless the reload
			// blocks it.
			select {
			case <-written:
			case <-time.After(200 * time.Millisecond):
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Query().Remove("write_after_load") })

	_, err = s.ReloadPolicy()
	require.NoError(t, err)
	<-written

	got, _ := s.Filter()
	assert.Equal(t, want, got, "the policy in force must be the one stored last")
}

// TestUpdatePolicyStoreFailure refuses the write at the database and checks
// the live policy was not changed by it.
func TestUpdatePolicyStoreFailure(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	const (
		open = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
		ssh  = `{"acls": [{"action": "accept", "src": ["persist-user@"], "dst": ["persist-user@:22"]}]}`
	)

	_, _, err := s.UpdatePolicy([]byte(ssh))
	require.NoError(t, err)

	before, _ := s.Filter()

	require.NoError(t,
		s.db.DB.Exec("ALTER TABLE policies RENAME TO policies_away").Error)

	_, _, err = s.UpdatePolicy([]byte(open))
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrInvalidPolicy)

	after, _ := s.Filter()
	assert.Equal(t, before, after, "an unstored policy must not be installed")
}

// TestPostgresUpdatePolicyConcurrentWrites runs a second write while the
// first one's insert is not yet committed. Pruning cannot see that row, so
// unless writers are serialised up to the install, it outlives the newer one.
func TestPostgresUpdatePolicyConcurrentWrites(t *testing.T) {
	srv, err := postgrestest.Start(t.Context())
	if err != nil {
		t.Skipf("start postgres: %s", err)
	}

	t.Cleanup(srv.Cleanup)

	dsn, err := srv.CreateDatabase(t.Context())
	require.NoError(t, err)

	u, err := url.Parse(dsn)
	require.NoError(t, err)

	pass, _ := u.User.Password()
	port, err := strconv.Atoi(u.Port())
	require.NoError(t, err)

	cfg := persistTestConfig("")
	cfg.Database = types.DatabaseConfig{
		Type: types.DatabasePostgres,
		Postgres: types.PostgresConfig{
			Host: u.Hostname(),
			Port: port,
			Name: strings.TrimLeft(u.Path, "/"),
			User: u.User.Username(),
			Pass: pass,
			Ssl:  "disable",
		},
	}

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	const (
		first  = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
		second = `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}`
	)

	_, _, err = s.UpdatePolicy([]byte(second))
	require.NoError(t, err)

	want, _ := s.Filter()

	var creates atomic.Int32

	written := make(chan struct{})

	require.NoError(t, s.db.DB.Callback().Create().After("gorm:create").
		Register("write_while_storing", func(tx *gorm.DB) {
			if tx.Statement.Table != "policies" || creates.Add(1) != 1 {
				return
			}

			go func() {
				defer close(written)

				_, _, err := s.UpdatePolicy([]byte(second))
				assert.NoError(t, err)
			}()

			// Give the second write time to finish, unless the first
			// write blocks it.
			select {
			case <-written:
			case <-time.After(200 * time.Millisecond):
			}
		}))
	t.Cleanup(func() {
		_ = s.db.DB.Callback().Create().Remove("write_while_storing")
	})

	_, _, err = s.UpdatePolicy([]byte(first))
	require.NoError(t, err)
	<-written

	var rows int64
	require.NoError(t,
		s.db.DB.Unscoped().Model(&types.Policy{}).Count(&rows).Error)
	assert.Equal(t, int64(1), rows, "only the current policy may be stored")

	stored, err := s.GetPolicy()
	require.NoError(t, err)
	assert.JSONEq(t, second, stored.Data, "the write that ran last is stored")

	got, _ := s.Filter()
	assert.Equal(t, want, got, "the policy in force must be the one stored")
}

// TestReloadPolicyEmpty: with no policy configured a reload has nothing to
// install; an emptied policy file is refused. Both keep the live policy.
func TestReloadPolicyEmpty(t *testing.T) {
	const pol = `{"acls": [{"action": "accept", "src": ["persist-user@"], "dst": ["persist-user@:22"]}]}`

	t.Run("no policy configured", func(t *testing.T) {
		_, s, _ := persistTestSetup(t)
		t.Cleanup(func() { _ = s.Close() })

		_, err := s.SetPolicy([]byte(pol))
		require.NoError(t, err)

		before, _ := s.Filter()

		_, err = s.ReloadPolicy()
		require.NoError(t, err)

		after, _ := s.Filter()
		assert.Equal(t, before, after)
	})

	t.Run("empty policy file", func(t *testing.T) {
		_, s, _ := persistTestSetup(t)
		t.Cleanup(func() { _ = s.Close() })

		s.cfg.Policy = types.PolicyConfig{
			Mode: types.PolicyModeFile,
			Path: filepath.Join(t.TempDir(), "policy.hujson"),
		}

		require.NoError(t, os.WriteFile(s.cfg.Policy.Path, []byte(pol), 0o600))

		_, err := s.ReloadPolicy()
		require.NoError(t, err)

		before, _ := s.Filter()

		// os.ReadFile gives an empty, non-nil slice here.
		require.NoError(t, os.WriteFile(s.cfg.Policy.Path, nil, 0o600))

		_, err = s.ReloadPolicy()
		require.ErrorIs(t, err, policyv2.ErrPolicyEmpty)

		after, _ := s.Filter()
		assert.Equal(t, before, after)
	})
}

// TestNodeWriteChangeWhenPolicyRefreshFails fails both the NodeStore
// writer's SetNodes and the caller's. The write still reached the
// NodeStore, so the change returned with the error must resend the node to
// itself and its peers rather than be empty.
func TestNodeWriteChangeWhenPolicyRefreshFails(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{
		"tagOwners": {"tag:ci": ["persist-user@"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`))
	require.NoError(t, err)

	nodes := make(types.Nodes, 0, s.nodeStore.ListNodes().Len())
	for _, nv := range s.nodeStore.ListNodes().All() {
		nodes = append(nodes, nv.AsStruct())
	}

	s.nodeStore.Stop()
	s.polMan = failingSetNodesPolicyManager{PolicyManager: s.polMan}
	s.nodeStore = NewNodeStore(nodes, policyPeersFunc(s.polMan), TestBatchSize, TestBatchTimeout)
	s.nodeStore.Start()

	tests := []struct {
		name  string
		write func() (change.Change, error)
	}{
		{name: "SetNodeTags", write: func() (change.Change, error) {
			_, c, err := s.SetNodeTags(nodeID, []string{"tag:ci"})
			return c, err
		}},
		{name: "RenameNode", write: func() (change.Change, error) {
			_, c, err := s.RenameNode(nodeID, "renamed")
			return c, err
		}},
		{name: "SetNodeExpiry", write: func() (change.Change, error) {
			_, c, err := s.SetNodeExpiry(nodeID, nil)
			return c, err
		}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := tt.write()
			require.ErrorIs(t, err, errInjectedPolicyNodeUpdate)
			assert.Equal(t, nodeID, c.OriginNode, "change: %s", c.Type())
			assert.Contains(t, c.PeersChanged, nodeID, "change: %s", c.Type())
		})
	}
}

// TestBackfillNodeIPsSurvivesConcurrentPersist guards the backfill against a
// node persist landing between its database write and the NodeStore reload:
// that persist writes the old addresses back and the backfill is lost.
func TestBackfillNodeIPsSurvivesConcurrentPersist(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	require.NoError(t, s.Close())

	// Dropping the IPv6 prefix gives the backfill work to do.
	cfg := persistTestConfig(dbPath)
	cfg.PrefixV6 = nil

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, nv.IPv6().Valid(), "precondition: node has an IPv6 address")

	// The backfill reads the nodes table twice: inside its write, then to
	// reload NodeStore. Persist the node just before the reload.
	var reads atomic.Int32

	persisted := make(chan struct{})

	require.NoError(t, s.db.DB.Callback().Query().Before("gorm:query").
		Register("persist_before_reload", func(tx *gorm.DB) {
			if tx.Statement.Table != "nodes" || reads.Add(1) != 2 {
				return
			}

			go func() {
				_, _ = s.persistNode(nv)

				close(persisted)
			}()

			// Give an unserialised persist time to land before the reload.
			select {
			case <-persisted:
			case <-time.After(200 * time.Millisecond):
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Query().Remove("persist_before_reload") })

	_, _, err = s.BackfillNodeIPs()
	require.NoError(t, err)
	<-persisted

	nv, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.False(t, nv.IPv6().Valid(), "NodeStore kept the removed IPv6 address")

	dbNode, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Nil(t, dbNode.IPv6, "database kept the removed IPv6 address")
}

// nameSkipReasons lists checks of [TestNodeNameReplayCompat] where headscale
// differs from SaaS, keyed <test_id>/<step>/<node or action index>/<check>.
// A listed check that matches fails, so a fix must delete its entry.
var nameSkipReasons = map[string]string{
	"names/N11/pdb/label":   adminNameFollowsHostname,
	"names/N11/pdb/reopen":  adminNameFollowsHostname,
	"names/N11b/pdb/label":  adminNameFollowsHostname,
	"names/N11b/pdb/reopen": adminNameFollowsHostname,
	"names/N12a/pdb/label":  adminNameFollowsHostname,
	"names/N12a/pdb/reopen": adminNameFollowsHostname,
	"names/N12b/pdb/label":  adminNameFollowsHostname,
	"names/N12b/pdb/reopen": adminNameFollowsHostname,
	"names/N13/pdb/label":   adminNameFollowsHostname,
	"names/N13/pdb/reopen":  adminNameFollowsHostname,
}

const (
	adminNameFollowsHostname = "ADMIN_NAME_FOLLOWS_HOSTNAME: an admin name equal to the hostname's label counts as derived from it, so a hostname change replaces it; SaaS keeps an admin name across hostname changes"
)

// TestNodeNameReplayCompat replays the names capture through State: joins by
// pre-auth key with no map request after them, restarts and hostname changes
// as map requests, renames and deletes. After each step every device's label
// must be SaaS's, in the NodeStore and as a restart would load it from the
// database, since SaaS never changes a label without a cause.
//
// Test data source: ../servertest/testdata/steps/names.hujson, loaded by
// name; TestNodeNameCompat in ../servertest replays it with clients.
func TestNodeNameReplayCompat(t *testing.T) {
	c, err := testcapture.Read(filepath.Join("..", "servertest", "testdata", "steps", "names.hujson"))
	require.NoError(t, err)

	s, err := NewState(persistTestConfig(t.TempDir() + "/headscale.db"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	// SaaS keys and admin calls act as the tailnet's admin.
	adminName, _, _ := strings.Cut(c.Tailnet, "@")
	admin := s.CreateUserForTest(adminName)

	type replayNode struct {
		id       types.NodeID
		machine  key.MachinePublic
		nodeKey  key.NodePublic
		hostinfo *tailcfg.Hostinfo
	}

	keys := map[string]string{}
	nodes := map[string]*replayNode{}
	evaluated := map[string]bool{}

	for _, step := range c.Steps {
		outcomes := map[int]string{}

		for i, a := range step.Actions {
			switch {
			case a.Kind == "policy":
				_, err := s.SetPolicy([]byte(strings.ReplaceAll(string(a.Body), c.Tailnet, adminName+"@")))
				require.NoError(t, err, "%s: policy", step.Name)

			case a.Kind == "api" && a.Method == http.MethodPost && a.Path == "/tailnet/-/keys":
				var body struct {
					Capabilities struct {
						Devices struct {
							Create struct {
								Tags []string `json:"tags"`
							} `json:"create"`
						} `json:"devices"`
					} `json:"capabilities"`
				}
				require.NoError(t, json.Unmarshal(a.Body, &body), "%s: key body", step.Name)

				pak, err := s.CreatePreAuthKey(admin.TypedID(), true, false, nil, body.Capabilities.Devices.Create.Tags)
				require.NoError(t, err, "%s: mint %s", step.Name, a.Key)

				keys[a.Key] = pak.Key

			case a.Kind == "join":
				n := &replayNode{
					machine:  key.NewMachine().Public(),
					nodeKey:  key.NewNode().Public(),
					hostinfo: &tailcfg.Hostinfo{Hostname: a.Hostname},
				}
				if a.RequestTags != nil {
					n.hostinfo.RequestTags = *a.RequestTags
				}

				nv, _, err := s.HandleNodeFromPreAuthKey(tailcfg.RegisterRequest{
					Auth:     &tailcfg.RegisterResponseAuth{AuthKey: keys[a.Key]},
					NodeKey:  n.nodeKey,
					Hostinfo: n.hostinfo.Clone(),
				}, n.machine)
				require.NoError(t, err, "%s: join %s", step.Name, a.Node)

				n.id = nv.ID()
				nodes[a.Node] = n

			case a.Kind == "restart", a.Kind == "set_hostname":
				// A restarted tailscaled polls with a new disco key.
				n := nodes[a.Node]
				if a.Kind == "set_hostname" {
					n.hostinfo.Hostname = a.Hostname
				}

				_, err := s.UpdateNodeFromMapRequest(n.id, tailcfg.MapRequest{
					NodeKey:  n.nodeKey,
					DiscoKey: key.NewDisco().Public(),
					Hostinfo: n.hostinfo.Clone(),
				})
				require.NoError(t, err, "%s: %s %s", step.Name, a.Kind, a.Node)

			case a.Kind == "retire", a.Kind == "api" && a.Method == http.MethodDelete:
				alias := a.Node
				if alias == "" {
					alias = captureDeviceAlias(a.Path)
				}

				nv, ok := s.GetNodeByID(nodes[alias].id)
				require.True(t, ok, "%s: delete of a missing %s", step.Name, alias)

				_, err := s.DeleteNode(nv)
				require.NoError(t, err, "%s: delete %s", step.Name, alias)

			case a.Kind == "api" && strings.HasSuffix(a.Path, "/name"):
				var body struct {
					Name string `json:"name"`
				}
				require.NoError(t, json.Unmarshal(a.Body, &body), "%s: rename body", step.Name)

				_, _, err := s.RenameNode(nodes[captureDeviceAlias(a.Path)].id, body.Name)
				outcomes[i] = renameOutcome(err == nil)

			case a.Kind == "kill", a.Kind == "wait",
				a.Kind == "api" && (a.Method == http.MethodGet || strings.HasPrefix(a.Path, "/tailnet/-/dns/")):
				// A killed daemon only stops polling; reads change nothing,
				// and DNS comes from the config.

			default:
				t.Fatalf("%s: no replay for %s %s %s", step.Name, a.Kind, a.Method, a.Path)
			}
		}

		devices, ok := captureDevices(t, step)
		if !ok {
			continue
		}

		reopened := reopenLabels(t, s)

		t.Run(step.Name, func(t *testing.T) {
			prefix := c.TestID + "/" + step.Name + "/"

			var listed, live []string

			for _, d := range devices {
				alias := captureDeviceAlias(d.ID)
				n, ok := nodes[alias]
				require.True(t, ok, "%s never joined", alias)

				listed = append(listed, alias)
				want, _, _ := strings.Cut(d.Name, ".")

				got := "absent"
				if nv, ok := s.GetNodeByID(n.id); ok {
					got = nv.GivenName()
				}

				reload, ok := reopened[n.id]
				if !ok {
					reload = "absent"
				}

				nameCheck(t, prefix, alias+"/label", want, got, evaluated)
				nameCheck(t, prefix, alias+"/reopen", want, reload, evaluated)
			}

			for alias, n := range nodes {
				if _, ok := s.GetNodeByID(n.id); ok {
					live = append(live, alias)
				}
			}

			slices.Sort(listed)
			slices.Sort(live)
			nameCheck(t, prefix, "devices", strings.Join(listed, " "), strings.Join(live, " "), evaluated)

			for _, i := range slices.Sorted(maps.Keys(outcomes)) {
				want := renameOutcome(step.Actions[i].Status == http.StatusOK)
				nameCheck(t, prefix, strconv.Itoa(i)+"/outcome", want, outcomes[i], evaluated)
			}
		})
	}

	for k := range nameSkipReasons {
		if !evaluated[k] {
			t.Errorf("skip entry %q names no check", k)
		}
	}
}

// nameCheck compares one check against SaaS. A check listed in
// nameSkipReasons is skipped while it differs and fails once it matches.
func nameCheck(t *testing.T, prefix, name, want, got string, evaluated map[string]bool) {
	t.Helper()

	key := prefix + name
	evaluated[key] = true

	t.Run(name, func(t *testing.T) {
		reason, listed := nameSkipReasons[key]

		switch {
		case listed && got == want:
			t.Errorf("matches SaaS; delete the skip entry %q (%s)", key, reason)
		case listed:
			t.Skip(reason)
		default:
			assert.Equal(t, want, got)
		}
	})
}

func renameOutcome(accepted bool) string {
	if accepted {
		return "accepted"
	}

	return "refused"
}

// captureDevices decodes the step's last device-list read.
func captureDevices(t *testing.T, step testcapture.Step) ([]struct{ ID, Name string }, bool) {
	t.Helper()

	for _, a := range slices.Backward(step.Actions) {
		if a.Kind != "api" || a.Method != http.MethodGet || !strings.HasPrefix(a.Path, "/tailnet/-/devices") {
			continue
		}

		var out struct {
			Devices []struct{ ID, Name string } `json:"devices"`
		}
		require.NoError(t, json.Unmarshal(a.Response, &out), "%s: %s", step.Name, a.Path)

		return out.Devices, true
	}

	return nil, false
}

// captureDeviceAlias extracts x from "{device:x}" or "/device/{device:x}/...".
func captureDeviceAlias(s string) string {
	_, rest, _ := strings.Cut(s, "{device:")
	alias, _, _ := strings.Cut(rest, "}")

	return alias
}

// reopenLabels returns each node's label as a restart would load it: from a
// State opened on a copy of s's database.
func reopenLabels(t *testing.T, s *State) map[types.NodeID]string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "copy.db")
	require.NoError(t, s.db.DB.Exec("VACUUM INTO ?", path).Error)

	reopened, err := NewState(persistTestConfig(path))
	require.NoError(t, err)

	defer reopened.Close()

	out := map[types.NodeID]string{}
	for _, nv := range reopened.ListNodes().All() {
		out[nv.ID()] = nv.GivenName()
	}

	return out
}

// TestBringNodeExpiryForwardDecidesInWriter: a client's earlier expiry is
// checked against the node as the writer holds it, so an admin expiry that
// lands after the caller read the node is not pushed back, and a node key
// the node no longer holds changes nothing.
func TestBringNodeExpiryForwardDecidesInWriter(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	read, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	_, _, err := s.SetNodeExpiry(nodeID, nil)
	require.NoError(t, err)

	soon := time.Now().Add(time.Hour).Truncate(time.Second)
	node, _, err := s.BringNodeExpiryForward(nodeID, read.NodeKey(), soon)
	require.NoError(t, err)
	require.True(t, node.Expiry().Valid(), "an earlier expiry turns expiry on")
	assert.True(t, soon.Equal(node.Expiry().Get()))

	_, _, err = s.BringNodeExpiryForward(nodeID, read.NodeKey(), soon.Add(time.Minute))
	require.ErrorIs(t, err, ErrExpiryExtension, "a later expiry")

	_, _, err = s.BringNodeExpiryForward(nodeID, key.NewNode().Public(), soon.Add(-time.Minute))
	require.ErrorIs(t, err, ErrExpiryExtension, "another node key")

	past := time.Now().Add(-time.Minute).Truncate(time.Second)
	_, _, err = s.SetNodeExpiry(nodeID, &past)
	require.NoError(t, err)

	_, _, err = s.BringNodeExpiryForward(nodeID, read.NodeKey(), soon.Add(-time.Minute))
	require.ErrorIs(t, err, ErrExpiryExtension, "the admin expiry is earlier")

	current, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.True(t, current.IsExpired(), "the admin expiry stands")

	stored, err := s.db.GetNodeByID(nodeID)
	require.NoError(t, err)
	require.NotNil(t, stored.Expiry)
	assert.True(t, past.Equal(*stored.Expiry))
}

// TestSetNodeExpiryRejectsUnencodableExpiry proves an admin cannot store a key
// expiry that every map carrying the node would fail to encode.
func TestSetNodeExpiryRejectsUnencodableExpiry(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	beyond, err := time.Parse(time.RFC3339, "9999-12-31T23:59:59-23:59")
	require.NoError(t, err)

	before := s.nodeStore.data.Load()

	_, _, err = s.SetNodeExpiry(nodeID, &beyond)
	require.ErrorIs(t, err, types.ErrExpiryOutOfRange)
	require.Same(t, before, s.nodeStore.data.Load(),
		"a refused expiry must not reach the NodeStore")

	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	_, _, err = s.SetNodeExpiry(nodeID, &latest)
	require.NoError(t, err)
}

// TestAuthPathRejectsUnencodableExpiry proves an expiry handed to the auth
// path, such as an OIDC token's, cannot store what SetNodeExpiry refuses.
func TestAuthPathRejectsUnencodableExpiry(t *testing.T) {
	_, s, _ := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	user := s.CreateUserForTest("auth-path-user")
	nodeKey := key.NewNode().Public()
	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    nodeKey,
		Hostname:   "auth-path-node",
	})))

	// How go-oidc reads an exp claim in the year 10000.
	beyond := time.Unix(253402300800, 0)

	_, _, err := s.HandleNodeFromAuthPath(
		authID, types.UserID(user.ID), &beyond, util.RegisterMethodOIDC,
	)
	require.ErrorIs(t, err, types.ErrExpiryOutOfRange)

	_, found := s.GetNodeByNodeKey(nodeKey)
	require.False(t, found, "a refused expiry must not create a node")
}

// TestAcceptedExpirySurvivesRestart proves an accepted expiry that is already in
// the year 10000 in its own zone is stored so SQLite can load it at the next
// start. go-oidc reads a token's exp in the server's zone, east of UTC here.
func TestAcceptedExpirySurvivesRestart(t *testing.T) {
	latest := time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)
	east := latest.In(time.FixedZone("", 60*60))

	dbPath, s, adminID := persistTestSetup(t)

	_, _, err := s.SetNodeExpiry(adminID, &east)
	require.NoError(t, err)

	user := s.CreateUserForTest("oidc-user")
	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: key.NewMachine().Public(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   "oidc-node",
	})))

	oidcNode, _, err := s.HandleNodeFromAuthPath(
		authID, types.UserID(user.ID), &east, util.RegisterMethodOIDC,
	)
	require.NoError(t, err)
	require.NoError(t, s.Close())

	s = persistTestReopen(t, dbPath)

	for _, id := range []types.NodeID{adminID, oidcNode.ID()} {
		nv, ok := s.GetNodeByID(id)
		require.True(t, ok)
		assert.True(t, latest.Equal(nv.Expiry().Get()), "node %d", id)
	}
}

// TestLoadedExpiryIsUTC proves an expiry the database returns in another zone is
// served in UTC. PostgreSQL returns the server's zone, where the latest accepted
// expiry is in the year 10000 and cannot be encoded.
func TestLoadedExpiryIsUTC(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	require.NoError(t, s.Close())

	expiry := time.Date(2030, time.January, 1, 0, 0, 0, 0, time.UTC)

	database, err := db.NewHeadscaleDatabase(persistTestConfig(dbPath))
	require.NoError(t, err)
	require.NoError(t, database.DB.Model(&types.Node{}).Where("id = ?", nodeID).
		Update("expiry", expiry.In(time.FixedZone("", 60*60))).Error)
	require.NoError(t, database.Close())

	s = persistTestReopen(t, dbPath)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	got := nv.Expiry().Get()
	assert.True(t, expiry.Equal(got))
	assert.Equal(t, time.UTC, got.Location())
}

// TestNewStateBoundsStoredClientReport covers legacy reports before they reach peers.
func TestNewStateBoundsStoredClientReport(t *testing.T) {
	endpoints := make([]netip.AddrPort, types.MaxEndpoints+1)
	for i := range endpoints {
		endpoints[i] = netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), uint16(i))
	}

	routes := make([]netip.Prefix, types.MaxRoutableIPs+1)
	for i := range routes {
		routes[i] = netip.PrefixFrom(netip.AddrFrom16([16]byte{0xfd, byte(i >> 8), byte(i)}), 64)
	}

	for _, tt := range []struct {
		name          string
		hostname      string
		endpoints     []netip.AddrPort
		routes        []netip.Prefix
		wantHostname  string
		wantEndpoints []netip.AddrPort
		wantRoutes    []netip.Prefix
	}{
		{
			name:          "at limits",
			hostname:      strings.Repeat("h", types.MaxHostnameLength),
			endpoints:     endpoints[:types.MaxEndpoints],
			routes:        routes[:types.MaxRoutableIPs],
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength),
			wantEndpoints: endpoints[:types.MaxEndpoints],
			wantRoutes:    routes[:types.MaxRoutableIPs],
		},
		{
			name:          "over limits",
			hostname:      strings.Repeat("h", types.MaxHostnameLength+1),
			endpoints:     endpoints,
			routes:        routes,
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength),
			wantEndpoints: endpoints[:types.MaxEndpoints],
			wantRoutes:    routes[:types.MaxRoutableIPs],
		},
		{
			name:     "multibyte hostname and zoned endpoint",
			hostname: strings.Repeat("h", types.MaxHostnameLength-1) + "é",
			endpoints: []netip.AddrPort{
				netip.MustParseAddrPort("[fe80::1%eth0]:41641"), endpoints[0],
			},
			wantHostname:  strings.Repeat("h", types.MaxHostnameLength-1),
			wantEndpoints: endpoints[:1],
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dbPath := t.TempDir() + "/headscale.db"
			cfg := persistTestConfig(dbPath)
			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			user := database.CreateUserForTest("bound-user")
			node := database.CreateRegisteredNodeForTest(user, "bounded")
			err = database.DB.Model(node).Select("Hostname", "Endpoints", "Hostinfo").
				Updates(&types.Node{
					Hostname:  tt.hostname,
					Endpoints: tt.endpoints,
					Hostinfo: &tailcfg.Hostinfo{
						Hostname: tt.hostname, RoutableIPs: tt.routes,
						NetInfo: &tailcfg.NetInfo{PreferredDERP: 1, DERPLatency: map[string]float64{"1-v4": 0.01}},
					},
				}).Error
			require.NoError(t, err)
			require.NoError(t, database.Close())

			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			nv, ok := s.GetNodeByID(node.ID)
			require.True(t, ok)
			require.True(t, nv.Hostinfo().Valid())
			assert.Equal(t, tailcfg.DERPRegionID(1), nv.Hostinfo().NetInfo().PreferredDERP())
			assert.Nil(t, nv.Hostinfo().AsStruct().NetInfo.DERPLatency)
			assert.Equal(t, tt.wantHostname, nv.Hostname())
			assert.Equal(t, tt.wantHostname, nv.Hostinfo().Hostname())
			assert.Equal(t, tt.wantEndpoints, nv.Endpoints().AsSlice())
			assert.Equal(t, tt.wantRoutes, nv.Hostinfo().RoutableIPs().AsSlice())

			c, err := s.UpdateNodeFromMapRequest(node.ID, tailcfg.MapRequest{
				NodeKey: nv.NodeKey(), DiscoKey: key.NewDisco().Public(),
			})
			require.NoError(t, err)
			require.Len(t, c.PeerPatches, 1)
			assert.Equal(t, tt.wantEndpoints, c.PeerPatches[0].Endpoints)

			row, err := s.DB().GetNodeByID(node.ID)
			require.NoError(t, err)
			assert.Equal(t, tt.wantHostname, row.Hostname, "the next persist rewrites the row")
			assert.True(t, slices.Equal(tt.wantEndpoints, row.Endpoints), "persisted endpoints match the bounded report")
			assert.Equal(t, tt.wantRoutes, row.Hostinfo.RoutableIPs)
		})
	}
}

func TestNewStateDiscardsOversizedHostinfo(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)
	err := s.DB().DB.Model(&types.Node{ID: nodeID}).Select("Hostinfo").
		Updates(&types.Node{Hostinfo: &tailcfg.Hostinfo{
			OSVersion: strings.Repeat("v", types.MaxHostinfoSize),
		}}).Error
	require.NoError(t, err)
	require.NoError(t, s.Close())

	nv, ok := persistTestReopen(t, dbPath).GetNodeByID(nodeID)
	require.True(t, ok)
	assert.False(t, nv.Hostinfo().Valid(),
		"oversized Hostinfo is dropped until the node reports again")
}

// TestBootKeepsHostinfoTheMapPathStored pins that the startup check keeps
// what the map path accepted. A report without NetInfo keeps the stored one,
// so a stored Hostinfo can combine fields from two reports.
func TestBootKeepsHostinfoTheMapPathStored(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	nv, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	for _, hi := range []*tailcfg.Hostinfo{
		{
			Hostname: nv.Hostname(),
			NetInfo: &tailcfg.NetInfo{
				PreferredDERP: 1,
				LinkType:      strings.Repeat("l", 60<<10),
			},
		},
		{Hostname: nv.Hostname(), OSVersion: strings.Repeat("v", 60<<10)},
	} {
		req := tailcfg.MapRequest{
			NodeKey: nv.NodeKey(), DiscoKey: nv.DiscoKey(), Hostinfo: hi,
		}
		require.NoError(t, types.ValidateHostinfo(req.Hostinfo))

		_, err := s.UpdateNodeFromMapRequest(nodeID, req)
		require.NoError(t, err)
	}

	require.NoError(t, s.Close())

	reloaded, ok := persistTestReopen(t, dbPath).GetNodeByID(nodeID)
	require.True(t, ok)
	require.True(t, reloaded.Hostinfo().Valid(),
		"the startup check must keep a Hostinfo the map path stored")
	assert.Equal(t, tailcfg.DERPRegionID(1),
		reloaded.Hostinfo().NetInfo().PreferredDERP())

	osVersionLen := len(reloaded.Hostinfo().OSVersion())
	assert.Equal(t, 60<<10, osVersionLen)
}

// TestReauthKeepsOperationalMetadata covers a relogin before the next map request.
// Pending registrations carry only auth metadata; live connectivity must survive.
func TestReauthKeepsOperationalMetadata(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.0.0.0/24")

	node, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{
			Hostname: n.Hostname, RoutableIPs: []netip.Prefix{route},
			OS: "linux", OSVersion: "6.12.0",
			Services:     []tailcfg.Service{{Proto: tailcfg.PeerAPI4, Port: 41641}},
			SSH_HostKeys: []string{"ssh-ed25519 key"},
			NetInfo:      &tailcfg.NetInfo{PreferredDERP: 1},
		}
		n.DiscoKey = key.NewDisco().Public()
		n.Endpoints = []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")}
		n.ApprovedRoutes = []netip.Prefix{route}
	})
	require.True(t, ok)

	_, epoch := s.Connect(nodeID)
	require.NotZero(t, epoch)
	require.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(nodeID),
		"precondition: the node serves its route")

	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: node.MachineKey(),
		NodeKey:    key.NewNode().Public(),
		Hostname:   node.Hostname(),
		Hostinfo:   &tailcfg.Hostinfo{Hostname: node.Hostname()},
	})))

	relogged, _, err := s.HandleNodeFromAuthPath(
		authID, node.TypedUserID(), nil, util.RegisterMethodOIDC,
	)
	require.NoError(t, err)
	require.Equal(t, nodeID, relogged.ID(), "relogin must update the existing node")

	assert.Equal(t, []netip.Prefix{route}, relogged.AnnouncedRoutes())
	assert.Equal(t, []netip.Prefix{route}, s.GetNodePrimaryRoutes(nodeID))
	assert.True(t, node.Hostinfo().Equal(relogged.Hostinfo()))
	assert.Equal(t, node.DiscoKey(), relogged.DiscoKey())
	assert.Equal(t, node.Endpoints(), relogged.Endpoints())
}

func TestReauthRejectsOversizedMergedHostinfo(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	hi := &tailcfg.Hostinfo{Hostname: node.Hostname(), OSVersion: "v"}
	encoded, err := json.Marshal(hi)
	require.NoError(t, err)

	hi.OSVersion = strings.Repeat("v", types.MaxHostinfoSize-len(encoded)+1)
	require.NoError(t, types.ValidateHostinfo(hi))
	_, err = s.UpdateNodeFromMapRequest(nodeID, tailcfg.MapRequest{
		NodeKey: node.NodeKey(), DiscoKey: node.DiscoKey(), Hostinfo: hi,
	})
	require.NoError(t, err)

	before, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	rowBefore, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)

	hostname := strings.Repeat("h", types.MaxHostnameLength)
	require.NoError(t, types.ValidateHostinfo(&tailcfg.Hostinfo{Hostname: hostname}))

	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: node.MachineKey(), NodeKey: key.NewNode().Public(),
		Hostname: hostname, Hostinfo: &tailcfg.Hostinfo{Hostname: hostname},
	})))
	_, _, err = s.HandleNodeFromAuthPath(authID, node.TypedUserID(), nil, util.RegisterMethodOIDC)
	require.ErrorIs(t, err, types.ErrHostinfoTooLarge)

	after, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, before.AsStruct(), after.AsStruct(), "rejected merge leaves the live node unchanged")

	rowAfter, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	assert.Equal(t, rowBefore, rowAfter, "rejected merge leaves the stored node unchanged")
}

func TestReauthKeepsTaggedFutureExpiry(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:ci":["persist-user@"]}}`))
	require.NoError(t, err)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	userID := node.TypedUserID()
	_, _, err = s.SetNodeTags(nodeID, []string{"tag:ci"})
	require.NoError(t, err)

	future := time.Now().Add(time.Hour).UTC()
	node, ok = s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Expiry = &future
	})
	require.True(t, ok)
	require.True(t, node.IsTagged())

	authID := types.MustAuthID()
	require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
		MachineKey: node.MachineKey(), NodeKey: key.NewNode().Public(),
		Hostname: node.Hostname(),
		Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), RequestTags: []string{"tag:ci"}},
	})))
	relogged, _, err := s.HandleNodeFromAuthPath(authID, userID, nil, util.RegisterMethodOIDC)
	require.NoError(t, err)
	require.Equal(t, nodeID, relogged.ID())
	require.True(t, relogged.IsTagged())
	require.True(t, relogged.Expiry().Valid())
	assert.True(t, future.Equal(relogged.Expiry().Get()))

	row, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.NotNil(t, row.Expiry)
	assert.True(t, future.Equal(*row.Expiry))
}

func TestReauthReplacesReportedTags(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	_, err := s.SetPolicy([]byte(`{"tagOwners":{"tag:a":["persist-user@"],"tag:b":["persist-user@"]}}`))
	require.NoError(t, err)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	userID := node.TypedUserID()

	for _, tags := range [][]string{{"tag:a"}, nil, {"tag:b"}} {
		want := slices.Clone(tags)
		authID := types.MustAuthID()
		require.NoError(t, s.SetAuthCacheEntry(authID, types.NewRegisterAuthRequest(&types.RegistrationData{
			MachineKey: node.MachineKey(), NodeKey: key.NewNode().Public(),
			Hostname: node.Hostname(),
			Hostinfo: &tailcfg.Hostinfo{Hostname: node.Hostname(), RequestTags: tags},
		})))
		relogged, _, err := s.HandleNodeFromAuthPath(authID, userID, nil, util.RegisterMethodOIDC)
		require.NoError(t, err)
		require.Equal(t, nodeID, relogged.ID())
		assert.Equal(t, want, relogged.Hostinfo().RequestTags().AsSlice())
		assert.Equal(t, len(want) > 0, relogged.IsTagged())

		if len(tags) > 0 {
			tags[0] = "tag:changed"
		}

		stored, ok := s.GetNodeByID(nodeID)
		require.True(t, ok)
		assert.Equal(t, want, stored.Hostinfo().RequestTags().AsSlice(),
			"cached tags must not alias stored Hostinfo")

		row, err := s.DB().GetNodeByID(nodeID)
		require.NoError(t, err)
		assert.Equal(t, want, row.Hostinfo.RequestTags)
	}
}

func TestUpdateUserClearsColumns(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	userID := types.UserID(node.UserID().Get())
	_, _, err := s.UpdateUser(userID, func(user *types.User) error {
		user.DisplayName = "Display"
		user.Email = "persist@example.com"
		user.ProfilePicURL = "https://example.com/picture"

		return nil
	})
	require.NoError(t, err)
	_, _, err = s.RenameUser(userID, "renamed")
	require.NoError(t, err)
	user, err := s.GetUserByID(userID)
	require.NoError(t, err)
	assert.Equal(t, "Display", user.DisplayName)
	assert.Equal(t, "persist@example.com", user.Email)
	assert.Equal(t, "https://example.com/picture", user.ProfilePicURL)
	_, _, err = s.UpdateUser(userID, func(user *types.User) error {
		user.DisplayName = ""
		user.Email = ""
		user.ProfilePicURL = ""

		return nil
	})
	require.NoError(t, err)
	user, err = s.GetUserByID(userID)
	require.NoError(t, err)
	assert.Empty(t, user.DisplayName)
	assert.Empty(t, user.Email)
	assert.Empty(t, user.ProfilePicURL)
	assert.Equal(t, "renamed", user.Name)
}

func TestUpdateUserRefreshesNodeCopies(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	original, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	userID := types.UserID(original.UserID().Get())
	user, err := s.GetUserByID(userID)
	require.NoError(t, err)

	_, ok = s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.AuthKey = &types.Credential{ID: 1, UserID: new(user.ID), User: user.Clone()}
	})
	require.True(t, ok)

	tagged := s.nodeStore.PutNode(types.Node{
		ID: nodeID + 1, Hostname: "tagged", Tags: []string{"tag:server"},
		MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(),
		AuthKey: &types.Credential{ID: 2, UserID: new(user.ID), User: user.Clone()},
	})
	other, _, err := s.CreateUser(types.User{Name: "other"})
	require.NoError(t, err)

	otherNode := s.nodeStore.PutNode(types.Node{
		ID: nodeID + 2, Hostname: "other", UserID: new(other.ID), User: other.Clone(),
		MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public(),
		AuthKey: &types.Credential{ID: 3, UserID: new(other.ID), User: other.Clone()},
	})
	before, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	_, c, err := s.RenameUser(userID, "renamed-user")
	require.NoError(t, err)
	assert.True(t, c.IncludeSelf)
	assert.True(t, c.SendAllPeers)

	updated, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, "renamed-user", updated.User().Name())
	assert.Equal(t, "renamed-user", updated.AuthKey().User().Name())
	assert.Equal(t, "persist-user", before.User().Name())
	assert.Equal(t, "persist-user", before.AuthKey().User().Name())

	updatedTagged, ok := s.GetNodeByID(tagged.ID())
	require.True(t, ok)
	assert.True(t, updatedTagged.IsTagged())
	assert.Equal(t, "renamed-user", updatedTagged.AuthKey().User().Name())
	assert.Equal(t, "persist-user", tagged.AuthKey().User().Name())

	unchanged, ok := s.GetNodeByID(otherNode.ID())
	require.True(t, ok)
	assert.Equal(t, "other", unchanged.User().Name())
	assert.Equal(t, "other", unchanged.AuthKey().User().Name())

	snapshot := s.nodeStore.data.Load()
	_, c, err = s.RenameUser(userID, "renamed-user")
	require.NoError(t, err)
	assert.True(t, c.IsEmpty())
	assert.Same(t, snapshot, s.nodeStore.data.Load(), "an unchanged user must not rebuild the snapshot")

	_, c, err = s.UpdateUser(userID, func(user *types.User) error {
		user.Provider = "updated-provider"
		return nil
	})
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "a non-profile column does not need a full map update")

	updated, ok = s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, "updated-provider", updated.User().Provider())
	assert.Equal(t, "updated-provider", updated.AuthKey().User().Provider())
}

type blockingSetUsersPolicyManager struct {
	policy.PolicyManager

	blocked atomic.Bool
	reached chan struct{}
	resume  <-chan struct{}
	last    []types.User
}

func (pm *blockingSetUsersPolicyManager) SetUsers(users []types.User) (bool, bool, error) {
	if !pm.blocked.Swap(true) {
		close(pm.reached)
		<-pm.resume
	}

	pm.last = users

	return pm.PolicyManager.SetUsers(users)
}

func TestUpdateUserPublishesInOrder(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	user := node.User().AsStruct()
	userID := types.UserID(user.ID)
	_, ok = s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.AuthKey = &types.Credential{ID: 1, UserID: new(user.ID), User: user.Clone()}
	})
	require.True(t, ok)

	resume := make(chan struct{})

	releaseFirst := sync.OnceFunc(func() { close(resume) })
	defer releaseFirst()

	pm := &blockingSetUsersPolicyManager{
		PolicyManager: s.polMan,
		reached:       make(chan struct{}),
		resume:        resume,
	}
	s.polMan = pm

	update := func(name string) error {
		_, _, err := s.UpdateUser(userID, func(u *types.User) error {
			u.Name = name
			u.Email = name + "@example.com"
			u.DisplayName = name + " display"
			u.ProfilePicURL = "https://example.com/" + name

			return nil
		})

		return err
	}

	firstDone := make(chan error, 1)
	go func() { firstDone <- update("first-user") }()

	// The first update pauses after its commit, inside the policy user update.
	<-pm.reached

	var secondErr error

	secondDone := make(chan struct{})

	go func() {
		secondErr = update("latest-user")

		close(secondDone)
	}()

	// Give the second update time to overtake the paused first one.
	select {
	case <-secondDone:
	case <-time.After(100 * time.Millisecond):
	}

	releaseFirst()
	require.NoError(t, <-firstDone)
	<-secondDone
	require.NoError(t, secondErr)

	stored, err := s.GetUserByID(userID)
	require.NoError(t, err)
	assert.Equal(t, "latest-user", stored.Name)

	require.Len(t, pm.last, 1)
	assert.Equal(t, stored.Name, pm.last[0].Name, "policy users must follow the database")

	updated, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, stored.Name, updated.User().Name())
	assert.Equal(t, stored.Name, updated.AuthKey().User().Name())
	assert.Equal(t, stored.TailscaleUserProfile(), updated.User().TailscaleUserProfile())
	assert.Equal(t, stored.TailscaleUserProfile(), updated.AuthKey().User().TailscaleUserProfile())
}

func TestUserListPublishesInOrder(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	resume := make(chan struct{})

	releaseFirst := sync.OnceFunc(func() { close(resume) })
	defer releaseFirst()

	pm := &blockingSetUsersPolicyManager{
		PolicyManager: s.polMan,
		reached:       make(chan struct{}),
		resume:        resume,
	}
	s.polMan = pm

	createDone := make(chan error, 1)

	go func() {
		_, _, err := s.CreateUser(types.User{Name: "created-user"})
		createDone <- err
	}()

	// The creation pauses holding a user list read before the rename commits.
	<-pm.reached

	var renameErr error

	renameDone := make(chan struct{})

	go func() {
		_, _, renameErr = s.RenameUser(types.UserID(node.User().ID()), "renamed-user")

		close(renameDone)
	}()

	select {
	case <-renameDone:
	case <-time.After(100 * time.Millisecond):
	}

	releaseFirst()
	require.NoError(t, <-createDone)
	<-renameDone
	require.NoError(t, renameErr)

	names := make([]string, 0, len(pm.last))
	for _, user := range pm.last {
		names = append(names, user.Name)
	}

	assert.ElementsMatch(t, []string{"renamed-user", "created-user"}, names,
		"policy users must follow the database")
}

var errSetUsersTest = errors.New("set users failed")

type failingSetUsersPolicyManager struct {
	policy.PolicyManager
}

func (failingSetUsersPolicyManager) SetUsers([]types.User) (bool, bool, error) {
	return false, false, errSetUsersTest
}

func TestUpdateUserRefreshesNodeCopiesWhenPolicyUpdateFails(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	s.polMan = failingSetUsersPolicyManager{PolicyManager: s.polMan}

	_, _, err := s.RenameUser(types.UserID(node.User().ID()), "renamed-user")
	require.ErrorIs(t, err, errSetUsersTest)

	updated, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, "renamed-user", updated.User().Name(),
		"the committed row and its cached copy must agree")
}

func TestUserNameCollisionDoesNotBlockCreationOrRestart(t *testing.T) {
	dbPath := t.TempDir() + "/headscale.db"
	cfg := persistTestConfig(dbPath)
	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("dup")
	node := database.CreateRegisteredNodeForTest(user, "duplicate-name-node")
	_, err = database.SetPolicy(`{
		"acls": [],
		"nodeAttrs": [{"target":["dup@"], "attr":["randomize-client-port"]}]
	}`)
	require.NoError(t, err)
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() {
		if s != nil {
			_ = s.Close()
		}
	})
	require.NotEmpty(t, s.polMan.NodeCapMap(node.ID))

	created, _, err := s.CreateUser(types.User{
		Name:               "dup",
		Provider:           "oidc",
		ProviderIdentifier: sql.NullString{String: "https://idp.example/second", Valid: true},
	})
	require.NoError(t, err, "a colliding user must not prevent user creation")
	require.NotNil(t, created)

	_, _, err = s.CreateUser(types.User{Name: "later"})
	require.NoError(t, err, "a previous collision must not prevent later user creation")
	assert.Empty(t, s.polMan.NodeCapMap(node.ID))
	require.NoError(t, s.Close())
	s = nil

	reopened := persistTestReopen(t, dbPath)
	users, err := reopened.ListAllUsers()
	require.NoError(t, err)
	require.Len(t, users, 3)
	require.Empty(t, reopened.polMan.NodeCapMap(node.ID))
}
