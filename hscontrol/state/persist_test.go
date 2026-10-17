package state

import (
	"encoding/json"
	"errors"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
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
		ValidHostinfo:  &tailcfg.Hostinfo{},
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
		ValidHostinfo:  &tailcfg.Hostinfo{},
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
// momentarily-endpoint-less peer disco-deaf); a policy change forces a full
// recompute; a new node is a whole-node add.
func TestReauthChange(t *testing.T) {
	n := types.Node{
		ID:       7,
		NodeKey:  key.NewNode().Public(),
		DiscoKey: key.NewDisco().Public(),
	}
	node := n.View()

	relogin := reauthChange(node, true, false)
	assert.Len(t, relogin.PeerPatches, 1, "relogin must be a peer patch")
	assert.Empty(t, relogin.PeersChanged, "relogin must not be a whole-node add")

	added := reauthChange(node, false, false)
	assert.Empty(t, added.PeerPatches)
	assert.Len(t, added.PeersChanged, 1, "a new node must be a whole-node add")

	pol := reauthChange(node, true, true)
	assert.Empty(t, pol.PeerPatches, "a policy change must not be a peer patch")
	assert.Empty(t, pol.PeersChanged)
	assert.False(t, pol.IsEmpty(), "a policy change must be non-empty")
}

// TestOnlyKeysChanged covers which relogins may ride the key-rotation patch:
// one that flips Expired or changes Hostinfo peers read must not, as
// [tailcfg.PeerChange] carries neither (#3531).
func TestOnlyKeysChanged(t *testing.T) {
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

	tests := []struct {
		name          string
		before, after types.NodeView
		want          bool
	}{
		{name: "keys", before: node(future, hi), after: node(future, hi), want: true},
		{name: "hostinfo peers do not read", before: node(future, hi), after: node(future, withOSVersion), want: true},
		{name: "un-expired", before: node(past, hi), after: node(future, hi)},
		{name: "hostinfo peers read", before: node(future, hi), after: node(future, withService)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, onlyKeysChanged(tt.before, tt.after, now))
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
	_, s, nodeID := persistTestSetup(t)
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
	require.NotEmpty(t, cs)
	assert.Equal(t, []types.NodeID{nodeID}, cs[0].PeersRemoved,
		"a committed deletion must still notify peers and stop the node's session")
	assert.Equal(t, []types.NodeID{nodeID}, cs[0].DeletedNodes,
		"a committed deletion must identify the session to stop")

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

// TestReloadPolicyReturnsChangesOnAutoApproveFailure covers a policy reload
// whose route auto-approval fails to persist. The NodeStore write already
// fed the approved routes to the policy manager, so no later write sees the
// policy move again; the reload must return its changes with the error for
// the caller to publish.
func TestReloadPolicyReturnsChangesOnAutoApproveFailure(t *testing.T) {
	_, s, nodeID := persistTestSetup(t)
	t.Cleanup(func() { _ = s.Close() })

	route := netip.MustParsePrefix("10.9.0.0/24")
	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Hostinfo = &tailcfg.Hostinfo{RoutableIPs: []netip.Prefix{route}}
	})
	require.True(t, ok)

	_, err := s.db.SetPolicy(`{
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
		"autoApprovers": {"routes": {"10.9.0.0/24": ["persist-user@"]}}
	}`)
	require.NoError(t, err)

	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
				_ = tx.AddError(errInjectedNodeUpdate)
			}
		}))
	t.Cleanup(func() { _ = s.db.DB.Callback().Update().Remove("fail_node_update") })

	cs, err := s.ReloadPolicy()
	require.ErrorIs(t, err, errInjectedNodeUpdate)

	approved, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	require.Contains(t, approved.ApprovedRoutes().AsSlice(), route,
		"the NodeStore holds the approval the database write lost")

	assert.True(t, slices.ContainsFunc(cs, func(c change.Change) bool { return c.IncludePolicy }),
		"the reload must return its policy change with the error: %v", cs)
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
	"names/N1/db-b/reopen": labelNotSaved,
	"names/N5/e2/reopen":   labelNotSaved,
	"names/N5/e1/reopen":   labelNotSaved,
	"names/N6/e2/reopen":   labelNotSaved,
	"names/N6/e1/reopen":   labelNotSaved,
	"names/N7/e2/reopen":   labelNotSaved,
	"names/N7/e1/reopen":   labelNotSaved,
	"names/N8/e2/reopen":   labelNotSaved,
	"names/N8/e1/reopen":   labelNotSaved,
	"names/N9a/e2/reopen":  labelNotSaved,
	"names/N9a/e1/reopen":  labelNotSaved,
	"names/N9b/e2/reopen":  labelNotSaved,
	"names/N9b/e1/reopen":  labelNotSaved,
	"names/N10/e2/reopen":  labelNotSaved,
	"names/N10/e1/reopen":  labelNotSaved,
	"names/N11/e2/reopen":  labelNotSaved,
	"names/N11/e1/reopen":  labelNotSaved,
	"names/N11b/e2/reopen": labelNotSaved,
	"names/N11b/e1/reopen": labelNotSaved,
	"names/N12a/e2/reopen": labelNotSaved,
	"names/N12a/e1/reopen": labelNotSaved,
	"names/N12b/e2/reopen": labelNotSaved,
	"names/N12b/e1/reopen": labelNotSaved,
	"names/N13/e2/reopen":  labelNotSaved,
	"names/N13/e1/reopen":  labelNotSaved,

	"names/N1/n63b/label":  labelSuffixOverflow,
	"names/N2/n63b/label":  labelSuffixOverflow,
	"names/N3/n63b/label":  labelSuffixOverflow,
	"names/N4/n63b/label":  labelSuffixOverflow,
	"names/N5/n63b/label":  labelSuffixOverflow,
	"names/N6/n63b/label":  labelSuffixOverflow,
	"names/N7/n63b/label":  labelSuffixOverflow,
	"names/N8/n63b/label":  labelSuffixOverflow,
	"names/N9a/n63b/label": labelSuffixOverflow,
	"names/N9b/n63b/label": labelSuffixOverflow,
	"names/N10/n63b/label": labelSuffixOverflow,
	"names/N11/n63b/label": labelSuffixOverflow,

	"names/N1/n63b/reopen":  labelNotSavedOverflow,
	"names/N2/n63b/reopen":  labelNotSavedOverflow,
	"names/N3/n63b/reopen":  labelNotSavedOverflow,
	"names/N4/n63b/reopen":  labelNotSavedOverflow,
	"names/N5/n63b/reopen":  labelNotSavedOverflow,
	"names/N6/n63b/reopen":  labelNotSavedOverflow,
	"names/N7/n63b/reopen":  labelNotSavedOverflow,
	"names/N8/n63b/reopen":  labelNotSavedOverflow,
	"names/N9a/n63b/reopen": labelNotSavedOverflow,
	"names/N9b/n63b/reopen": labelNotSavedOverflow,
	"names/N10/n63b/reopen": labelNotSavedOverflow,
	"names/N11/n63b/reopen": labelNotSavedOverflow,

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

	"names/N7/m1/reopen":   labelNotSaved,
	"names/N8/m1/reopen":   labelNotSaved,
	"names/N9a/m1/reopen":  labelNotSaved,
	"names/N9b/m1/reopen":  labelNotSaved,
	"names/N10/m1/reopen":  labelNotSaved,
	"names/N11/m1/reopen":  labelNotSaved,
	"names/N11b/m1/reopen": labelNotSaved,
	"names/N12a/m1/reopen": labelNotSaved,
	"names/N12b/m1/reopen": labelNotSaved,
	"names/N13/m1/reopen":  labelNotSaved,
}

const (
	labelSuffixOverflow      = "LABEL_SUFFIX_OVERFLOW: headscale appends -N to a 63-byte label, giving a 65-byte one; SaaS cuts the label so the suffix fits in 63 bytes"
	adminNameFollowsHostname = "ADMIN_NAME_FOLLOWS_HOSTNAME: an admin name equal to the hostname's label counts as derived from it, so a hostname change replaces it; SaaS keeps an admin name across hostname changes"
	labelNotSaved            = "LABEL_NOT_SAVED: headscale writes a new node's row with its hostname's label before the NodeStore resolves a collision or an empty label, and saves the result only on a later change; SaaS keeps the label it gave"
	labelNotSavedOverflow    = "LABEL_NOT_SAVED+LABEL_SUFFIX_OVERFLOW: the row keeps the unsuffixed 63-byte label, and the label the NodeStore resolves is 65 bytes; SaaS cuts the label so the suffix fits"
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
