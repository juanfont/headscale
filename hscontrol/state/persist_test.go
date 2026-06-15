package state

import (
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
// NodeStore + persistNodeToDB, which is the same code path the public
// SetApprovedRoutes call exercises.
func TestPersistEmptyTags(t *testing.T) {
	dbPath, s, nodeID := persistTestSetup(t)

	_, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = []string{"tag:test"}
	})
	require.True(t, ok)

	seeded, ok := s.nodeStore.GetNode(nodeID)
	require.True(t, ok)

	_, _, err := s.persistNodeToDB(seeded)
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []string{"tag:test"}, gotAfterSeed.Tags.List(),
		"tags should hold the seeded value")

	cleared, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Tags = nil
	})
	require.True(t, ok)

	_, _, err = s.persistNodeToDB(cleared)
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

	_, _, err := s.persistNodeToDB(seeded)
	require.NoError(t, err)

	gotAfterSeed, err := s.DB().GetNodeByID(nodeID)
	require.NoError(t, err)
	require.Equal(t, []netip.AddrPort{endpoint}, gotAfterSeed.Endpoints.List(),
		"endpoints should hold the seeded value")

	cleared, ok := s.nodeStore.UpdateNode(nodeID, func(n *types.Node) {
		n.Endpoints = nil
	})
	require.True(t, ok)

	_, _, err = s.persistNodeToDB(cleared)
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
	_, err = s.applyAuthNodeUpdate(authNodeUpdateParams{
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
	updated, err := s.applyAuthNodeUpdate(authNodeUpdateParams{
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

// TestReauthChange covers the decision both re-auth paths share: a same-user
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

var errInjectedNodeUpdate = errors.New("injected node update failure")

// TestPreAuthKeyReauthRevertsNodeStoreOnDBFailure ensures a failed database
// write during pre-auth-key re-registration does not leave the NodeStore
// holding a node key that was never persisted: a restart would reload the old
// row and the client's current key would no longer resolve, locking it out.
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
	// after the NodeStore has already been mutated.
	require.NoError(t, s.db.DB.Callback().Update().Before("gorm:update").
		Register("fail_node_update", func(tx *gorm.DB) {
			if tx.Statement.Table == "nodes" {
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
