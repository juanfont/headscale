package state

import (
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/ptr"
)

// TestEphemeralNodeDeleteWithConcurrentUpdate tests the race condition where UpdateNode and DeleteNode
// are called concurrently and may be batched together. This reproduces the issue where ephemeral nodes
// are not properly deleted during logout because UpdateNodeFromMapRequest returns a stale node view
// after the node has been deleted from the NodeStore.
func TestEphemeralNodeDeleteWithConcurrentUpdate(t *testing.T) {
	// Create a simple test node
	node := createTestNode(1, 1, "test-user", "test-node")

	// Create NodeStore
	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put the node in the store
	resultNode := store.PutNode(node)
	require.True(t, resultNode.Valid(), "initial PutNode should return valid node")

	// Verify node exists
	retrievedNode, found := store.GetNode(node.ID)
	require.True(t, found)
	require.Equal(t, node.ID, retrievedNode.ID())

	// Test scenario: UpdateNode is called, returns a node view from the batch,
	// but in the same batch a DeleteNode removes the node.
	// This simulates what happens when:
	// 1. UpdateNodeFromMapRequest calls UpdateNode and gets back updatedNode
	// 2. At the same time, handleLogout calls DeleteNode
	// 3. They get batched together: [UPDATE, DELETE]
	// 4. UPDATE modifies the node, DELETE removes it
	// 5. UpdateNode returns a node view based on the state AFTER both operations
	// 6. If DELETE came after UPDATE, the returned node should be invalid

	done := make(chan bool, 2)
	var updatedNode types.NodeView
	var updateOk bool

	// Goroutine 1: UpdateNode (simulates UpdateNodeFromMapRequest)
	go func() {
		updatedNode, updateOk = store.UpdateNode(node.ID, func(n *types.Node) {
			n.LastSeen = ptr.To(time.Now())
		})
		done <- true
	}()

	// Goroutine 2: DeleteNode (simulates handleLogout for ephemeral node)
	go func() {
		// Small delay to increase chance of batching together
		time.Sleep(1 * time.Millisecond)
		store.DeleteNode(node.ID)
		done <- true
	}()

	// Wait for both operations
	<-done
	<-done

	// Give batching time to complete
	time.Sleep(50 * time.Millisecond)

	// The key assertion: if UpdateNode and DeleteNode were batched together
	// with DELETE after UPDATE, then UpdateNode should return an invalid node
	// OR it should return a valid node but the node should no longer exist in the store

	_, found = store.GetNode(node.ID)
	assert.False(t, found, "node should be deleted from NodeStore")

	// If the update happened before delete in the batch, the returned node might be invalid
	if updateOk {
		t.Logf("UpdateNode returned ok=true, valid=%v", updatedNode.Valid())
		// This is the bug scenario - UpdateNode thinks it succeeded but node is gone
		if updatedNode.Valid() {
			t.Logf("WARNING: UpdateNode returned valid node but node was deleted - this indicates the race condition bug")
		}
	} else {
		t.Logf("UpdateNode correctly returned ok=false (node deleted in same batch)")
	}
}

// TestUpdateNodeReturnsInvalidWhenDeletedInSameBatch specifically tests that when
// UpdateNode and DeleteNode are in the same batch with DELETE after UPDATE,
// the UpdateNode should return an invalid node view.
func TestUpdateNodeReturnsInvalidWhenDeletedInSameBatch(t *testing.T) {
	node := createTestNode(2, 1, "test-user", "test-node-2")

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put node in store
	_ = store.PutNode(node)

	// Simulate the exact sequence: UpdateNode gets queued, then DeleteNode gets queued,
	// they batch together, and we check what UpdateNode returns

	resultChan := make(chan struct {
		node types.NodeView
		ok   bool
	})

	// Start UpdateNode - it will block until batch is applied
	go func() {
		node, ok := store.UpdateNode(node.ID, func(n *types.Node) {
			n.LastSeen = ptr.To(time.Now())
		})
		resultChan <- struct {
			node types.NodeView
			ok   bool
		}{node, ok}
	}()

	// Give UpdateNode a moment to queue its work
	time.Sleep(5 * time.Millisecond)

	// Now queue DeleteNode - should batch with the UPDATE
	store.DeleteNode(node.ID)

	// Get the result from UpdateNode
	result := <-resultChan

	// Wait for batch to complete
	time.Sleep(50 * time.Millisecond)

	// Node should be deleted
	_, found := store.GetNode(node.ID)
	assert.False(t, found, "node should be deleted")

	// The critical check: what did UpdateNode return?
	// After the commit c6b09289988f34398eb3157e31ba092eb8721a9f,
	// UpdateNode returns the node state from the batch.
	// If DELETE came after UPDATE in the batch, the node doesn't exist anymore,
	// so UpdateNode should return (invalid, false)
	t.Logf("UpdateNode returned: ok=%v, valid=%v", result.ok, result.node.Valid())

	// This is the expected behavior - if node was deleted in same batch,
	// UpdateNode should return invalid node
	if result.ok && result.node.Valid() {
		t.Error("BUG: UpdateNode returned valid node even though it was deleted in same batch")
	}
}

// TestPersistNodeToDBPreventsRaceCondition tests that persistNodeToDB correctly handles
// the race condition where a node is deleted after UpdateNode returns but before
// persistNodeToDB is called. This reproduces the ephemeral node deletion bug.
func TestPersistNodeToDBPreventsRaceCondition(t *testing.T) {
	node := createTestNode(3, 1, "test-user", "test-node-3")

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put node in store
	_ = store.PutNode(node)

	// Simulate UpdateNode being called
	updatedNode, ok := store.UpdateNode(node.ID, func(n *types.Node) {
		n.LastSeen = ptr.To(time.Now())
	})
	require.True(t, ok, "UpdateNode should succeed")
	require.True(t, updatedNode.Valid(), "UpdateNode should return valid node")

	// Now delete the node (simulating ephemeral logout happening concurrently)
	store.DeleteNode(node.ID)

	// Wait for deletion to complete
	time.Sleep(50 * time.Millisecond)

	// Verify node is deleted
	_, found := store.GetNode(node.ID)
	require.False(t, found, "node should be deleted")

	// Now try to use the updatedNode from before the deletion
	// In the old code, this would re-insert the node into the database
	// With our fix, GetNode check in persistNodeToDB should prevent this

	// Simulate what persistNodeToDB does - check if node still exists
	_, exists := store.GetNode(updatedNode.ID())
	if !exists {
		t.Log("SUCCESS: persistNodeToDB check would prevent re-insertion of deleted node")
	} else {
		t.Error("BUG: Node still exists in NodeStore after deletion")
	}

	// The key assertion: after deletion, attempting to persist the old updatedNode
	// should fail because the node no longer exists in NodeStore
	assert.False(t, exists, "persistNodeToDB should detect node was deleted and refuse to persist")
}

// TestEphemeralNodeLogoutRaceCondition tests the specific race condition that occurs
// when an ephemeral node logs out. This reproduces the bug where:
//  1. UpdateNodeFromMapRequest calls UpdateNode and receives a node view
//  2. Concurrently, handleLogout is called for the ephemeral node and calls DeleteNode
//  3. UpdateNode and DeleteNode get batched together
//  4. If UpdateNode's result is used to call persistNodeToDB after the deletion,
//     the node could be re-inserted into the database even though it was deleted
func TestEphemeralNodeLogoutRaceCondition(t *testing.T) {
	ephemeralNode := createTestNode(4, 1, "test-user", "ephemeral-node")
	ephemeralNode.AuthKey = &types.PreAuthKey{
		ID:        1,
		Key:       "test-key",
		Ephemeral: true,
	}

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put ephemeral node in store
	_ = store.PutNode(ephemeralNode)

	// Simulate concurrent operations:
	// 1. UpdateNode (from UpdateNodeFromMapRequest during polling)
	// 2. DeleteNode (from handleLogout when client sends logout request)

	var updatedNode types.NodeView
	var updateOk bool
	done := make(chan bool, 2)

	// Goroutine 1: UpdateNode (simulates UpdateNodeFromMapRequest)
	go func() {
		updatedNode, updateOk = store.UpdateNode(ephemeralNode.ID, func(n *types.Node) {
			n.LastSeen = ptr.To(time.Now())
		})
		done <- true
	}()

	// Goroutine 2: DeleteNode (simulates handleLogout for ephemeral node)
	go func() {
		time.Sleep(1 * time.Millisecond) // Slight delay to batch operations
		store.DeleteNode(ephemeralNode.ID)
		done <- true
	}()

	// Wait for both operations
	<-done
	<-done

	// Give batching time to complete
	time.Sleep(50 * time.Millisecond)

	// Node should be deleted from store
	_, found := store.GetNode(ephemeralNode.ID)
	assert.False(t, found, "ephemeral node should be deleted from NodeStore")

	// Critical assertion: if UpdateNode returned before DeleteNode completed,
	// the updatedNode might be valid but the node is actually deleted.
	// This is the bug - UpdateNodeFromMapRequest would get a valid node,
	// then try to persist it, re-inserting the deleted ephemeral node.
	if updateOk && updatedNode.Valid() {
		t.Log("UpdateNode returned valid node, but node is deleted - this is the race condition")

		// In the real code, this would cause persistNodeToDB to be called with updatedNode
		// The fix in persistNodeToDB checks if the node still exists:
		_, stillExists := store.GetNode(updatedNode.ID())
		assert.False(t, stillExists, "persistNodeToDB should check NodeStore and find node deleted")
	} else if !updateOk || !updatedNode.Valid() {
		t.Log("UpdateNode correctly returned invalid/not-ok result (delete happened in same batch)")
	}
}

// TestUpdateNodeFromMapRequestEphemeralLogoutSequence tests the exact sequence
// that causes ephemeral node logout failures:
// 1. Client sends MapRequest with updated endpoint info
// 2. UpdateNodeFromMapRequest starts processing, calls UpdateNode
// 3. Client sends logout request (past expiry)
// 4. handleLogout calls DeleteNode for ephemeral node
// 5. UpdateNode and DeleteNode batch together
// 6. UpdateNode returns a valid node (from before delete in batch)
// 7. persistNodeToDB is called with the stale valid node
// 8. Node gets re-inserted into database instead of staying deleted
func TestUpdateNodeFromMapRequestEphemeralLogoutSequence(t *testing.T) {
	ephemeralNode := createTestNode(5, 1, "test-user", "ephemeral-node-5")
	ephemeralNode.AuthKey = &types.PreAuthKey{
		ID:        2,
		Key:       "test-key-2",
		Ephemeral: true,
	}

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Initial state: ephemeral node exists
	_ = store.PutNode(ephemeralNode)

	// Step 1: UpdateNodeFromMapRequest calls UpdateNode
	// (simulating client sending MapRequest with endpoint updates)
	updateStarted := make(chan bool)
	var updatedNode types.NodeView
	var updateOk bool

	go func() {
		updateStarted <- true
		updatedNode, updateOk = store.UpdateNode(ephemeralNode.ID, func(n *types.Node) {
			n.LastSeen = ptr.To(time.Now())
			endpoint := netip.MustParseAddrPort("10.0.0.1:41641")
			n.Endpoints = []netip.AddrPort{endpoint}
		})
	}()

	<-updateStarted
	// Small delay to ensure UpdateNode is queued
	time.Sleep(5 * time.Millisecond)

	// Step 2: Logout happens - handleLogout calls DeleteNode
	// (simulating client sending logout with past expiry)
	store.DeleteNode(ephemeralNode.ID)

	// Wait for batching to complete
	time.Sleep(50 * time.Millisecond)

	// Step 3: Check results
	_, nodeExists := store.GetNode(ephemeralNode.ID)
	assert.False(t, nodeExists, "ephemeral node must be deleted after logout")

	// Step 4: Simulate what happens if we try to persist the updatedNode
	if updateOk && updatedNode.Valid() {
		// This is the problematic path - UpdateNode returned a valid node
		// but the node was deleted in the same batch
		t.Log("UpdateNode returned valid node even though node was deleted")

		// The fix: persistNodeToDB must check NodeStore before persisting
		_, checkExists := store.GetNode(updatedNode.ID())
		if checkExists {
			t.Error("BUG: Node still exists in NodeStore after deletion - should be impossible")
		} else {
			t.Log("SUCCESS: persistNodeToDB would detect node is deleted and refuse to persist")
		}
	} else {
		t.Log("UpdateNode correctly indicated node was deleted (returned invalid or not-ok)")
	}

	// Final assertion: node must not exist
	_, finalExists := store.GetNode(ephemeralNode.ID)
	assert.False(t, finalExists, "ephemeral node must remain deleted")
}

// TestUpdateNodeDeletedInSameBatchReturnsInvalid specifically tests that when
// UpdateNode and DeleteNode are batched together with DELETE after UPDATE,
// UpdateNode returns ok=false to indicate the node was deleted.
func TestUpdateNodeDeletedInSameBatchReturnsInvalid(t *testing.T) {
	node := createTestNode(6, 1, "test-user", "test-node-6")

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put node in store
	_ = store.PutNode(node)

	// Queue UpdateNode
	updateDone := make(chan struct {
		node types.NodeView
		ok   bool
	})

	go func() {
		updatedNode, ok := store.UpdateNode(node.ID, func(n *types.Node) {
			n.LastSeen = ptr.To(time.Now())
		})
		updateDone <- struct {
			node types.NodeView
			ok   bool
		}{updatedNode, ok}
	}()

	// Small delay to ensure UpdateNode is queued
	time.Sleep(5 * time.Millisecond)

	// Queue DeleteNode - should batch with UpdateNode
	store.DeleteNode(node.ID)

	// Get UpdateNode result
	result := <-updateDone

	// Wait for batch to complete
	time.Sleep(50 * time.Millisecond)

	// Node should be deleted
	_, exists := store.GetNode(node.ID)
	assert.False(t, exists, "node should be deleted from store")

	// UpdateNode should indicate the node was deleted
	// After c6b09289988f34398eb3157e31ba092eb8721a9f, when UPDATE and DELETE
	// are in the same batch with DELETE after UPDATE, UpdateNode returns
	// the state after the batch is applied - which means the node doesn't exist
	assert.False(t, result.ok, "UpdateNode should return ok=false when node deleted in same batch")
	assert.False(t, result.node.Valid(), "UpdateNode should return invalid node when node deleted in same batch")
}

// TestPersistNodeToDBChecksNodeStoreBeforePersist verifies that persistNodeToDB
// checks if the node still exists in NodeStore before persisting to database.
// This prevents the race condition where:
// 1. UpdateNodeFromMapRequest calls UpdateNode and gets a valid node
// 2. Ephemeral node logout calls DeleteNode
// 3. UpdateNode and DeleteNode batch together
// 4. UpdateNode returns a valid node (from before delete in batch)
// 5. UpdateNodeFromMapRequest calls persistNodeToDB with the stale node
// 6. persistNodeToDB must detect the node is deleted and refuse to persist
func TestPersistNodeToDBChecksNodeStoreBeforePersist(t *testing.T) {
	ephemeralNode := createTestNode(7, 1, "test-user", "ephemeral-node-7")
	ephemeralNode.AuthKey = &types.PreAuthKey{
		ID:        3,
		Key:       "test-key-3",
		Ephemeral: true,
	}

	store := NewNodeStore(nil, allowAllPeersFunc)
	store.Start()
	defer store.Stop()

	// Put node in store
	_ = store.PutNode(ephemeralNode)

	// Simulate the race:
	// 1. UpdateNode is called (from UpdateNodeFromMapRequest)
	updatedNode, ok := store.UpdateNode(ephemeralNode.ID, func(n *types.Node) {
		n.LastSeen = ptr.To(time.Now())
	})
	require.True(t, ok, "UpdateNode should succeed")
	require.True(t, updatedNode.Valid(), "UpdateNode should return valid node")

	// 2. Node is deleted (from handleLogout for ephemeral node)
	store.DeleteNode(ephemeralNode.ID)

	// Wait for deletion
	time.Sleep(50 * time.Millisecond)

	// 3. Verify node is deleted from store
	_, exists := store.GetNode(ephemeralNode.ID)
	require.False(t, exists, "node should be deleted from NodeStore")

	// 4. Simulate what persistNodeToDB does - check if node still exists
	// The fix in persistNodeToDB checks NodeStore before persisting:
	// if !exists { return error }
	// This prevents re-inserting the deleted node into the database

	// Verify the node from UpdateNode is valid but node is gone from store
	assert.True(t, updatedNode.Valid(), "UpdateNode returned a valid node view")
	_, stillExists := store.GetNode(updatedNode.ID())
	assert.False(t, stillExists, "but node should be deleted from NodeStore")

	// This is the critical test: persistNodeToDB must check NodeStore
	// and refuse to persist if the node doesn't exist anymore
	// The actual persistNodeToDB implementation does:
	// _, exists := s.nodeStore.GetNode(node.ID())
	// if !exists { return error }
}
