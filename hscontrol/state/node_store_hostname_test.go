package state

import (
	"fmt"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestPutNodeGivenNameCollisionBumps is the reproduction for #3188.
// Before the hostname-cleanroom rewrite, two nodes could be written
// with the same GivenName, producing duplicates. After the rewrite,
// the NodeStore writer goroutine detects GivenName collisions inside
// applyBatch and appends -1, -2, … to make the label unique.
func TestPutNodeGivenNameCollisionBumps(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	n1 := createTestNode(1, 1, "alice", "laptop")
	n2 := createTestNode(2, 1, "alice", "laptop")
	n3 := createTestNode(3, 1, "alice", "laptop")

	got1 := store.PutNode(n1)
	got2 := store.PutNode(n2)
	got3 := store.PutNode(n3)

	require.Equal(t, "laptop", got1.GivenName(), "first registration keeps base label")
	require.Equal(t, "laptop-1", got2.GivenName(), "second registration bumps to -1")
	require.Equal(t, "laptop-2", got3.GivenName(), "third registration bumps to -2")
}

// TestPutNodeEmptyGivenNameFallsBackToNode covers the SaaS rule that
// an empty sanitised label becomes the literal "node". Subsequent
// empty-label registrations bump as usual.
func TestPutNodeEmptyGivenNameFallsBackToNode(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	n1 := createTestNode(1, 1, "alice", "")
	n1.GivenName = ""
	n2 := createTestNode(2, 1, "alice", "")
	n2.GivenName = ""

	got1 := store.PutNode(n1)
	got2 := store.PutNode(n2)

	require.Equal(t, "node", got1.GivenName())
	require.Equal(t, "node-1", got2.GivenName())
}

// TestPutNodeIdempotentKeepsLabel asserts that re-putting the same
// node (same ID, same GivenName) does not bump its own label.
func TestPutNodeIdempotentKeepsLabel(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	n := createTestNode(1, 1, "alice", "laptop")
	first := store.PutNode(n)
	require.Equal(t, "laptop", first.GivenName())

	second := store.PutNode(n)
	require.Equal(t, "laptop", second.GivenName(), "re-put of same node must not bump its own label")
}

// TestUpdateNodeBumpsOnCollision asserts that UpdateNode also runs
// the collision-bump branch when a callback rewrites GivenName to a
// label held by another node.
func TestUpdateNodeBumpsOnCollision(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	store.PutNode(createTestNode(1, 1, "alice", "laptop"))
	store.PutNode(createTestNode(2, 1, "alice", "phone"))

	view, ok := store.UpdateNode(2, func(n *types.Node) {
		n.GivenName = "laptop"
	})
	require.True(t, ok)
	require.Equal(t, "laptop-1", view.GivenName(), "UpdateNode must bump on collision")
}

// TestConcurrentPutNodeSameGivenNameAllUnique is the race regression
// for the plan's safety argument: N goroutines concurrently PutNode
// with the same GivenName and distinct IDs. All N stored labels must
// be unique (no two nodes holding the same GivenName).
func TestConcurrentPutNodeSameGivenNameAllUnique(t *testing.T) {
	const N = 20

	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	var wg sync.WaitGroup

	results := make(chan string, N)
	for i := range N {
		wg.Add(1)

		go func(id int) {
			defer wg.Done()

			n := createTestNode(types.NodeID(id+1), 1, "alice", "laptop") //nolint:gosec // test ids

			view := store.PutNode(n)
			results <- view.GivenName()
		}(i)
	}

	wg.Wait()
	close(results)

	seen := make(map[string]struct{}, N)
	for label := range results {
		if _, dup := seen[label]; dup {
			t.Fatalf("duplicate label %q across concurrent PutNode", label)
		}

		seen[label] = struct{}{}
	}

	require.Len(t, seen, N, "all concurrent PutNodes must land with unique labels")

	for i := range N {
		want := "laptop"
		if i > 0 {
			want = fmt.Sprintf("laptop-%d", i)
		}

		if _, ok := seen[want]; !ok {
			t.Errorf("expected label %q in result set, got %v", want, seen)
		}
	}
}

// TestSetGivenNameSuccess renames a node to a free label and asserts
// the NodeView reflects the new label.
func TestSetGivenNameSuccess(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	store.PutNode(createTestNode(1, 1, "alice", "laptop"))

	view, err := store.SetGivenName(1, "workhorse")
	require.NoError(t, err)
	require.Equal(t, "workhorse", view.GivenName())
}

// TestSetGivenNameRejectsTaken refuses to rename a node to a label
// held by a different node, leaving both labels unchanged.
func TestSetGivenNameRejectsTaken(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	store.PutNode(createTestNode(1, 1, "alice", "laptop"))
	store.PutNode(createTestNode(2, 1, "alice", "phone"))

	_, err := store.SetGivenName(2, "laptop")
	require.ErrorIs(t, err, ErrGivenNameTaken)

	view, _ := store.GetNode(2)
	require.Equal(t, "phone", view.GivenName(), "rejected rename must not mutate state")
}

// TestSetGivenNameRejectsInvalid returns ErrGivenNameInvalid for
// labels that are not valid DNS labels.
func TestSetGivenNameRejectsInvalid(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	store.PutNode(createTestNode(1, 1, "alice", "laptop"))

	for _, bad := range []string{"Joe's Mac", "has space", "-leading", "trailing-", "", "dot.in.label"} {
		_, err := store.SetGivenName(1, bad)
		require.ErrorIsf(t, err, ErrGivenNameInvalid, "label %q must reject as invalid", bad)
	}
}

// TestSetGivenNameRejectsMissingNode returns ErrNodeNotFound.
func TestSetGivenNameRejectsMissingNode(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	_, err := store.SetGivenName(999, "something")
	require.ErrorIs(t, err, ErrNodeNotFound, "got %v", err)
}

// TestSetGivenNameIdempotent renaming a node to its own current label
// succeeds (not a collision against itself).
func TestSetGivenNameIdempotent(t *testing.T) {
	store := NewNodeStore(nil, allowAllPeersFunc, TestBatchSize, TestBatchTimeout)

	store.Start()
	defer store.Stop()

	store.PutNode(createTestNode(1, 1, "alice", "laptop"))

	view, err := store.SetGivenName(1, "laptop")
	require.NoError(t, err)
	require.Equal(t, "laptop", view.GivenName())
}
