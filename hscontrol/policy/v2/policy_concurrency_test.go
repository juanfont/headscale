package v2

import (
	"fmt"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestPolicyManagerConcurrentReads is the correctness guard for the #3346 fix:
// PolicyManager read methods take a shared RLock and populate their per-node
// caches (filterRulesMap, matchersForNodeMap) concurrently. This test hammers
// those reads from many goroutines while a writer mutates the node set, so the
// race detector catches any unsafe access to the shared caches or policy state.
//
// It uses an autogroup:self policy so reads take the per-node filter slow path
// — the same path that made #3346's reconnect storm expensive — which is where
// the lazy caches are written.
func TestPolicyManagerConcurrentReads(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "user2", Email: "user2@headscale.net"},
		{Model: gorm.Model{ID: 3}, Name: "user3", Email: "user3@headscale.net"},
	}

	policy := `{
		"acls": [
			{
				"action": "accept",
				"src": ["autogroup:member"],
				"dst": ["autogroup:self:*"]
			}
		]
	}`

	const nodeCount = 60

	nodes := make(types.Nodes, 0, nodeCount)
	for i := range nodeCount {
		n := node(
			fmt.Sprintf("node%d", i),
			fmt.Sprintf("100.64.0.%d", i+1),
			fmt.Sprintf("fd7a:115c:a1e0::%d", i+1),
			users[i%len(users)],
		)
		n.ID = types.NodeID(i + 1) //nolint:gosec // safe in test
		nodes = append(nodes, n)
	}

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	const (
		readers        = 16
		iterations     = 60
		mutatorReloads = 30
	)

	var wg sync.WaitGroup

	// Concurrent readers exercise every converted RLock read path, including
	// the two lazily populated per-node caches. Assertions inside the
	// goroutines use assert (not require) so a failure does not call
	// t.FailNow from a non-test goroutine.
	for r := range readers {
		wg.Go(func() {
			for i := range iterations {
				nv := nodes[(r+i)%len(nodes)].View()

				rules, err := pm.FilterForNode(nv)
				assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
				assert.NotNil(t, rules)

				_, err = pm.MatchersForNode(nv)
				assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine

				pm.Filter()
				pm.NodeCapMap(nv.ID())

				// BuildPeerMap is the O(n^2) writer-side read; exercise it
				// under RLock too, but not every iteration.
				if i%8 == 0 {
					assert.NotNil(t, pm.BuildPeerMap(nodes.ViewSlice()))
				}
			}
		})
	}

	// A writer repeatedly re-sets the node set, invalidating and racing the
	// caches the readers are populating.
	wg.Go(func() {
		for range mutatorReloads {
			_, err := pm.SetNodes(nodes.ViewSlice())
			assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
		}
	})

	wg.Wait()
}
