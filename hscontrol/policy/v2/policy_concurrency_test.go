package v2

import (
	"fmt"
	"slices"
	"sync"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestPolicyManagerConcurrentReads is the correctness guard for the #3346 fix:
// PolicyManager readers capture a generation and populate its per-node
// caches concurrently. This test hammers those reads from many goroutines
// while a writer replaces nodes and policies, so the
// race detector catches any unsafe access to the shared caches or policy state.
//
// It uses an autogroup:self policy so reads take the per-node filter slow path
// — the same path that made #3346's reconnect storm expensive — which is where
// the lazy caches are written.
//
//nolint:testifylint // Concurrent workers must not call FailNow.
func TestPolicyManagerConcurrentReads(t *testing.T) {
	users := types.Users{
		{ID: 1, Name: "user1", Email: "user1@headscale.net"},
		{ID: 2, Name: "user2", Email: "user2@headscale.net"},
		{ID: 3, Name: "user3", Email: "user3@headscale.net"},
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

	tagged := slices.Clone(nodes)
	tagged[0] = nodes[0].Clone()
	tagged[0].Tags = []string{"tag:changed"}
	policies := [][]byte{[]byte(policy), []byte(`{
		"acls":[{"action":"accept","src":["autogroup:member"],
		"dst":["autogroup:self:443"]}]
	}`)}

	const (
		readers        = 16
		iterations     = 60
		mutatorReloads = 30
	)

	var wg sync.WaitGroup

	// Concurrent readers exercise the captured generation read paths, including
	// the two lazily populated per-node caches. Assertions inside the
	// goroutines use assert (not require) so a failure does not call
	// t.FailNow from a non-test goroutine.
	for r := range readers {
		wg.Go(func() {
			for i := range iterations {
				view := pm.ReadView()
				nv := view.generation.nodes.At((r + i) % len(nodes))

				rules, err := view.PacketRulesForNode(nv)
				assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
				assert.NotNil(t, rules)

				again, err := view.PacketRulesForNode(nv)
				assert.NoError(t, err)
				assert.Equal(t, rules, again)

				peerRules, err := view.PeerRulesForNode(nv)
				assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
				peerAgain, err := view.PeerRulesForNode(nv)
				assert.NoError(t, err)
				assert.Equal(t, peerRules, peerAgain)

				view.PacketRules()
				view.NodeCapMap(nv.ID())

				// BuildPeerMap is the O(n^2) writer-side read; exercise the
				// captured generation too, but not every iteration.
				if i%8 == 0 {
					assert.NotNil(t,
						view.generation.buildPeerMap(view.generation.nodes),
					)
				}
			}
		})
	}

	// A writer repeatedly changes nodes and policies, replacing and racing the
	// caches the readers are populating.
	wg.Go(func() {
		for i := range mutatorReloads {
			replacement := tagged
			if i%2 != 0 {
				replacement = nodes
			}

			before := pm.ReadView()
			changed, err := pm.SetNodes(replacement.ViewSlice())
			assert.NoError(t, err) //nolint:testifylint // assert (not require) is correct off the test goroutine
			assert.True(t, changed)

			afterNodes := pm.ReadView()
			assert.NotSame(t, before.generation, afterNodes.generation)

			_, err = pm.SetPolicy(policies[(i+1)%2])
			assert.NoError(t, err)
			assert.NotSame(t, afterNodes.generation, pm.ReadView().generation)
		}
	})

	wg.Wait()
}

// TestViaRoutesForPeerDoesNotWritePolicyGrants guards against
// ViaRoutesForPeer appending ACL-derived grants into the backing array of
// pm.pol.Grants. Readers hold only the shared RLock, so any spare capacity
// in that slice becomes a write/write race between concurrent callers.
func TestViaRoutesForPeerDoesNotWritePolicyGrants(t *testing.T) {
	users := types.Users{{Name: "user1", Email: "user1@headscale.net"}}

	a := node("a", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
	a.ID = 1
	b := node("b", "100.64.0.2", "fd7a:115c:a1e0::2", users[0])
	b.ID = 2
	nodes := types.Nodes{a, b}

	policy := `{
		"grants": [
			{"src": ["*"], "dst": ["*"], "ip": ["tcp:22"]}
		],
		"acls": [
			{"action": "accept", "src": ["*"], "dst": ["*:*"]}
		]
	}`

	pm, err := NewPolicyManager([]byte(policy), users, nodes.ViewSlice())
	require.NoError(t, err)

	// Guarantee spare capacity instead of relying on the JSON decoder's
	// growth policy.
	pm.pol.Grants = slices.Grow(pm.pol.Grants, 4)
	spare := pm.pol.Grants[len(pm.pol.Grants):cap(pm.pol.Grants)]

	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 50 {
				pm.ViaRoutesForPeer(a.View(), b.View())
			}
		})
	}

	wg.Wait()

	for i, g := range spare {
		assert.Zero(t, g, "spare slot %d of pm.pol.Grants was written", i)
	}
}
