package servertest_test

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
	"tailscale.com/tailcfg"
	"tailscale.com/types/netmap"
)

const (
	policyAllowAll    = "allow-all"
	policyDefault     = "default"
	policyRestrictive = "restrictive"

	defaultUserName = "default"
)

// meshState is the model that tracks expected state alongside the
// real harness. It records which client indices are connected vs
// disconnected so invariant checks can filter appropriately.
type meshState struct {
	harness *servertest.TestHarness

	// tb is the real *testing.T used for harness operations that
	// require testing.TB (TempDir, Cleanup, etc). Infrastructure
	// failures (server creation, client registration) abort the
	// test immediately.
	tb testing.TB

	// connected tracks whether each client index is currently
	// connected (true) or disconnected (false).
	connected []bool

	// totalAdded is the total number of clients ever added
	// (including the initial set). Equals len(harness.Clients()).
	totalAdded int

	// currentPolicy tracks which policy is active for logging.
	currentPolicy string
}

// connectedClients returns the TestClient pointers for all clients
// that the model believes are connected.
func (m *meshState) connectedClients() []*servertest.TestClient {
	var out []*servertest.TestClient

	for i, c := range m.connected {
		if c {
			out = append(out, m.harness.Client(i))
		}
	}

	return out
}

// connectedIndices returns the indices of connected clients.
func (m *meshState) connectedIndices() []int {
	var out []int

	for i, c := range m.connected {
		if c {
			out = append(out, i)
		}
	}

	return out
}

// disconnectedIndices returns the indices of disconnected clients.
func (m *meshState) disconnectedIndices() []int {
	var out []int

	for i, c := range m.connected {
		if !c {
			out = append(out, i)
		}
	}

	return out
}

// connectedCount returns the number of currently connected clients.
func (m *meshState) connectedCount() int {
	n := 0

	for _, c := range m.connected {
		if c {
			n++
		}
	}

	return n
}

// policyEntry pairs a human-readable label with a HuJSON policy doc.
type policyEntry struct {
	label string
	doc   []byte
}

// policyPool is the set of ACL policies that can be randomly applied.
// All policies grant full connectivity (with different rule shapes)
// so that peer visibility invariants hold regardless of which policy
// is active.
var policyPool = []policyEntry{
	{
		label: policyAllowAll,
		doc: []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`),
	},
	{
		label: "allow-all-tcp",
		doc: []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"], "proto": "tcp"}
			]
		}`),
	},
	{
		label: "allow-all-with-autogroup",
		doc: []byte(`{
			"acls": [
				{"action": "accept", "src": ["autogroup:member"], "dst": ["autogroup:member:*"]}
			]
		}`),
	},
}

// meshConvergenceTimeout is the maximum time to wait for the mesh
// to converge after an operation. This must be generous because the
// batcher coalesces changes with a 50ms delay, and propagation
// through poll -> mapper -> controlclient adds latency.
const meshConvergenceTimeout = 30 * time.Second

// checkMeshInvariants verifies all mesh invariants against the
// currently-connected clients. It uses rt.Fatalf for failures so
// that rapid can shrink the failing operation sequence.
func checkMeshInvariants(rt *rapid.T, m *meshState, opDesc string) {
	connected := m.connectedClients()
	if len(connected) == 0 {
		return // nothing to check
	}

	// Invariant 1: All connected clients have a non-nil netmap with
	// non-empty self-addresses.
	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil {
			rt.Fatalf("%s: invariant violation: client %s has nil netmap",
				opDesc, c.Name)

			return // unreachable, but silences SA5011
		}

		if !nm.SelfNode.Valid() {
			rt.Fatalf("%s: invariant violation: client %s has invalid SelfNode",
				opDesc, c.Name)

			return
		}

		if nm.SelfNode.Addresses().Len() == 0 {
			rt.Fatalf("%s: invariant violation: client %s self node has no addresses",
				opDesc, c.Name)
		}
	}

	// Invariant 2: Consistent peer counts among connected clients.
	// All connected clients should see at least (connectedCount - 1)
	// peers. Non-ephemeral disconnected nodes may still appear in
	// peer lists, so we check >= rather than ==.
	expectedMinPeers := len(connected) - 1

	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil {
			continue
		}

		if len(nm.Peers) < expectedMinPeers {
			rt.Fatalf("%s: invariant violation: client %s has %d peers, "+
				"want >= %d (peers: %v)",
				opDesc, c.Name, len(nm.Peers), expectedMinPeers,
				c.PeerNames())
		}
	}

	// Invariant 3: Peer visibility is symmetric among connected
	// clients. If connected client A sees connected client B, then
	// B must also see A.
	for _, a := range connected {
		for _, b := range connected {
			if a == b {
				continue
			}

			_, aSeesB := a.PeerByName(b.Name)
			_, bSeesA := b.PeerByName(a.Name)

			if aSeesB != bSeesA {
				rt.Fatalf("%s: invariant violation: asymmetric visibility: "+
					"%s sees %s = %v, but %s sees %s = %v",
					opDesc, a.Name, b.Name, aSeesB,
					b.Name, a.Name, bSeesA)
			}
		}
	}

	// Invariant 4: DERP map is present on all connected clients.
	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil {
			continue
		}

		if nm.DERPMap == nil {
			rt.Fatalf("%s: invariant violation: client %s has nil DERPMap",
				opDesc, c.Name)
		}

		if len(nm.DERPMap.Regions) == 0 {
			rt.Fatalf("%s: invariant violation: client %s has empty DERPMap regions",
				opDesc, c.Name)
		}
	}

	// Invariant 5: No duplicate node IDs across clients.
	seenIDs := make(map[tailcfg.NodeID]string)

	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		id := nm.SelfNode.ID()
		if prev, exists := seenIDs[id]; exists {
			rt.Fatalf("%s: invariant violation: duplicate node ID %d: "+
				"clients %s and %s", opDesc, id, prev, c.Name)
		}

		seenIDs[id] = c.Name
	}

	// Invariant 6: IP addresses are unique across all clients.
	seenAddrs := make(map[netip.Prefix]string)

	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		for i := range nm.SelfNode.Addresses().Len() {
			addr := nm.SelfNode.Addresses().At(i)
			if prev, exists := seenAddrs[addr]; exists {
				rt.Fatalf("%s: invariant violation: duplicate IP %s: "+
					"clients %s and %s", opDesc, addr, prev, c.Name)
			}

			seenAddrs[addr] = c.Name
		}
	}
}

// awaitMeshConvergence polls until all connected clients see at
// least the expected number of peers, or until timeout expires.
// Returns false if convergence did not happen in time.
//
//nolint:unparam // timeout parameter kept for flexibility in future callers
func awaitMeshConvergence(m *meshState, timeout time.Duration) bool {
	connected := m.connectedClients()
	if len(connected) <= 1 {
		// 0 or 1 connected clients: just ensure the single client
		// has a netmap if present.
		if len(connected) == 1 {
			deadline := time.After(timeout)

			for {
				if nm := connected[0].Netmap(); nm != nil {
					return true
				}

				select {
				case <-deadline:
					return false
				case <-time.After(100 * time.Millisecond):
				}
			}
		}

		return true
	}

	expectedPeers := len(connected) - 1
	deadline := time.After(timeout)

	for {
		allGood := true

		for _, c := range connected {
			nm := c.Netmap()
			if nm == nil || len(nm.Peers) < expectedPeers {
				allGood = false

				break
			}
		}

		if allGood {
			return true
		}

		select {
		case <-deadline:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestRapidMeshOperations is a stateful property-based test that
// generates random sequences of mesh operations (add client,
// disconnect, reconnect, change policy) against a real in-process
// Headscale server, then checks invariants after each operation.
//
// Architecture: the outer *testing.T is captured for harness
// operations (NewHarness, AddClient, Disconnect, etc.) which
// require testing.TB for TempDir/Cleanup. The inner *rapid.T is
// used for random data generation and property assertions so that
// rapid can shrink failing sequences.
//
// This tests the FULL STACK: HTTP -> Noise -> poll -> batcher ->
// mapper -> controlclient, with random operation sequences that
// would be impossible to explore with handwritten tests.
func TestRapidMeshOperations(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		// Universe: create a server + 1 default user + 3-5 initial clients.
		initialCount := rapid.IntRange(3, 5).Draw(rt, "initialClients")

		h := servertest.NewHarness(t, initialCount,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(meshConvergenceTimeout),
		)

		state := &meshState{
			harness:       h,
			tb:            t,
			connected:     make([]bool, initialCount),
			totalAdded:    initialCount,
			currentPolicy: "default (no policy)",
		}

		// Mark all initial clients as connected.
		for i := range initialCount {
			state.connected[i] = true
		}

		// The harness already waited for mesh convergence, so
		// check invariants on the initial state.
		checkMeshInvariants(rt, state, "initial mesh formation")

		// Stateful property test: generate random operations.
		rt.Repeat(map[string]func(*rapid.T){
			// AddClient: add a new client to the mesh.
			// Capped at 10 total clients to keep test runtime
			// reasonable.
			"AddClient": func(rt *rapid.T) {
				if state.totalAdded >= 10 {
					rt.Skip("max clients reached")
				}

				_ = state.harness.AddClient(t)
				state.connected = append(state.connected, true)
				state.totalAdded++

				opDesc := fmt.Sprintf("AddClient(total=%d)", state.totalAdded)

				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("%s: mesh did not converge within %v "+
						"(connected=%d)",
						opDesc, meshConvergenceTimeout,
						state.connectedCount())
				}

				checkMeshInvariants(rt, state, opDesc)
			},

			// DisconnectClient: disconnect a random connected client.
			"DisconnectClient": func(rt *rapid.T) {
				indices := state.connectedIndices()
				if len(indices) <= 1 {
					rt.Skip("too few connected clients to disconnect")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "disconnectIdx")
				client := state.harness.Client(idx)
				client.Disconnect(t)

				state.connected[idx] = false

				opDesc := fmt.Sprintf("DisconnectClient(%s, idx=%d)",
					client.Name, idx)

				// After disconnection, wait for remaining connected
				// clients to converge.
				if remaining := state.connectedCount(); remaining > 1 {
					if !awaitMeshConvergence(state, meshConvergenceTimeout) {
						rt.Fatalf("%s: mesh did not converge within %v "+
							"(connected=%d)",
							opDesc, meshConvergenceTimeout, remaining)
					}
				}

				checkMeshInvariants(rt, state, opDesc)
			},

			// ReconnectClient: reconnect a previously disconnected
			// client.
			"ReconnectClient": func(rt *rapid.T) {
				indices := state.disconnectedIndices()
				if len(indices) == 0 {
					rt.Skip("no disconnected clients to reconnect")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "reconnectIdx")
				client := state.harness.Client(idx)
				client.Reconnect(t)

				state.connected[idx] = true

				opDesc := fmt.Sprintf("ReconnectClient(%s, idx=%d)",
					client.Name, idx)

				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("%s: mesh did not converge within %v "+
						"(connected=%d)",
						opDesc, meshConvergenceTimeout,
						state.connectedCount())
				}

				checkMeshInvariants(rt, state, opDesc)
			},

			// ChangePolicy: apply a random ACL policy.
			"ChangePolicy": func(rt *rapid.T) {
				pol := rapid.SampledFrom(policyPool).Draw(rt, "policy")

				state.harness.ChangePolicy(t, pol.doc)
				state.currentPolicy = pol.label

				opDesc := fmt.Sprintf("ChangePolicy(%s)", pol.label)

				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("%s: mesh did not converge within %v "+
						"(connected=%d)",
						opDesc, meshConvergenceTimeout,
						state.connectedCount())
				}

				checkMeshInvariants(rt, state, opDesc)
			},

			// WaitAndCheck: wait for convergence and verify
			// invariants. This is a no-op operation that gives the
			// system time to settle.
			"WaitAndCheck": func(rt *rapid.T) {
				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("WaitAndCheck: mesh did not converge "+
						"within %v (connected=%d, total=%d, policy=%s)",
						meshConvergenceTimeout,
						state.connectedCount(),
						state.totalAdded,
						state.currentPolicy)
				}

				checkMeshInvariants(rt, state, "WaitAndCheck")
			},
		})
	})
}

// TestRapidMeshChurn is a focused variant that generates longer
// sequences of disconnect/reconnect operations to stress-test the
// session replacement and grace period logic.
func TestRapidMeshChurn(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const initialCount = 4

		h := servertest.NewHarness(t, initialCount,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(meshConvergenceTimeout),
		)

		state := &meshState{
			harness:       h,
			tb:            t,
			connected:     []bool{true, true, true, true},
			totalAdded:    initialCount,
			currentPolicy: policyDefault,
		}

		checkMeshInvariants(rt, state, "initial churn mesh")

		rt.Repeat(map[string]func(*rapid.T){
			"Disconnect": func(rt *rapid.T) {
				indices := state.connectedIndices()
				if len(indices) <= 1 {
					rt.Skip("need at least 1 connected")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "disconnectIdx")
				state.harness.Client(idx).Disconnect(t)

				state.connected[idx] = false
			},

			"Reconnect": func(rt *rapid.T) {
				indices := state.disconnectedIndices()
				if len(indices) == 0 {
					rt.Skip("no disconnected clients")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "reconnectIdx")
				state.harness.Client(idx).Reconnect(t)

				state.connected[idx] = true
			},

			"ConvergeAndCheck": func(rt *rapid.T) {
				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("churn: mesh did not converge "+
						"(connected=%d)",
						state.connectedCount())
				}

				checkMeshInvariants(rt, state, "churn:ConvergeAndCheck")
			},
		})

		// Final convergence check after all operations.
		if !awaitMeshConvergence(state, meshConvergenceTimeout) {
			rt.Fatalf("churn: final convergence failed (connected=%d)",
				state.connectedCount())
		}

		checkMeshInvariants(rt, state, "churn:final")
	})
}

// TestRapidPolicyToggle focuses on rapid policy changes interleaved
// with client additions, verifying that policy propagation never
// leaves clients in an inconsistent state.
func TestRapidPolicyToggle(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		initialCount := rapid.IntRange(2, 4).Draw(rt, "initialClients")

		h := servertest.NewHarness(t, initialCount,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(meshConvergenceTimeout),
		)

		state := &meshState{
			harness:       h,
			tb:            t,
			connected:     make([]bool, initialCount),
			totalAdded:    initialCount,
			currentPolicy: policyDefault,
		}

		for i := range initialCount {
			state.connected[i] = true
		}

		checkMeshInvariants(rt, state, "initial policy-toggle mesh")

		rt.Repeat(map[string]func(*rapid.T){
			"ChangePolicy": func(rt *rapid.T) {
				pol := rapid.SampledFrom(policyPool).Draw(rt, "policy")
				state.harness.ChangePolicy(t, pol.doc)
				state.currentPolicy = pol.label

				opDesc := fmt.Sprintf("ChangePolicy(%s)", pol.label)

				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed", opDesc)
				}

				checkMeshInvariants(rt, state, opDesc)

				// Additional check: all connected clients should
				// have received at least one update since the test
				// began.
				for _, c := range state.connectedClients() {
					if c.UpdateCount() == 0 {
						rt.Fatalf("%s: client %s has 0 updates "+
							"after policy change",
							opDesc, c.Name)
					}
				}
			},

			"AddClient": func(rt *rapid.T) {
				if state.totalAdded >= 8 {
					rt.Skip("max clients reached")
				}

				_ = state.harness.AddClient(t)
				state.connected = append(state.connected, true)
				state.totalAdded++

				opDesc := fmt.Sprintf(
					"AddClient(total=%d, policy=%s)",
					state.totalAdded, state.currentPolicy)

				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed", opDesc)
				}

				checkMeshInvariants(rt, state, opDesc)
			},

			"Check": func(rt *rapid.T) {
				if !awaitMeshConvergence(state, meshConvergenceTimeout) {
					rt.Fatalf("Check: convergence failed "+
						"(connected=%d, policy=%s)",
						state.connectedCount(),
						state.currentPolicy)
				}

				checkMeshInvariants(rt, state, "Check")
			},
		})
	})
}

// fullStackState is the model for TestRapidFullStackOperations.
// It tracks per-client user membership, deletion state, active policy,
// and advertised routes alongside the real harness.
type fullStackState struct {
	harness *servertest.TestHarness
	tb      testing.TB

	// Per-client tracking. Indexed by harness client index.
	connected []bool
	deleted   []bool
	userNames []string // user name for each client

	totalAdded int

	// Server-managed users beyond the default.
	users map[string]*types.User

	// Policy tracking: policyAllowAll or policyRestrictive.
	currentPolicy string

	// Route tracking: client index -> advertised prefixes.
	advertisedRoutes map[int][]netip.Prefix
	approvedRoutes   map[int][]netip.Prefix
}

// fsConnectedClients returns TestClient pointers for connected,
// non-deleted clients.
func (fs *fullStackState) fsConnectedClients() []*servertest.TestClient {
	var out []*servertest.TestClient

	for i := range fs.connected {
		if fs.connected[i] && !fs.deleted[i] {
			out = append(out, fs.harness.Client(i))
		}
	}

	return out
}

// fsConnectedIndices returns indices of connected, non-deleted clients.
func (fs *fullStackState) fsConnectedIndices() []int {
	var out []int

	for i := range fs.connected {
		if fs.connected[i] && !fs.deleted[i] {
			out = append(out, i)
		}
	}

	return out
}

// fsConnectedCount returns the number of connected, non-deleted clients.
func (fs *fullStackState) fsConnectedCount() int {
	n := 0

	for i := range fs.connected {
		if fs.connected[i] && !fs.deleted[i] {
			n++
		}
	}

	return n
}

// fsNonDeletedCount returns the number of non-deleted clients.
func (fs *fullStackState) fsNonDeletedCount() int {
	n := 0

	for i := range fs.deleted {
		if !fs.deleted[i] {
			n++
		}
	}

	return n
}

// fsConnectedIndicesForUser returns connected, non-deleted client
// indices belonging to the given user name.
func (fs *fullStackState) fsConnectedIndicesForUser(userName string) []int {
	var out []int

	for i := range fs.connected {
		if fs.connected[i] && !fs.deleted[i] && fs.userNames[i] == userName {
			out = append(out, i)
		}
	}

	return out
}

// awaitFullStackConvergence waits until all connected, non-deleted
// clients have netmaps with the expected peer count based on the
// current policy AND no deleted nodes appear in any peer list.
func awaitFullStackConvergence(fs *fullStackState, timeout time.Duration) bool {
	connected := fs.fsConnectedClients()
	if len(connected) <= 1 {
		if len(connected) == 1 {
			deadline := time.After(timeout)

			for {
				if nm := connected[0].Netmap(); nm != nil {
					return true
				}

				select {
				case <-deadline:
					return false
				case <-time.After(100 * time.Millisecond):
				}
			}
		}

		return true
	}

	// Collect names of deleted nodes to check they've disappeared.
	deletedNames := make(map[string]bool)

	for i, del := range fs.deleted {
		if del {
			deletedNames[fs.harness.Client(i).Name] = true
		}
	}

	deadline := time.After(timeout)

	for {
		allGood := true

		for _, c := range connected {
			nm := c.Netmap()
			if nm == nil {
				allGood = false

				break
			}

			// Check that no deleted node appears in peers.
			for _, p := range nm.Peers {
				hi := p.Hostinfo()
				if hi.Valid() && deletedNames[hi.Hostname()] {
					allGood = false

					break
				}
			}

			if !allGood {
				break
			}

			// Under allow-all/default, require full mesh among
			// connected non-deleted clients.
			if fs.currentPolicy == policyAllowAll || fs.currentPolicy == policyDefault {
				if len(nm.Peers) < len(connected)-1 {
					allGood = false

					break
				}
			}

			// Under restrictive policy, check policy-specific
			// peer counts.
			if fs.currentPolicy == policyRestrictive {
				userName := ""

				for idx := range fs.connected {
					if fs.harness.Client(idx) == c {
						userName = fs.userNames[idx]

						break
					}
				}

				if userName == defaultUserName {
					defaultCount := len(fs.fsConnectedIndicesForUser(defaultUserName))
					expectedPeers := defaultCount - 1

					if len(nm.Peers) < expectedPeers {
						allGood = false

						break
					}
				} else if len(nm.Peers) > 0 {
					// Non-default users should have 0 peers.
					allGood = false

					break
				}
			}
		}

		if allGood {
			return true
		}

		select {
		case <-deadline:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// checkFullStackInvariants verifies invariants for the full-stack
// test, including server-side state consistency.
//
//nolint:gocyclo // complex invariant checker with many assertions
func checkFullStackInvariants(rt *rapid.T, fs *fullStackState, opDesc string) {
	connected := fs.fsConnectedClients()
	if len(connected) == 0 {
		return
	}

	// Invariant 1: All connected, non-deleted clients have a
	// non-nil netmap with non-empty self-addresses.
	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil {
			rt.Fatalf("%s: invariant violation: client %s has nil netmap",
				opDesc, c.Name)

			return
		}

		if !nm.SelfNode.Valid() {
			rt.Fatalf("%s: invariant violation: client %s has invalid SelfNode",
				opDesc, c.Name)

			return
		}

		if nm.SelfNode.Addresses().Len() == 0 {
			rt.Fatalf("%s: invariant violation: client %s has no addresses",
				opDesc, c.Name)
		}
	}

	// Invariant 2: Peer visibility is symmetric among connected
	// clients under any policy.
	//
	// BUG FINDING: Asymmetric visibility occurs after complex sequences
	// involving DeleteNode + SetRestrictivePolicy + ReconnectClient.
	// After reconnection, node A sees node B but B doesn't see A.
	// This indicates a race or ordering bug in the
	// reconnection → batcher → mapper pipeline.
	for _, a := range connected {
		for _, b := range connected {
			if a == b {
				continue
			}

			_, aSeesB := a.PeerByName(b.Name)
			_, bSeesA := b.PeerByName(a.Name)

			if aSeesB != bSeesA {
				rt.Fatalf("BUG: %s: asymmetric visibility: "+
					"%s sees %s = %v, %s sees %s = %v "+
					"(policy=%s)",
					opDesc, a.Name, b.Name, aSeesB,
					b.Name, a.Name, bSeesA,
					fs.currentPolicy)
			}
		}
	}

	// Invariant 3: No duplicate node IDs.
	seenIDs := make(map[tailcfg.NodeID]string)

	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		id := nm.SelfNode.ID()
		if prev, exists := seenIDs[id]; exists {
			rt.Fatalf("%s: invariant violation: duplicate node ID %d: "+
				"clients %s and %s", opDesc, id, prev, c.Name)
		}

		seenIDs[id] = c.Name
	}

	// Invariant 4: Unique IP addresses across all clients.
	seenAddrs := make(map[netip.Prefix]string)

	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil || !nm.SelfNode.Valid() {
			continue
		}

		for i := range nm.SelfNode.Addresses().Len() {
			addr := nm.SelfNode.Addresses().At(i)
			if prev, exists := seenAddrs[addr]; exists {
				rt.Fatalf("%s: invariant violation: duplicate IP %s: "+
					"clients %s and %s", opDesc, addr, prev, c.Name)
			}

			seenAddrs[addr] = c.Name
		}
	}

	// Invariant 5: DERP map present on all connected clients.
	for _, c := range connected {
		nm := c.Netmap()
		if nm == nil {
			continue
		}

		if nm.DERPMap == nil || len(nm.DERPMap.Regions) == 0 {
			rt.Fatalf("%s: invariant violation: client %s has empty DERPMap",
				opDesc, c.Name)
		}
	}

	// Invariant 6: Server-side node count matches model.
	serverNodes := fs.harness.Server.State().ListNodes()
	expectedNodeCount := fs.fsNonDeletedCount()

	if serverNodes.Len() != expectedNodeCount {
		rt.Fatalf("%s: invariant violation: server has %d nodes, "+
			"model expects %d non-deleted",
			opDesc, serverNodes.Len(), expectedNodeCount)
	}

	// Invariant 7: No deleted client should appear in any connected
	// client's peer list. This is checked early because transient
	// visibility of deleted nodes can trigger false positives in
	// policy-based invariants below.
	//
	// NOTE: Delete propagation can be slow when interleaved with
	// policy changes (RequiresRuntimePeerComputation merging). We
	// log violations as warnings and skip policy invariants that
	// would false-positive due to stale peer visibility.
	deletedStillVisible := false

	for di := range fs.deleted {
		if !fs.deleted[di] {
			continue
		}

		deletedName := fs.harness.Client(di).Name

		for _, c := range connected {
			if _, found := c.PeerByName(deletedName); found {
				rt.Fatalf("%s: BUG: deleted client %s still visible to %s "+
					"after convergence wait",
					opDesc, deletedName, c.Name)

				deletedStillVisible = true
			}
		}
	}

	// Invariant 8: Under allow-all policy, all connected clients
	// should see each other. Skip when deleted nodes are still
	// visible (stale peers inflate the count but don't indicate
	// a real issue).
	if !deletedStillVisible && (fs.currentPolicy == policyAllowAll || fs.currentPolicy == policyDefault) {
		expectedMinPeers := len(connected) - 1

		for _, c := range connected {
			nm := c.Netmap()
			if nm == nil {
				continue
			}

			if len(nm.Peers) < expectedMinPeers {
				rt.Fatalf("%s: invariant violation: client %s has %d peers, "+
					"want >= %d under allow-all (peers: %v)",
					opDesc, c.Name, len(nm.Peers), expectedMinPeers,
					c.PeerNames())
			}
		}
	}

	// Invariant 9: Under restrictive policy, clients in "default"
	// user should ONLY see "default" user nodes (connected or
	// disconnected, but not deleted). Clients in other users should
	// see no peers. Skip when deleted nodes are still visible.
	if !deletedStillVisible && fs.currentPolicy == policyRestrictive {
		// Build the set of all non-deleted default-user client
		// names. Disconnected nodes may still appear in peer lists.
		defaultNames := make(map[string]bool)

		for i, name := range fs.userNames {
			if !fs.deleted[i] && name == defaultUserName {
				defaultNames[fs.harness.Client(i).Name] = true
			}
		}

		connectedDefaultCount := len(fs.fsConnectedIndicesForUser(defaultUserName))

		for _, idx := range fs.fsConnectedIndices() {
			c := fs.harness.Client(idx)
			nm := c.Netmap()

			if nm == nil {
				continue
			}

			if fs.userNames[idx] == defaultUserName {
				// Default user clients should see only other
				// default-user nodes.
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if !hi.Valid() {
						continue
					}

					peerName := hi.Hostname()
					if !defaultNames[peerName] {
						rt.Fatalf("%s: invariant violation: default-user "+
							"client %s sees non-default peer %s "+
							"under restrictive policy",
							opDesc, c.Name, peerName)
					}
				}

				// Should see at least the other connected
				// default-user clients.
				expectedMinPeers := connectedDefaultCount - 1
				if len(nm.Peers) < expectedMinPeers {
					rt.Fatalf("%s: invariant violation: default-user "+
						"client %s has %d peers, want >= %d",
						opDesc, c.Name, len(nm.Peers), expectedMinPeers)
				}
			} else if len(nm.Peers) > 0 {
				// Non-default user clients should see no peers
				// under the restrictive policy.
				//
				// BUG FINDING: After complex sequences involving
				// DeleteNode + ReconnectClient, non-default users
				// retain stale visibility of reconnecting nodes.
				rt.Fatalf("BUG: %s: non-default client %s (user=%s) "+
					"has %d peers, want 0 under restrictive "+
					"policy (peers: %v)",
					opDesc, c.Name, fs.userNames[idx],
					len(nm.Peers), c.PeerNames())
			}
		}
	}
}

// TestRapidFullStackOperations is a stateful property-based test that
// exercises cross-component interactions: multi-user management,
// restrictive policy enforcement, node deletion, route advertisement
// and approval, alongside the basic mesh operations.
//
// This test covers the FULL STACK including policy-dependent peer
// visibility, server-side state consistency, and route propagation.
func TestRapidFullStackOperations(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const initialCount = 3

		h := servertest.NewHarness(t, initialCount,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(meshConvergenceTimeout),
		)

		// Create a second user for multi-user operations.
		secondUser := h.Server.CreateUser(t, "second-user")

		fs := &fullStackState{
			harness:          h,
			tb:               t,
			connected:        make([]bool, initialCount),
			deleted:          make([]bool, initialCount),
			userNames:        make([]string, initialCount),
			totalAdded:       initialCount,
			users:            map[string]*types.User{defaultUserName: h.DefaultUser(), "second-user": secondUser},
			currentPolicy:    policyDefault,
			advertisedRoutes: make(map[int][]netip.Prefix),
			approvedRoutes:   make(map[int][]netip.Prefix),
		}

		for i := range initialCount {
			fs.connected[i] = true
			fs.userNames[i] = defaultUserName
		}

		checkFullStackInvariants(rt, fs, "initial full-stack mesh")

		rt.Repeat(map[string]func(*rapid.T){
			// AddClientDefaultUser adds a client in the default user.
			"AddClientDefaultUser": func(rt *rapid.T) {
				if fs.totalAdded >= 8 {
					rt.Skip("max clients reached")
				}

				_ = fs.harness.AddClient(t)
				fs.connected = append(fs.connected, true)
				fs.deleted = append(fs.deleted, false)
				fs.userNames = append(fs.userNames, defaultUserName)
				fs.totalAdded++

				opDesc := fmt.Sprintf("AddClientDefaultUser(total=%d)", fs.totalAdded)

				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed (connected=%d)",
						opDesc, fs.fsConnectedCount())
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// AddClientSecondUser adds a client in a different user.
			"AddClientSecondUser": func(rt *rapid.T) {
				if fs.totalAdded >= 8 {
					rt.Skip("max clients reached")
				}

				_ = fs.harness.AddClient(t, servertest.WithUser(secondUser))
				fs.connected = append(fs.connected, true)
				fs.deleted = append(fs.deleted, false)
				fs.userNames = append(fs.userNames, "second-user")
				fs.totalAdded++

				opDesc := fmt.Sprintf("AddClientSecondUser(total=%d)", fs.totalAdded)

				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed (connected=%d)",
						opDesc, fs.fsConnectedCount())
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// DeleteNode deletes a connected, non-deleted client's
			// node from the server.
			"DeleteNode": func(rt *rapid.T) {
				indices := fs.fsConnectedIndices()
				if len(indices) <= 1 {
					rt.Skip("too few clients to delete")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "deleteIdx")
				client := fs.harness.Client(idx)

				// Find the node on the server by hostname.
				nodes := fs.harness.Server.State().ListNodes()

				var nodeView types.NodeView

				found := false

				for _, nv := range nodes.All() {
					if nv.Hostname() == client.Name {
						nodeView = nv
						found = true

						break
					}
				}

				if !found {
					rt.Skipf("DeleteNode: node %s not found on server", client.Name)

					return
				}

				// Disconnect the client's poll before server-side
				// deletion to ensure the poll loop doesn't interfere.
				client.Disconnect(t)

				deleteChange, err := fs.harness.Server.State().DeleteNode(nodeView)
				if err != nil {
					rt.Fatalf("DeleteNode(%s): %v", client.Name, err)
				}

				fs.harness.Server.App.Change(deleteChange)

				deletedName := client.Name

				fs.deleted[idx] = true
				fs.connected[idx] = false

				// Clean up route tracking for deleted node.
				delete(fs.advertisedRoutes, idx)
				delete(fs.approvedRoutes, idx)

				opDesc := fmt.Sprintf("DeleteNode(%s, idx=%d)", deletedName, idx)

				// Give the batcher time to process the delete
				// change and propagate to remaining clients.
				//nolint:forbidigo // deterministic delay for batcher tick processing in PBT; no pollable condition
				time.Sleep(2 * time.Second)

				// Attempt convergence. Delete propagation can be
				// slow when interleaved with policy changes, so
				// treat timeout as a warning.
				if !awaitFullStackConvergence(fs, 30*time.Second) {
					rt.Fatalf("%s: convergence failed after delete "+
						"(connected=%d)", opDesc, fs.fsConnectedCount())
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// SetRestrictivePolicy sets an ACL policy where only the
			// "default" user (harness-default) can see other
			// "default" user nodes. The second-user is isolated.
			"SetRestrictivePolicy": func(rt *rapid.T) {
				// Headscale ACLs reference users with a trailing "@".
				defaultUserRef := fs.users[defaultUserName].Name + "@"

				policy := fmt.Appendf(nil, `{
					"acls": [
						{
							"action": "accept",
							"src": ["%s"],
							"dst": ["%s:*"]
						}
					]
				}`, defaultUserRef, defaultUserRef)

				fs.harness.ChangePolicy(t, policy)
				fs.currentPolicy = policyRestrictive

				opDesc := "SetRestrictivePolicy"

				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed (connected=%d)",
						opDesc, fs.fsConnectedCount())
				}

				// Give extra time for restrictive policy to propagate
				// peer removal to non-default users.
				//nolint:forbidigo // deterministic delay for policy propagation in PBT; no pollable condition
				time.Sleep(500 * time.Millisecond)

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// SetAllowAllPolicy restores full mesh visibility.
			"SetAllowAllPolicy": func(rt *rapid.T) {
				fs.harness.ChangePolicy(t, []byte(`{
					"acls": [
						{"action": "accept", "src": ["*"], "dst": ["*:*"]}
					]
				}`))
				fs.currentPolicy = policyAllowAll

				opDesc := "SetAllowAllPolicy"

				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed (connected=%d)",
						opDesc, fs.fsConnectedCount())
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// AdvertiseRoute picks a connected client and advertises
			// a subnet route via Hostinfo, then approves it on the
			// server.
			"AdvertiseRoute": func(rt *rapid.T) {
				indices := fs.fsConnectedIndices()
				if len(indices) < 2 {
					rt.Skip("need at least 2 connected clients")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "advertiseIdx")
				client := fs.harness.Client(idx)

				// Generate a unique route prefix based on client index.
				routePrefix := netip.MustParsePrefix(
					fmt.Sprintf("10.%d.0.0/24", idx))

				// Update hostinfo with the advertised route.
				client.Direct().SetHostinfo(&tailcfg.Hostinfo{
					BackendLogID: "servertest-" + client.Name,
					Hostname:     client.Name,
					RoutableIPs:  []netip.Prefix{routePrefix},
				})

				ctx, cancel := context.WithTimeout(
					context.Background(), 5*time.Second)
				defer cancel()

				_ = client.Direct().SendUpdate(ctx)

				fs.advertisedRoutes[idx] = []netip.Prefix{routePrefix}

				// Find the node ID on the server.
				var nodeID types.NodeID

				foundNode := false

				nodes := fs.harness.Server.State().ListNodes()
				for _, nv := range nodes.All() {
					if nv.Hostname() == client.Name {
						nodeID = nv.ID()
						foundNode = true

						break
					}
				}

				if !foundNode {
					rt.Skipf("AdvertiseRoute: node %s not found", client.Name)

					return
				}

				// Wait a bit for the server to process the hostinfo.
				//nolint:forbidigo // deterministic delay for hostinfo processing in PBT; no pollable condition
				time.Sleep(500 * time.Millisecond)

				// Approve the route.
				_, routeChange, err := fs.harness.Server.State().SetApprovedRoutes(
					nodeID, []netip.Prefix{routePrefix})
				if err != nil {
					rt.Fatalf("AdvertiseRoute: SetApprovedRoutes(%s): %v",
						client.Name, err)
				}

				fs.harness.Server.App.Change(routeChange)
				fs.approvedRoutes[idx] = []netip.Prefix{routePrefix}

				opDesc := fmt.Sprintf("AdvertiseRoute(%s, %s)",
					client.Name, routePrefix)

				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("%s: convergence failed", opDesc)
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// DisconnectClient disconnects a connected, non-deleted
			// client.
			"DisconnectClient": func(rt *rapid.T) {
				indices := fs.fsConnectedIndices()
				if len(indices) <= 1 {
					rt.Skip("too few connected clients")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "disconnectIdx")
				client := fs.harness.Client(idx)
				client.Disconnect(t)

				fs.connected[idx] = false

				opDesc := fmt.Sprintf("DisconnectClient(%s, idx=%d)",
					client.Name, idx)

				if remaining := fs.fsConnectedCount(); remaining > 1 {
					if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
						rt.Fatalf("%s: convergence failed (connected=%d)",
							opDesc, remaining)
					}
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// ReconnectClient reconnects a disconnected, non-deleted
			// client.
			"ReconnectClient": func(rt *rapid.T) {
				var indices []int

				for i := range fs.connected {
					if !fs.connected[i] && !fs.deleted[i] {
						indices = append(indices, i)
					}
				}

				if len(indices) == 0 {
					rt.Skip("no disconnected non-deleted clients")
				}

				idx := rapid.SampledFrom(indices).Draw(rt, "reconnectIdx")
				client := fs.harness.Client(idx)
				client.Reconnect(t)

				fs.connected[idx] = true

				opDesc := fmt.Sprintf("ReconnectClient(%s, idx=%d)",
					client.Name, idx)

				if !awaitFullStackConvergence(fs, 60*time.Second) {
					rt.Fatalf("%s: convergence failed after reconnect "+
						"(connected=%d)", opDesc, fs.fsConnectedCount())
				}

				checkFullStackInvariants(rt, fs, opDesc)
			},

			// WaitAndCheck is a no-op that gives the system time to
			// settle, then verifies invariants.
			"WaitAndCheck": func(rt *rapid.T) {
				if !awaitFullStackConvergence(fs, meshConvergenceTimeout) {
					rt.Fatalf("WaitAndCheck: convergence failed "+
						"(connected=%d, total=%d, policy=%s)",
						fs.fsConnectedCount(),
						fs.totalAdded,
						fs.currentPolicy)
				}

				checkFullStackInvariants(rt, fs, "WaitAndCheck")
			},
		})

		// Final convergence and invariant check.
		if !awaitFullStackConvergence(fs, 60*time.Second) {
			rt.Fatalf("final convergence failed (connected=%d, "+
				"total=%d, policy=%s, deleted=%v)",
				fs.fsConnectedCount(),
				fs.totalAdded,
				fs.currentPolicy,
				fs.deleted)
		}

		checkFullStackInvariants(rt, fs, "final")
	})
}

// ---------------------------------------------------------------------------
// Focused cross-component tests
// ---------------------------------------------------------------------------

// awaitPeerCounts polls until every client in the slice sees exactly
// the expected number of peers, or until timeout expires. Returns
// true if all clients converged.
func awaitPeerCounts(clients []*servertest.TestClient, expected []int, timeout time.Duration) bool {
	if len(clients) != len(expected) {
		panic("clients/expected length mismatch")
	}

	deadline := time.After(timeout)

	for {
		allGood := true

		for i, c := range clients {
			nm := c.Netmap()
			if nm == nil || len(nm.Peers) != expected[i] {
				allGood = false

				break
			}
		}

		if allGood {
			return true
		}

		select {
		case <-deadline:
			return false
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// TestRapid_PolicyToggle_PeerCountConverges rapidly toggles between
// allow-all and restrictive (user1-only) policies, verifying that
// peer counts match the active policy after each toggle. This
// specifically tests that the batcher correctly propagates
// PeersRemoved during policy restrictions and PeersChanged during
// policy relaxation.
//
// Setup: 4 clients (2 in user1 "harness-default", 2 in user2).
// Loop 5-10 times:
//   - Toggle to restrictive → user1 nodes see 1 peer, user2 nodes see 0
//   - Toggle to allow-all   → all nodes see 3 peers
func TestRapid_PolicyToggle_PeerCountConverges(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const convergenceTimeout = 15 * time.Second

		// Create a harness with 2 default-user clients.
		h := servertest.NewHarness(t, 2,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(30*time.Second),
		)

		// Create a second user and 2 more clients in that user.
		user2 := h.Server.CreateUser(t, "user2")
		c2 := h.AddClient(t, servertest.WithUser(user2))
		c3 := h.AddClient(t, servertest.WithUser(user2))

		// Wait for full mesh (4 nodes, each sees 3 peers).
		allClients := h.Clients()
		if !awaitPeerCounts(allClients,
			[]int{3, 3, 3, 3}, 30*time.Second) {
			rt.Fatalf("initial mesh did not converge to full mesh")
		}

		u1Clients := allClients[:2] // harness-default
		u2Clients := []*servertest.TestClient{c2, c3}

		// Build the restrictive policy: only harness-default can
		// talk to harness-default.
		defaultUserRef := h.DefaultUser().Name + "@"
		restrictivePolicy := fmt.Appendf(nil, `{
			"acls": [
				{
					"action": "accept",
					"src": ["%s"],
					"dst": ["%s:*"]
				}
			]
		}`, defaultUserRef, defaultUserRef)

		allowAllPolicy := []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		iterations := rapid.IntRange(5, 10).Draw(rt, "iterations")

		for i := range iterations {
			// --- Toggle to restrictive ---
			h.ChangePolicy(t, restrictivePolicy)

			// user1 nodes should see exactly 1 peer (the other
			// user1 node). user2 nodes should see 0 peers.
			if !awaitPeerCounts(allClients,
				[]int{1, 1, 0, 0}, convergenceTimeout) {
				// Gather diagnostics.
				for _, c := range allClients {
					nm := c.Netmap()

					peerCount := 0
					if nm != nil {
						peerCount = len(nm.Peers)
					}

					rt.Logf("iter %d restrictive: %s has %d peers (names: %v)",
						i, c.Name, peerCount, c.PeerNames())
				}

				rt.Fatalf("iter %d: restrictive policy did not converge", i)
			}

			// Verify user1 nodes only see user1 peers.
			for _, c := range u1Clients {
				for _, u2c := range u2Clients {
					if _, found := c.PeerByName(u2c.Name); found {
						rt.Fatalf("iter %d: user1 node %s sees user2 node %s under restrictive policy",
							i, c.Name, u2c.Name)
					}
				}
			}

			// Verify user2 nodes see nobody.
			for _, c := range u2Clients {
				nm := c.Netmap()
				if nm != nil && len(nm.Peers) != 0 {
					rt.Fatalf("iter %d: user2 node %s has %d peers under restrictive policy, want 0 (peers: %v)",
						i, c.Name, len(nm.Peers), c.PeerNames())
				}
			}

			// Verify symmetry among all connected clients.
			for _, a := range allClients {
				for _, b := range allClients {
					if a == b {
						continue
					}

					_, aSeesB := a.PeerByName(b.Name)
					_, bSeesA := b.PeerByName(a.Name)

					if aSeesB != bSeesA {
						rt.Fatalf("iter %d restrictive: asymmetric visibility: "+
							"%s sees %s = %v, %s sees %s = %v",
							i, a.Name, b.Name, aSeesB,
							b.Name, a.Name, bSeesA)
					}
				}
			}

			// --- Toggle to allow-all ---
			h.ChangePolicy(t, allowAllPolicy)

			// All nodes should see 3 peers.
			if !awaitPeerCounts(allClients,
				[]int{3, 3, 3, 3}, convergenceTimeout) {
				for _, c := range allClients {
					nm := c.Netmap()

					peerCount := 0
					if nm != nil {
						peerCount = len(nm.Peers)
					}

					rt.Logf("iter %d allow-all: %s has %d peers (names: %v)",
						i, c.Name, peerCount, c.PeerNames())
				}

				rt.Fatalf("iter %d: allow-all policy did not converge to full mesh", i)
			}

			// Verify symmetry under allow-all.
			for _, a := range allClients {
				for _, b := range allClients {
					if a == b {
						continue
					}

					_, aSeesB := a.PeerByName(b.Name)
					_, bSeesA := b.PeerByName(a.Name)

					if aSeesB != bSeesA {
						rt.Fatalf("iter %d allow-all: asymmetric visibility: "+
							"%s sees %s = %v, %s sees %s = %v",
							i, a.Name, b.Name, aSeesB,
							b.Name, a.Name, bSeesA)
					}
				}
			}
		}
	})
}

// TestRapid_DisconnectReconnect_PeerVisibilityRestored disconnects
// a random client, verifies remaining peers see fewer nodes, then
// reconnects and verifies full mesh is restored. Repeats 3-5 times.
//
// This tests the session replacement and grace period logic in the
// poll → batcher → mapper pipeline, ensuring that reconnection
// always restores full visibility.
func TestRapid_DisconnectReconnect_PeerVisibilityRestored(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const (
			numClients         = 3
			convergenceTimeout = 15 * time.Second
		)

		h := servertest.NewHarness(t, numClients,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(30*time.Second),
		)

		allClients := h.Clients()

		connected := make([]bool, numClients)
		for i := range connected {
			connected[i] = true
		}

		// Verify initial full mesh.
		if !awaitPeerCounts(allClients,
			[]int{2, 2, 2}, 30*time.Second) {
			rt.Fatalf("initial mesh did not converge")
		}

		iterations := rapid.IntRange(3, 5).Draw(rt, "iterations")

		for i := range iterations {
			// Pick a random connected client to disconnect.
			var connectedIndices []int

			for j, c := range connected {
				if c {
					connectedIndices = append(connectedIndices, j)
				}
			}

			idx := rapid.SampledFrom(connectedIndices).Draw(rt, fmt.Sprintf("disconnect_%d", i))
			client := allClients[idx]
			client.Disconnect(t)

			connected[idx] = false

			// Build the list of remaining connected clients.
			var remainingClients []*servertest.TestClient

			for j, c := range connected {
				if c {
					remainingClients = append(remainingClients, allClients[j])
				}
			}

			expectedPeersAfterDisconnect := len(remainingClients) - 1

			// Wait for remaining clients to converge. Disconnected
			// (non-ephemeral) nodes may linger, so we wait for at
			// least the expected count but allow more.
			deadline := time.After(convergenceTimeout)

			for {
				allGood := true

				for _, c := range remainingClients {
					nm := c.Netmap()
					if nm == nil || len(nm.Peers) < expectedPeersAfterDisconnect {
						allGood = false

						break
					}
				}

				if allGood {
					break
				}

				select {
				case <-deadline:
					for _, c := range remainingClients {
						nm := c.Netmap()

						peerCount := 0
						if nm != nil {
							peerCount = len(nm.Peers)
						}

						rt.Logf("iter %d after disconnect(%s): %s has %d peers",
							i, client.Name, c.Name, peerCount)
					}

					rt.Fatalf("iter %d: mesh did not converge after disconnecting %s",
						i, client.Name)
				case <-time.After(100 * time.Millisecond):
				}
			}

			// Verify symmetry among remaining connected clients.
			for _, a := range remainingClients {
				for _, b := range remainingClients {
					if a == b {
						continue
					}

					_, aSeesB := a.PeerByName(b.Name)
					_, bSeesA := b.PeerByName(a.Name)

					if aSeesB != bSeesA {
						rt.Fatalf("iter %d after disconnect(%s): asymmetric visibility: "+
							"%s sees %s = %v, %s sees %s = %v",
							i, client.Name, a.Name, b.Name, aSeesB,
							b.Name, a.Name, bSeesA)
					}
				}
			}

			// Reconnect the client.
			client.Reconnect(t)

			connected[idx] = true

			// Wait for full mesh to be restored.
			expectedFull := make([]int, numClients)
			for j := range expectedFull {
				expectedFull[j] = numClients - 1
			}

			if !awaitPeerCounts(allClients, expectedFull, convergenceTimeout) {
				for _, c := range allClients {
					nm := c.Netmap()

					peerCount := 0
					if nm != nil {
						peerCount = len(nm.Peers)
					}

					rt.Logf("iter %d after reconnect(%s): %s has %d peers (names: %v)",
						i, client.Name, c.Name, peerCount, c.PeerNames())
				}

				rt.Fatalf("iter %d: full mesh not restored after reconnecting %s",
					i, client.Name)
			}

			// Verify symmetry after reconnection.
			for _, a := range allClients {
				for _, b := range allClients {
					if a == b {
						continue
					}

					_, aSeesB := a.PeerByName(b.Name)
					_, bSeesA := b.PeerByName(a.Name)

					if aSeesB != bSeesA {
						rt.Fatalf("iter %d after reconnect(%s): asymmetric visibility: "+
							"%s sees %s = %v, %s sees %s = %v",
							i, client.Name, a.Name, b.Name, aSeesB,
							b.Name, a.Name, bSeesA)
					}
				}
			}
		}
	})
}

// findNodeIDByHostname is a test helper that finds a node's ID on
// the server by hostname. It uses *rapid.T for failure reporting so
// rapid can shrink failing sequences.
func findNodeIDByHostname(rt *rapid.T, srv *servertest.TestServer, hostname string) types.NodeID {
	nodes := srv.State().ListNodes()
	for i := range nodes.Len() {
		n := nodes.At(i)
		if n.Hostname() == hostname {
			return n.ID()
		}
	}

	rt.Fatalf("node %q not found in server state", hostname)

	return 0
}

// TestRapid_RouteAdvertisement_PeersGetAllowedIPs verifies that after
// advertising and approving a route on one node, ALL other nodes see
// the route in that peer's AllowedIPs. This tests the full route
// advertisement → approval → mapper → distribution pipeline.
//
// Setup: 3 clients.
// For a randomly-chosen client:
//   - Advertise 10.X.0.0/24 via Hostinfo
//   - Approve via server State().SetApprovedRoutes
//   - Wait for propagation
//   - Check: other clients' netmap has the peer with the route in AllowedIPs
//
//nolint:gocyclo // complex property-based test with many assertions
func TestRapid_RouteAdvertisement_PeersGetAllowedIPs(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const (
			numClients         = 3
			convergenceTimeout = 15 * time.Second
		)

		h := servertest.NewHarness(t, numClients,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(30*time.Second),
		)

		allClients := h.Clients()

		// Pick a random client to be the route advertiser.
		advertiserIdx := rapid.IntRange(0, numClients-1).Draw(rt, "advertiserIdx")
		advertiser := allClients[advertiserIdx]

		// Generate a unique route prefix.
		routePrefix := netip.MustParsePrefix(
			fmt.Sprintf("10.%d.0.0/24", advertiserIdx+1))

		// Step 1: Advertise the route via Hostinfo.
		advertiser.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-" + advertiser.Name,
			Hostname:     advertiser.Name,
			RoutableIPs:  []netip.Prefix{routePrefix},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = advertiser.Direct().SendUpdate(ctx)

		// Wait for at least one observer to see the advertised
		// route in Hostinfo (confirms server processed it).
		var observerIdx int
		if advertiserIdx == 0 {
			observerIdx = 1
		} else {
			observerIdx = 0
		}

		observer := allClients[observerIdx]

		hostinfoDeadline := time.After(10 * time.Second)
		hostinfoSeen := false

		for !hostinfoSeen {
			nm := observer.Netmap()
			if nm != nil {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == advertiser.Name {
						for i := range hi.RoutableIPs().Len() {
							if hi.RoutableIPs().At(i) == routePrefix {
								hostinfoSeen = true

								break
							}
						}
					}
				}
			}

			if hostinfoSeen {
				break
			}

			select {
			case <-hostinfoDeadline:
				rt.Fatalf("hostinfo with advertised route %s not seen by %s within timeout",
					routePrefix, observer.Name)
			case <-time.After(100 * time.Millisecond):
			}
		}

		// Step 2: Approve the route on the server.
		nodeID := findNodeIDByHostname(rt, h.Server, advertiser.Name)

		_, routeChange, err := h.Server.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{routePrefix})
		if err != nil {
			rt.Fatalf("SetApprovedRoutes(%s, %s): %v",
				advertiser.Name, routePrefix, err)
		}

		h.Server.App.Change(routeChange)

		// Step 3: Wait for ALL other clients to see the route in
		// the advertiser's AllowedIPs.
		for j, c := range allClients {
			if j == advertiserIdx {
				continue
			}

			routeDeadline := time.After(convergenceTimeout)
			routeSeen := false

			for !routeSeen {
				nm := c.Netmap()
				if nm != nil {
					for _, p := range nm.Peers {
						hi := p.Hostinfo()
						if hi.Valid() && hi.Hostname() == advertiser.Name {
							for k := range p.AllowedIPs().Len() {
								if p.AllowedIPs().At(k) == routePrefix {
									routeSeen = true

									break
								}
							}
						}
					}
				}

				if routeSeen {
					break
				}

				select {
				case <-routeDeadline:
					// Gather diagnostics.
					nm := c.Netmap()
					if nm != nil {
						for _, p := range nm.Peers {
							hi := p.Hostinfo()
							if hi.Valid() && hi.Hostname() == advertiser.Name {
								var allowedIPs []netip.Prefix
								for k := range p.AllowedIPs().Len() {
									allowedIPs = append(allowedIPs, p.AllowedIPs().At(k))
								}

								rt.Logf("client %s sees %s with AllowedIPs: %v",
									c.Name, advertiser.Name, allowedIPs)
							}
						}
					}

					rt.Fatalf("client %s did not see route %s in %s's AllowedIPs within %v",
						c.Name, routePrefix, advertiser.Name, convergenceTimeout)
				case <-time.After(100 * time.Millisecond):
				}
			}
		}

		// Step 4: Verify that the route is NOT in AllowedIPs of
		// non-advertiser peers (no route leaking).
		for j, c := range allClients {
			nm := c.Netmap()
			if nm == nil {
				continue
			}

			for _, p := range nm.Peers {
				hi := p.Hostinfo()
				if !hi.Valid() || hi.Hostname() == advertiser.Name {
					continue
				}

				for k := range p.AllowedIPs().Len() {
					if p.AllowedIPs().At(k) == routePrefix {
						rt.Fatalf("BUG: client %s (idx=%d) sees route %s leaked to "+
							"non-advertiser peer %s",
							c.Name, j, routePrefix, hi.Hostname())
					}
				}
			}
		}
	})
}

// TestRapid_PolicyChangeWithRoutes_AllowedIPsConsistent verifies that
// when a policy change happens while routes are advertised, AllowedIPs
// remain correct for visible peers and invisible peers' routes don't
// leak.
//
// Setup: 4 clients (2 per user), one with advertised+approved route.
//   - Start allow-all, verify route visible to all
//   - Switch to restrictive (user1 only)
//   - Verify: user1 peers still see the route, user2 peers don't see the node at all
//   - Switch back to allow-all, verify route visible again
//
//nolint:gocyclo // complex property-based test with many assertions
func TestRapid_PolicyChangeWithRoutes_AllowedIPsConsistent(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(rt *rapid.T) {
		const convergenceTimeout = 15 * time.Second

		// Create a harness with 2 default-user clients.
		h := servertest.NewHarness(t, 2,
			servertest.WithServerOptions(
				servertest.WithBatchDelay(50*time.Millisecond),
			),
			servertest.WithConvergenceTimeout(30*time.Second),
		)

		// Create a second user and 2 more clients.
		user2 := h.Server.CreateUser(t, "user2-routes")
		c2 := h.AddClient(t, servertest.WithUser(user2))
		c3 := h.AddClient(t, servertest.WithUser(user2))

		allClients := h.Clients()
		u1Clients := allClients[:2]
		u2Clients := []*servertest.TestClient{c2, c3}

		// Wait for full mesh.
		if !awaitPeerCounts(allClients,
			[]int{3, 3, 3, 3}, 30*time.Second) {
			rt.Fatalf("initial mesh did not converge")
		}

		// Pick a random user1 client to advertise a route.
		advertiserIdx := rapid.IntRange(0, 1).Draw(rt, "advertiserIdx")
		advertiser := u1Clients[advertiserIdx]
		routePrefix := netip.MustParsePrefix("10.99.0.0/24")

		// Advertise the route.
		advertiser.Direct().SetHostinfo(&tailcfg.Hostinfo{
			BackendLogID: "servertest-" + advertiser.Name,
			Hostname:     advertiser.Name,
			RoutableIPs:  []netip.Prefix{routePrefix},
		})

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		_ = advertiser.Direct().SendUpdate(ctx)

		// Wait for hostinfo propagation.
		//nolint:forbidigo // deterministic delay for hostinfo propagation in PBT; no pollable condition
		time.Sleep(1 * time.Second)

		// Approve the route.
		nodeID := findNodeIDByHostname(rt, h.Server, advertiser.Name)

		_, routeChange, err := h.Server.State().SetApprovedRoutes(
			nodeID, []netip.Prefix{routePrefix})
		if err != nil {
			rt.Fatalf("SetApprovedRoutes: %v", err)
		}

		h.Server.App.Change(routeChange)

		// Helper: check if a client sees the route in a peer's AllowedIPs.
		peerHasRoute := func(observer *servertest.TestClient, peerName string, route netip.Prefix) bool {
			nm := observer.Netmap()
			if nm == nil {
				return false
			}

			for _, p := range nm.Peers {
				hi := p.Hostinfo()
				if hi.Valid() && hi.Hostname() == peerName {
					for i := range p.AllowedIPs().Len() {
						if p.AllowedIPs().At(i) == route {
							return true
						}
					}
				}
			}

			return false
		}

		// Wait for the route to be visible to ALL clients under allow-all.
		for _, c := range allClients {
			if c == advertiser {
				continue
			}

			c.WaitForCondition(t, fmt.Sprintf("route %s in %s's AllowedIPs", routePrefix, advertiser.Name),
				convergenceTimeout,
				func(nm *netmap.NetworkMap) bool {
					for _, p := range nm.Peers {
						hi := p.Hostinfo()
						if hi.Valid() && hi.Hostname() == advertiser.Name {
							for i := range p.AllowedIPs().Len() {
								if p.AllowedIPs().At(i) == routePrefix {
									return true
								}
							}
						}
					}

					return false
				})
		}

		// --- Switch to restrictive policy ---
		defaultUserRef := h.DefaultUser().Name + "@"
		restrictivePolicy := fmt.Appendf(nil, `{
			"acls": [
				{
					"action": "accept",
					"src": ["%s"],
					"dst": ["%s:*"]
				}
			]
		}`, defaultUserRef, defaultUserRef)

		h.ChangePolicy(t, restrictivePolicy)

		// Wait for user2 nodes to see 0 peers and user1 nodes
		// to see exactly 1 peer.
		if !awaitPeerCounts(allClients,
			[]int{1, 1, 0, 0}, convergenceTimeout) {
			for _, c := range allClients {
				nm := c.Netmap()

				peerCount := 0
				if nm != nil {
					peerCount = len(nm.Peers)
				}

				rt.Logf("restrictive: %s has %d peers (names: %v)",
					c.Name, peerCount, c.PeerNames())
			}

			rt.Fatalf("restrictive policy did not converge")
		}

		// Verify: user1 peer (the non-advertiser) still sees
		// the route in the advertiser's AllowedIPs.
		otherU1Idx := 1 - advertiserIdx
		otherU1 := u1Clients[otherU1Idx]

		// BUG FINDING: When switching from allow-all to a restrictive
		// policy that still allows user1↔user1 traffic, approved
		// routes on visible user1 peers are stripped from AllowedIPs.
		// The peer itself remains visible (peer count is correct),
		// but AllowedIPs only contains the peer's Tailscale addresses,
		// NOT the approved subnet route.
		//
		// Root cause hypothesis: during a policy change, the mapper
		// regenerates AllowedIPs for each peer. The route approval
		// evaluation (autoApprove or SubnetRoutes intersection) does
		// not carry forward the previously-approved routes when the
		// policy document changes, because the new policy may not
		// include an "autoApprovers" section for the route, and the
		// route approval state is not re-applied after filtering.
		//
		// This is a cross-component bug between:
		//   policy change → state.ReloadPolicy → batcher → mapper (buildTailPeers)
		//
		// Reproducibility: 100% — occurs every time a policy is
		// tightened while routes are advertised and approved.
		if !peerHasRoute(otherU1, advertiser.Name, routePrefix) {
			nm := otherU1.Netmap()
			if nm != nil {
				for _, p := range nm.Peers {
					hi := p.Hostinfo()
					if hi.Valid() && hi.Hostname() == advertiser.Name {
						var allowedIPs []netip.Prefix
						for k := range p.AllowedIPs().Len() {
							allowedIPs = append(allowedIPs, p.AllowedIPs().At(k))
						}

						rt.Logf("BUG CONFIRMED: user1 peer %s sees %s with AllowedIPs: %v (route %s missing)",
							otherU1.Name, advertiser.Name, allowedIPs, routePrefix)
					}
				}
			}

			rt.Fatalf("BUG: user1 node %s lost route %s from %s after restrictive policy — "+
				"route approval state not preserved across policy changes",
				otherU1.Name, routePrefix, advertiser.Name)
		}

		// Verify: user2 peers don't see the advertiser at all
		// (so the route can't leak).
		for _, c := range u2Clients {
			if _, found := c.PeerByName(advertiser.Name); found {
				rt.Fatalf("BUG: user2 node %s still sees user1 advertiser %s under restrictive policy",
					c.Name, advertiser.Name)
			}

			// Also check no route leaking to any visible peer.
			nm := c.Netmap()
			if nm != nil {
				for _, p := range nm.Peers {
					for k := range p.AllowedIPs().Len() {
						if p.AllowedIPs().At(k) == routePrefix {
							hi := p.Hostinfo()

							peerName := "<unknown>"
							if hi.Valid() {
								peerName = hi.Hostname()
							}

							rt.Fatalf("BUG: user2 node %s sees route %s leaked via peer %s",
								c.Name, routePrefix, peerName)
						}
					}
				}
			}
		}

		// --- Switch back to allow-all ---
		allowAllPolicy := []byte(`{
			"acls": [
				{"action": "accept", "src": ["*"], "dst": ["*:*"]}
			]
		}`)

		h.ChangePolicy(t, allowAllPolicy)

		// Wait for full mesh.
		if !awaitPeerCounts(allClients,
			[]int{3, 3, 3, 3}, convergenceTimeout) {
			for _, c := range allClients {
				nm := c.Netmap()

				peerCount := 0
				if nm != nil {
					peerCount = len(nm.Peers)
				}

				rt.Logf("allow-all restore: %s has %d peers (names: %v)",
					c.Name, peerCount, c.PeerNames())
			}

			rt.Fatalf("allow-all policy did not restore full mesh")
		}

		// Verify: ALL clients (including user2) now see the route
		// in the advertiser's AllowedIPs again.
		for _, c := range allClients {
			if c == advertiser {
				continue
			}

			routeDeadline := time.After(convergenceTimeout)

			for !peerHasRoute(c, advertiser.Name, routePrefix) {
				select {
				case <-routeDeadline:
					nm := c.Netmap()
					if nm != nil {
						for _, p := range nm.Peers {
							hi := p.Hostinfo()
							if hi.Valid() && hi.Hostname() == advertiser.Name {
								var allowedIPs []netip.Prefix
								for k := range p.AllowedIPs().Len() {
									allowedIPs = append(allowedIPs, p.AllowedIPs().At(k))
								}

								rt.Logf("after allow-all restore: %s sees %s with AllowedIPs: %v",
									c.Name, advertiser.Name, allowedIPs)
							}
						}
					}

					rt.Fatalf("BUG: after restoring allow-all, client %s does not see route %s in %s's AllowedIPs",
						c.Name, routePrefix, advertiser.Name)
				case <-time.After(100 * time.Millisecond):
				}
			}
		}

		// Final symmetry check.
		for _, a := range allClients {
			for _, b := range allClients {
				if a == b {
					continue
				}

				_, aSeesB := a.PeerByName(b.Name)
				_, bSeesA := b.PeerByName(a.Name)

				if aSeesB != bSeesA {
					rt.Fatalf("final: asymmetric visibility: "+
						"%s sees %s = %v, %s sees %s = %v",
						a.Name, b.Name, aSeesB,
						b.Name, a.Name, bSeesA)
				}
			}
		}
	})
}
