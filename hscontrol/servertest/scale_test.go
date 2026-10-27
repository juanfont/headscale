package servertest

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go4.org/netipx"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/ipproto"
	"tailscale.com/types/logger"
	"tailscale.com/types/netmap"
	"tailscale.com/wgengine/filter"
)

const scaleDevicesPerUser = 10

type scaleCase struct {
	name          string
	policy        string
	taggedService bool
	ssh           bool
	peerCount     func(node, total int) int
	canSend       func(source, destination int) bool
}

// TestScale runs the same workloads at smoke-test and explicitly selected sizes.
// See README.md for large runs, resource constraints, and profiling commands.
func TestScale(t *testing.T) {
	nodes := 12

	if value, ok := os.LookupEnv("HEADSCALE_STRESS_NODES"); ok {
		var err error

		nodes, err = strconv.Atoi(value)
		require.NoError(t, err, "HEADSCALE_STRESS_NODES must be an integer")
		require.GreaterOrEqual(t, nodes, 2, "need at least two connected nodes")
	}

	personalPeers := func(node, total int) int {
		first := node / scaleDevicesPerUser * scaleDevicesPerUser
		return min(scaleDevicesPerUser, total-first) - 1
	}
	personalVisibility := func(node, peer int) bool {
		return node/scaleDevicesPerUser == peer/scaleDevicesPerUser
	}

	cases := []scaleCase{
		{
			name: "allow_all",
			policy: `{
				"grants": [{"src": ["*"], "dst": ["*"], "ip": ["tcp:443"]}]
			}`,
			peerCount: func(_, total int) int { return total - 1 },
			canSend:   func(_, _ int) bool { return true },
		},
		{
			name:      "isolated",
			policy:    `{"acls": []}`,
			peerCount: func(_, _ int) int { return 0 },
			canSend:   func(_, _ int) bool { return false },
		},
		{
			name: "personal_devices",
			policy: `{
				"grants": [{
					"src": ["autogroup:member"], "dst": ["autogroup:self"],
					"ip": ["tcp:443"]
				}]
			}`,
			peerCount: personalPeers,
			canSend:   personalVisibility,
		},
		{
			name: "shared_service",
			policy: `{
				"tagOwners": {"tag:service": ["scale-user-0@"]},
				"grants": [{
					"src": ["autogroup:member"], "dst": ["tag:service"],
					"ip": ["tcp:443"]
				}]
			}`,
			taggedService: true,
			peerCount: func(node, total int) int {
				if node == 0 {
					return total - 1
				}

				return 1
			},
			canSend: func(source, destination int) bool { return source != 0 && destination == 0 },
		},
		{
			name: "personal_ssh",
			policy: `{
				"grants": [{
					"src": ["autogroup:member"], "dst": ["autogroup:self"],
					"ip": ["tcp:22", "tcp:443"]
				}],
				"ssh": [{
					"action": "accept", "src": ["autogroup:member"],
					"dst": ["autogroup:self"], "users": ["root"]
				}]
			}`,
			ssh:       true,
			peerCount: personalPeers,
			canSend:   personalVisibility,
		},
	}

	t.Run(fmt.Sprintf("%d_nodes", nodes), func(t *testing.T) {
		// Run serially: each server and all its clients share this process.
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) { runScale(t, nodes, tc) })
		}
	})
}

// Discard client protocol chatter while keeping test failures and phase reports.
type quietScaleTB struct{ testing.TB }

func (quietScaleTB) Logf(string, ...any) {}

func runScale(t *testing.T, nodes int, tc scaleCase) {
	t.Helper()

	workers := min(4, runtime.GOMAXPROCS(0))

	opts := []ServerOption{WithBatcherWorkers(workers)}
	if _, largeRun := os.LookupEnv("HEADSCALE_STRESS_NODES"); !largeRun {
		opts = append(opts, WithNodeStoreBatchTimeout(10*time.Millisecond))
	}

	srv := NewServer(t, opts...)
	clients := make([]*TestClient, nodes)
	selfNodes := make([]tailcfg.NodeView, nodes)
	indices := make(map[tailcfg.NodeID]int, nodes)

	const convergenceTimeout = 2 * time.Minute

	t.Logf(
		"target_nodes=%d devices_per_user=%d workers=%d gomaxprocs=%d gomemlimit=%q go=%s",
		nodes,
		scaleDevicesPerUser,
		workers,
		runtime.GOMAXPROCS(0),
		os.Getenv("GOMEMLIMIT"),
		runtime.Version(),
	)

	phase := func(name string, work func()) {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)

		started := time.Now()
		defer func() {
			elapsed := time.Since(started)

			runtime.ReadMemStats(&after)

			peers := 0
			live := 0

			for _, c := range clients {
				if c != nil {
					peers += len(c.Peers())
					select {
					case <-c.pollDone:
					default:
						live++
					}
				}
			}

			t.Logf(
				"phase=%s elapsed=%s allocated_bytes=%d heap_bytes=%d gc_cycles=%d goroutines=%d registered_nodes=%d live_clients=%d peer_entries=%d",
				name,
				elapsed,
				after.TotalAlloc-before.TotalAlloc,
				after.HeapAlloc,
				after.NumGC-before.NumGC,
				runtime.NumGoroutine(),
				srv.State().ListNodes().Len(),
				live,
				peers,
			)
		}()

		work()
		checkScaleStreams(t, srv, clients, indices)
	}

	// A generation attribute distinguishes fresh policy delivery from old maps.
	setPolicy := func(policy, generation string) {
		var document map[string]any
		require.NoError(t, json.Unmarshal([]byte(policy), &document))
		document["nodeAttrs"] = []any{map[string]any{
			"target": []string{"*"}, "attr": []string{generation},
		}}
		data, err := json.Marshal(document)
		require.NoError(t, err)
		_, err = srv.State().SetPolicyInDB(string(data))
		require.NoError(t, err)
		changes, err := srv.State().ReloadPolicy()
		srv.App.Change(changes...)
		require.NoError(t, err)
	}

	waitForState := func(generation string, revoked bool, osMarker string) {
		deadline := time.Now().Add(convergenceTimeout)

		for i, c := range clients {
			wantPeers := tc.peerCount(i, nodes)
			if revoked {
				wantPeers = 0
			}

			c.WaitForCondition(
				t,
				fmt.Sprintf("%s: %d peers, OS=%q", generation, wantPeers, osMarker),
				time.Until(deadline),
				func(nm *netmap.NetworkMap) bool {
					if !nm.SelfNode.CapMap().Contains(nodecap.Cap(generation)) ||
						len(nm.Peers) != wantPeers {
						return false
					}

					hasSSH := nm.SSHPolicy != nil && len(nm.SSHPolicy.Rules) > 0
					if hasSSH != (tc.ssh && !revoked) {
						return false
					}

					if revoked && nm.PacketFilterRules.Len() != 0 {
						return false
					}

					return tc.peersMatch(nm, i, indices, osMarker)
				},
			)
			checkScalePacketFilter(t, tc, c.Netmap(), selfNodes, i, revoked)

			if tc.ssh && !revoked {
				checkScaleSSH(t, c.Netmap().SSHPolicy, selfNodes, i)
			}
		}
	}

	phase("enroll", func() {
		users := make([]*types.User, (nodes+scaleDevicesPerUser-1)/scaleDevicesPerUser)
		for i := range users {
			users[i] = srv.CreateUser(t, fmt.Sprintf("scale-user-%d", i))
		}

		setPolicy(tc.policy, "example.com/scale-initial")

		// Bound concurrent logins, and join every batch before checking results.
		for first := 0; first < nodes; first += 32 {
			var registrations sync.WaitGroup
			for i := first; i < min(first+32, nodes); i++ {
				registrations.Go(func() {
					opts := []ClientOption{
						WithUser(users[i/scaleDevicesPerUser]), WithoutNetmapHistory(),
					}
					if tc.taggedService && i == 0 {
						opts = append(opts, WithTags("tag:service"))
					}

					clients[i] = NewClient(quietScaleTB{t}, srv,
						fmt.Sprintf("scale-node-%05d", i), opts...)
				})
			}

			registrations.Wait()

			if t.Failed() {
				t.FailNow()
			}
		}

		deadline := time.Now().Add(convergenceTimeout)
		for i, c := range clients {
			c.WaitForCondition(t, "initial map", time.Until(deadline),
				func(nm *netmap.NetworkMap) bool { return nm.SelfNode.Valid() })
			id := c.Netmap().SelfNode.ID()
			selfNodes[i] = c.Netmap().SelfNode
			_, duplicate := indices[id]
			require.False(t, duplicate, "duplicate client node ID %d", id)
			indices[id] = i
		}

		require.Equal(t, nodes, srv.State().ListNodes().Len())
		waitForState("example.com/scale-initial", false, "")
	})

	// One sender per user, including the shared service, changes in each burst.
	for round := range 3 {
		marker := fmt.Sprintf("scale-os-%d", round)
		phase(fmt.Sprintf("update_burst_%d", round), func() {
			updateScaleClients(t, srv, clients, marker)
			waitForState("example.com/scale-initial", false, marker)
		})
	}

	phase("revoke_policy", func() {
		setPolicy(`{"acls": []}`, "example.com/scale-revoked")
		waitForState("example.com/scale-revoked", true, "")
	})
	phase("restore_policy", func() {
		setPolicy(tc.policy, "example.com/scale-restored")
		waitForState("example.com/scale-restored", false, "scale-os-2")
	})
	phase("reconnect_burst", func() {
		var reconnects sync.WaitGroup
		for i := 0; i < nodes; i += scaleDevicesPerUser {
			reconnects.Go(func() { clients[i].Reconnect(quietScaleTB{t}) })
		}

		reconnects.Wait()

		if t.Failed() {
			t.FailNow()
		}

		waitForState("example.com/scale-restored", false, "scale-os-2")
		setPolicy(tc.policy, "example.com/scale-reconnected")
		waitForState("example.com/scale-reconnected", false, "scale-os-2")
	})
}

func (tc scaleCase) peersMatch(
	nm *netmap.NetworkMap,
	viewer int,
	indices map[tailcfg.NodeID]int,
	osMarker string,
) bool {
	var previous tailcfg.NodeID

	for _, peer := range nm.Peers {
		j, ok := indices[peer.ID()]
		if !ok || j == viewer || (!tc.canSend(viewer, j) && !tc.canSend(j, viewer)) ||
			peer.ID() <= previous {
			return false
		}

		previous = peer.ID()

		online, known := peer.Online().GetOk()
		if !known || !online {
			return false
		}

		if osMarker != "" && j%scaleDevicesPerUser == 0 &&
			peer.Hostinfo().OS() != osMarker {
			return false
		}
	}

	return true
}

func updateScaleClients(
	t *testing.T,
	srv *TestServer,
	clients []*TestClient,
	marker string,
) {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancel()

	var senders sync.WaitGroup

	for i := 0; i < len(clients); i += scaleDevicesPerUser {
		c := clients[i]

		senders.Go(func() {
			c.Direct().SetHostinfo(&tailcfg.Hostinfo{
				Hostname: c.Name, BackendLogID: "servertest-" + c.Name, OS: marker,
			})
			assert.NoError(t, c.Direct().SendUpdate(ctx), c.Name)
		})
	}

	senders.Wait()

	if t.Failed() {
		t.FailNow()
	}

	for i := 0; i < len(clients); i += scaleDevicesPerUser {
		node, ok := srv.State().GetNodeByNodeKey(clients[i].Netmap().NodeKey)
		require.True(t, ok)
		require.Equal(t, marker, node.Hostinfo().OS(), clients[i].Name)
	}
}

// Probe a few sources per node instead of making the test itself all-pairs.
func checkScalePacketFilter(
	t *testing.T,
	tc scaleCase,
	nm *netmap.NetworkMap,
	selfNodes []tailcfg.NodeView,
	viewer int,
	revoked bool,
) {
	t.Helper()

	var localIPs netipx.IPSetBuilder
	for _, prefix := range nm.SelfNode.Addresses().All() {
		localIPs.AddPrefix(prefix)
	}

	local, err := localIPs.IPSet()
	require.NoError(t, err)

	packetFilter := filter.New(nm.PacketFilter, nil, local, nil, nil, logger.Discard)

	first := viewer / scaleDevicesPerUser * scaleDevicesPerUser
	groupSize := min(scaleDevicesPerUser, len(selfNodes)-first)

	sibling := first + (viewer-first+1)%groupSize
	for _, source := range []int{sibling, (first + scaleDevicesPerUser) % len(selfNodes), 0} {
		for family, dst := range nm.SelfNode.Addresses().All() {
			src := selfNodes[source].Addresses().At(family).Addr()

			want := filter.Drop
			if !revoked && tc.canSend(source, viewer) {
				want = filter.Accept
			}

			require.Equal(t, want, packetFilter.CheckTCP(src, dst.Addr(), 443),
				"%d -> %d TCP 443", selfNodes[source].ID(), selfNodes[viewer].ID())
			require.Equal(t, filter.Drop, packetFilter.CheckTCP(src, dst.Addr(), 80))
			require.Equal(
				t,
				filter.Drop,
				packetFilter.Check(src, dst.Addr(), 443, ipproto.UDP),
			)

			if tc.ssh {
				require.Equal(t, want, packetFilter.CheckTCP(src, dst.Addr(), 22))
			}
		}
	}
}

func checkScaleSSH(
	t *testing.T,
	policy *tailcfg.SSHPolicy,
	selfNodes []tailcfg.NodeView,
	viewer int,
) {
	t.Helper()

	require.NotNil(t, policy)
	require.Len(t, policy.Rules, 1)
	rule := policy.Rules[0]
	require.NotNil(t, rule.Action)
	require.True(t, rule.Action.Accept)
	require.False(t, rule.Action.Reject)
	require.Empty(t, rule.Action.HoldAndDelegate)
	require.Equal(t, map[string]string{"0": "", "root": "root"}, rule.SSHUsers)

	wantIPs := make(map[string]bool)

	first := viewer / scaleDevicesPerUser * scaleDevicesPerUser
	for _, node := range selfNodes[first:min(first+scaleDevicesPerUser, len(selfNodes))] {
		for _, prefix := range node.Addresses().All() {
			wantIPs[prefix.Addr().String()] = true
		}
	}

	require.Len(t, rule.Principals, len(wantIPs))

	for _, principal := range rule.Principals {
		require.False(t, principal.Any)
		require.Empty(t, principal.Node)
		require.Empty(t, principal.UserLogin)
		require.True(
			t,
			wantIPs[principal.NodeIP],
			"unexpected SSH source %s",
			principal.NodeIP,
		)
		delete(wantIPs, principal.NodeIP)
	}

	require.Empty(t, wantIPs)
}

func checkScaleStreams(
	t *testing.T,
	srv *TestServer,
	clients []*TestClient,
	indices map[tailcfg.NodeID]int,
) {
	t.Helper()

	require.Zero(t, srv.App.MapBatcher().WorkErrors(), "mapper work failed")
	connections := srv.App.MapBatcher().Debug()
	require.Len(t, connections, len(clients))

	for id, info := range connections {
		_, known := indices[id.NodeID()]
		require.True(t, known, "unexpected connected node %s", id)
		require.True(t, info.Connected, "node %s disconnected on server", id)
		require.Equal(t, 1, info.ActiveConnections, "node %s", id)
	}

	for _, c := range clients {
		require.NotNil(t, c, "client registration failed")

		select {
		case <-c.pollDone:
			t.Fatalf("%s: control stream exited", c.Name)
		default:
		}

		require.NotNil(t, c.Netmap(), c.Name)
		require.Empty(t, c.History(), "scale clients must not retain netmaps")
		require.Positive(t, c.UpdateCount(), c.Name)
	}
}

func TestClientNetmapHistory(t *testing.T) {
	for _, noHistory := range []bool{false, true} {
		t.Run(fmt.Sprintf("disabled=%v", noHistory), func(t *testing.T) {
			c := &TestClient{
				noHistory: noHistory,
				updates:   make(chan *netmap.NetworkMap, 1),
			}
			for range 3 {
				c.UpdateFullNetmap(&netmap.NetworkMap{})
			}

			require.Equal(t, 3, c.UpdateCount())
			require.NotNil(t, c.Netmap())

			if noHistory {
				require.Empty(t, c.History())
			} else {
				require.Len(t, c.History(), 3)
			}
		})
	}
}
