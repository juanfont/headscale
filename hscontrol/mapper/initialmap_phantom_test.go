package mapper

import (
	"errors"
	"fmt"
	"reflect"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
)

// TestUnreadyConnectionDefersBroadcastsUntilInitialMap pins the ordering fix
// for the "initial MapResponse lacked Node" client failure: a connection
// registered by [Batcher.AddNode] but still waiting for its initial map must
// not receive broadcast deltas — a delta as the stream's first frame makes the
// Tailscale client tear down the poll. The change is requeued, not dropped,
// because the in-flight initial map may have been generated from a snapshot
// older than the change.
func TestUnreadyConnectionDefersBroadcastsUntilInitialMap(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	batcher := testData.Batcher.Batcher
	peerNode := &testData.Nodes[0]
	targetNode := &testData.Nodes[1]

	// Register the target's connection by hand in the state AddNode leaves it
	// in between registering the channel and delivering the initial map.
	nc := newMultiChannelNodeConn(targetNode.n.ID, batcher.mapper)
	entry := &connectionEntry{
		done:    make(chan struct{}),
		id:      "test-unready",
		c:       targetNode.ch,
		version: tailcfg.CapabilityVersion(100),
		created: time.Now(),
	}
	entry.pendingInitial.Store(true)
	nc.addConnection(entry)
	batcher.nodes.Store(targetNode.n.ID, nc)

	// A broadcast lands while the initial map is still in flight: nothing may
	// reach the channel, and the caller must be told to retry
	// (the worker prepends such changes back onto pending).
	retryChange := change.NodeAdded(peerNode.n.ID)

	err := nc.change(retryChange)
	if !errors.Is(err, errNoReadyConnections) {
		t.Fatalf("change on unready connection: want errNoReadyConnections, got %v", err)
	}

	select {
	case resp := <-targetNode.ch:
		t.Fatalf("unready connection received a frame before its initial map: %+v", resp)
	default:
	}

	// Once the initial map is delivered, the retried change goes out.
	entry.pendingInitial.Store(false)

	err = nc.change(retryChange)
	if err != nil {
		t.Fatalf("change on ready connection: %v", err)
	}

	select {
	case resp := <-targetNode.ch:
		if len(resp.PeersChanged) == 0 {
			t.Fatalf("expected PeersChanged delta after readiness, got %+v", resp)
		}
	default:
		t.Fatal("ready connection did not receive the retried change")
	}
}

// TestUnreadyConnectionBesideReadyOneHoldsBroadcasts pins that a node's change
// reaches none of its streams while one of them still awaits its initial map,
// which may predate the change. Sent to the ready stream alone, the change
// would count as delivered and never reach the new one.
func TestUnreadyConnectionBesideReadyOneHoldsBroadcasts(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(
		t,
		NewBatcherAndMapper,
		1,
		2,
		normalBufferSize,
	)
	defer cleanup()

	batcher := testData.Batcher.Batcher
	peerNode := &testData.Nodes[0]
	targetNode := &testData.Nodes[1]

	nc := newMultiChannelNodeConn(targetNode.n.ID, batcher.mapper)
	nc.addConnection(makeConnectionEntry("test-ready", targetNode.ch))

	pendingCh := make(chan *tailcfg.MapResponse, normalBufferSize)
	pending := makeConnectionEntry("test-unready", pendingCh)
	pending.pendingInitial.Store(true)
	nc.addConnection(pending)
	batcher.nodes.Store(targetNode.n.ID, nc)

	retryChange := change.NodeAdded(peerNode.n.ID)

	err := nc.change(retryChange)
	if !errors.Is(err, errNoReadyConnections) {
		t.Fatalf(
			"change with a connection awaiting its initial map: want errNoReadyConnections, got %v",
			err,
		)
	}

	for name, ch := range map[string]chan *tailcfg.MapResponse{"ready": targetNode.ch, "unready": pendingCh} {
		select {
		case resp := <-ch:
			t.Fatalf(
				"%s connection received a frame while a stream awaits its initial map: %+v",
				name,
				resp,
			)
		default:
		}
	}

	pending.pendingInitial.Store(false)

	err = nc.change(retryChange)
	if err != nil {
		t.Fatalf("change on ready connections: %v", err)
	}

	for name, ch := range map[string]chan *tailcfg.MapResponse{"ready": targetNode.ch, "new": pendingCh} {
		select {
		case resp := <-ch:
			if len(resp.PeersChanged) == 0 {
				t.Fatalf("%s connection: expected PeersChanged delta, got %+v",
					name, resp)
			}
		default:
			t.Fatalf("%s connection did not receive the retried change", name)
		}
	}
}

// onlineRecorder keeps the peer online states a stream receives, in order.
type onlineRecorder struct {
	mu  sync.Mutex
	got []string
}

func (r *onlineRecorder) record(resp *tailcfg.MapResponse) {
	r.mu.Lock()
	defer r.mu.Unlock()

	for _, p := range resp.PeersChangedPatch {
		if p.Online != nil {
			r.got = append(r.got, fmt.Sprintf("%d:%t", p.NodeID, *p.Online))
		}
	}
}

func (r *onlineRecorder) states() []string {
	r.mu.Lock()
	defer r.mu.Unlock()

	return slices.Clone(r.got)
}

// TestHeldChangesKeepOrderWhenStreamTurnsReady reconnects a node mid-bundle:
// its new stream turns ready while the bundle's first change is being sent to
// the node's older streams. Every stream must get every change once, in order,
// and end on the newest state. A change of another kind sits between the two
// peer changes, so the bundle keeps them as separate changes.
func TestHeldChangesKeepOrderWhenStreamTurnsReady(t *testing.T) {
	tests := []struct {
		name   string
		bundle func(p, q types.NodeID) []change.Change
		want   func(p, q types.NodeID) []string
	}{
		{
			name: "online_then_offline",
			bundle: func(p, _ types.NodeID) []change.Change {
				return []change.Change{
					change.NodeOnline(p), change.DERPMap(), change.NodeOffline(p, time.Time{}),
				}
			},
			want: func(p, _ types.NodeID) []string {
				return []string{fmt.Sprintf("%d:true", p), fmt.Sprintf("%d:false", p)}
			},
		},
		{
			name: "two_peers_online",
			bundle: func(p, q types.NodeID) []change.Change {
				return []change.Change{
					change.NodeOnline(p), change.DERPMap(), change.NodeOnline(q),
				}
			},
			want: func(p, q types.NodeID) []string {
				return []string{fmt.Sprintf("%d:true", p), fmt.Sprintf("%d:true", q)}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(
				t,
				NewBatcherAndMapper,
				1,
				3,
				normalBufferSize,
			)
			defer cleanup()

			batcher := testData.Batcher.Batcher
			p, q, target := testData.Nodes[0].n.ID, testData.Nodes[1].n.ID, testData.Nodes[2].n.ID

			// Two older streams, unbuffered so a send blocks until it is read,
			// and the new one, still awaiting its initial map.
			firstCh := make(chan *tailcfg.MapResponse)
			secondCh := make(chan *tailcfg.MapResponse)
			newCh := make(chan *tailcfg.MapResponse, normalBufferSize)
			fresh := makeConnectionEntry("new", newCh)
			fresh.pendingInitial.Store(true)

			nc := newMultiChannelNodeConn(target, batcher.mapper)
			nc.addConnection(makeConnectionEntry("first", firstCh))
			nc.addConnection(makeConnectionEntry("second", secondCh))
			nc.addConnection(fresh)
			batcher.nodes.Store(target, nc)

			// The new stream's initial map goes out once the first stream
			// takes a frame, so while the second one waits for its own; or a
			// little later if no frame is sent first.
			var once sync.Once

			ready := make(chan struct{})
			markReady := func() {
				once.Do(func() {
					fresh.pendingInitial.Store(false)
					close(ready)
				})
			}

			timer := time.AfterFunc(200*time.Millisecond, markReady)
			defer timer.Stop()

			var firstGot, secondGot, newGot onlineRecorder

			stop := make(chan struct{})
			defer close(stop)

			read := func(ch <-chan *tailcfg.MapResponse, r *onlineRecorder, onFrame func()) {
				for {
					select {
					case resp := <-ch:
						onFrame()
						r.record(resp)
					case <-stop:
						return
					}
				}
			}

			go read(firstCh, &firstGot, markReady)
			go read(newCh, &newGot, func() {})
			go func() {
				select {
				case <-ready:
					read(secondCh, &secondGot, func() {})
				case <-stop:
				}
			}()

			batcher.AddWork(tt.bundle(p, q)...)

			want := tt.want(p, q)
			streams := map[string]*onlineRecorder{
				"first":  &firstGot,
				"second": &secondGot,
				"new":    &newGot,
			}

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				for name, r := range streams {
					assert.Len(c, r.states(), len(want), name)
				}
			}, 5*time.Second, 10*time.Millisecond)

			assert.Never(t, func() bool {
				for _, r := range streams {
					if len(r.states()) > len(want) {
						return true
					}
				}

				return false
			}, 100*time.Millisecond, 10*time.Millisecond, "no duplicate or late frame follows")

			for name, r := range streams {
				assert.Equal(t, want, r.states(), "%s stream", name)
			}
		})
	}
}

// TestSyncInitialMapNoPhantomPeersOnTimeout ensures the synchronous initial-map
// path does not record peers as sent until the map is actually delivered. When
// the AddNode channel send times out, the client received nothing, so
// lastSentPeers must stay empty; otherwise future computePeerDiff calculations
// miss peer additions or removals after reconnect.
func TestSyncInitialMapNoPhantomPeersOnTimeout(t *testing.T) {
	testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 2, normalBufferSize)
	defer cleanup()

	batcher := testData.Batcher.Batcher
	state := testData.State

	peerNode := &testData.Nodes[0]
	targetNode := &testData.Nodes[1]

	state.Connect(peerNode.n.ID)

	err := batcher.AddNode(peerNode.n.ID, peerNode.ch, tailcfg.CapabilityVersion(100), nil)
	if err != nil {
		t.Fatalf("adding peer node: %v", err)
	}

	go func() {
		for range peerNode.ch {
		}
	}()

	state.Connect(targetNode.n.ID)

	// Unbuffered channel that nobody reads: AddNode blocks on the initial-map
	// send and times out.
	unreadCh := make(chan *tailcfg.MapResponse)

	err = batcher.AddNode(targetNode.n.ID, unreadCh, tailcfg.CapabilityVersion(100), nil)
	if err == nil {
		t.Fatal("expected initial-map send timeout error, got nil")
	}

	nc, exists := batcher.nodes.Load(targetNode.n.ID)
	if !exists || nc == nil {
		t.Fatalf("expected node %d to be retained in b.nodes", targetNode.n.ID)
	}

	if nc.hasActiveConnections() {
		t.Fatalf("expected node %d to have no active connections after timeout", targetNode.n.ID)
	}

	var phantom []tailcfg.NodeID

	nc.lastSentPeers.Range(func(id tailcfg.NodeID, _ struct{}) bool {
		phantom = append(phantom, id)
		return true
	})

	if len(phantom) != 0 {
		t.Errorf("lastSentPeers must be empty after a failed initial-map delivery, got %d: %v",
			len(phantom), phantom)
	}
}

// TestInitialMapCarriesDebugConfigOnEveryStream pins that the logtail
// instruction reaches every client stream. A client applies
// [tailcfg.Debug.DisableLogTail] only while the process lives, so every
// AddNode's first frame (a fresh process or a second connection alike) has to
// carry it; a later non-full frame must not.
func TestInitialMapCarriesDebugConfigOnEveryStream(t *testing.T) {
	for _, tt := range []struct {
		name    string
		logTail bool
		want    *tailcfg.Debug
	}{
		{"logtail_disabled", false, &tailcfg.Debug{DisableLogTail: true}},
		{"logtail_enabled", true, nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			testData, cleanup := setupBatcherWithTestData(t, NewBatcherAndMapper, 1, 3, normalBufferSize)
			defer cleanup()

			// Set before any AddNode queues work, so no worker reads it concurrently.
			testData.Config.LogTail.Enabled = tt.logTail

			batcher := testData.Batcher.Batcher
			capVer := tailcfg.CapabilityVersion(100)

			firstFrame := func(t *testing.T, ch chan *tailcfg.MapResponse) *tailcfg.MapResponse {
				t.Helper()

				select {
				case resp := <-ch:
					return resp
				case <-time.After(5 * time.Second):
					t.Fatal("no initial map")

					return nil
				}
			}

			for i := range testData.Nodes {
				n := &testData.Nodes[i]
				testData.State.Connect(n.n.ID)

				err := batcher.AddNode(n.n.ID, n.ch, capVer, nil)
				if err != nil {
					t.Fatalf("AddNode(%d): %v", n.n.ID, err)
				}

				resp := firstFrame(t, n.ch)
				if resp.Node == nil {
					t.Fatalf("node %d: first frame lacks self node", n.n.ID)
				}

				if !reflect.DeepEqual(tt.want, resp.Debug) {
					t.Errorf("node %d initial map Debug = %+v, want %+v", n.n.ID, resp.Debug, tt.want)
				}
			}

			// A second stream for an already-connected node gets its own full map.
			second := make(chan *tailcfg.MapResponse, normalBufferSize)

			err := batcher.AddNode(testData.Nodes[0].n.ID, second, capVer, nil)
			if err != nil {
				t.Fatalf("AddNode second stream: %v", err)
			}

			if resp := firstFrame(t, second); !reflect.DeepEqual(tt.want, resp.Debug) {
				t.Errorf("second stream initial map Debug = %+v, want %+v", resp.Debug, tt.want)
			}

			batcher.AddWork(change.DERPMap())

			for i := range testData.Nodes {
				n := &testData.Nodes[i]

				for {
					resp := firstFrame(t, n.ch)
					if resp.DERPMap == nil {
						continue
					}

					if resp.Debug != nil {
						t.Errorf("node %d DERP frame carries Debug %+v", n.n.ID, resp.Debug)
					}

					break
				}
			}
		})
	}
}
