package notifier

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

type Notifier struct {
	l         sync.RWMutex
	nodes     map[types.NodeID]chan<- types.StateUpdate
	connected *xsync.MapOf[types.NodeID, bool]
	b         *batcher
}

func NewNotifier(cfg *types.Config) *Notifier {
	n := &Notifier{
		nodes:     make(map[types.NodeID]chan<- types.StateUpdate),
		connected: xsync.NewMapOf[types.NodeID, bool](),
	}
	b := newBatcher(cfg.Tuning.BatchChangeDelay, n)
	n.b = b

	go b.doWork()
	return n
}

// Close stops the batcher inside the notifier.
func (n *Notifier) Close() {
	n.b.close()
}

func (n *Notifier) tracef(nID types.NodeID, msg string, args ...any) {
	log.Trace().
		Uint64("node.id", nID.Uint64()).
		Int("open_chans", len(n.nodes)).Msgf(msg, args...)
}

func (n *Notifier) AddNode(nodeID types.NodeID, c chan<- types.StateUpdate) {
	start := time.Now()
	notifierWaitersForLock.WithLabelValues("lock", "add").Inc()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitersForLock.WithLabelValues("lock", "add").Dec()
	notifierWaitForLock.WithLabelValues("add").Observe(time.Since(start).Seconds())

	// If a channel exists, it means the node has opened a new
	// connection. Close the old channel and replace it.
	if curr, ok := n.nodes[nodeID]; ok {
		n.tracef(nodeID, "channel present, closing and replacing")
		close(curr)
	}

	n.nodes[nodeID] = c
	n.connected.Store(nodeID, true)

	n.tracef(nodeID, "added new channel")
	notifierNodeUpdateChans.Inc()
}

// RemoveNode removes a node and a given channel from the notifier.
// It checks that the channel is the same as currently being updated
// and ignores the removal if it is not.
// RemoveNode reports if the node/chan was removed.
func (n *Notifier) RemoveNode(nodeID types.NodeID, c chan<- types.StateUpdate) bool {
	start := time.Now()
	notifierWaitersForLock.WithLabelValues("lock", "remove").Inc()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitersForLock.WithLabelValues("lock", "remove").Dec()
	notifierWaitForLock.WithLabelValues("remove").Observe(time.Since(start).Seconds())

	if len(n.nodes) == 0 {
		return true
	}

	// If the channel exist, but it does not belong
	// to the caller, ignore.
	if curr, ok := n.nodes[nodeID]; ok {
		if curr != c {
			n.tracef(nodeID, "channel has been replaced, not removing")
			return false
		}
	}

	delete(n.nodes, nodeID)
	n.connected.Store(nodeID, false)

	n.tracef(nodeID, "removed channel")
	notifierNodeUpdateChans.Dec()

	return true
}

// IsConnected reports if a node is connected to headscale and has a
// poll session open.
func (n *Notifier) IsConnected(nodeID types.NodeID) bool {
	notifierWaitersForLock.WithLabelValues("rlock", "conncheck").Inc()
	n.l.RLock()
	defer n.l.RUnlock()
	notifierWaitersForLock.WithLabelValues("rlock", "conncheck").Dec()

	if val, ok := n.connected.Load(nodeID); ok {
		return val
	}
	return false
}

// IsLikelyConnected reports if a node is connected to headscale and has a
// poll session open, but doesnt lock, so might be wrong.
func (n *Notifier) IsLikelyConnected(nodeID types.NodeID) bool {
	if val, ok := n.connected.Load(nodeID); ok {
		return val
	}
	return false
}

func (n *Notifier) LikelyConnectedMap() *xsync.MapOf[types.NodeID, bool] {
	return n.connected
}

func (n *Notifier) NotifyAll(ctx context.Context, update types.StateUpdate) {
	n.NotifyWithIgnore(ctx, update)
}

func (n *Notifier) NotifyWithIgnore(
	ctx context.Context,
	update types.StateUpdate,
	ignoreNodeIDs ...types.NodeID,
) {
	notifierUpdateReceived.WithLabelValues(update.Type.String(), types.NotifyOriginKey.Value(ctx)).Inc()
	n.b.addOrPassthrough(update)
}

func (n *Notifier) NotifyByNodeID(
	ctx context.Context,
	update types.StateUpdate,
	nodeID types.NodeID,
) {
	start := time.Now()
	notifierWaitersForLock.WithLabelValues("rlock", "notify").Inc()
	n.l.RLock()
	defer n.l.RUnlock()
	notifierWaitersForLock.WithLabelValues("rlock", "notify").Dec()
	notifierWaitForLock.WithLabelValues("notify").Observe(time.Since(start).Seconds())

	if c, ok := n.nodes[nodeID]; ok {
		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", types.NotifyOriginKey.Value(ctx)).
				Any("origin-hostname", types.NotifyHostnameKey.Value(ctx)).
				Msgf("update not sent, context cancelled")
			notifierUpdateSent.WithLabelValues("cancelled", update.Type.String(), types.NotifyOriginKey.Value(ctx), nodeID.String()).Inc()

			return
		case c <- update:
			n.tracef(nodeID, "update successfully sent on chan, origin: %s, origin-hostname: %s", ctx.Value("origin"), ctx.Value("hostname"))
			notifierUpdateSent.WithLabelValues("ok", update.Type.String(), types.NotifyOriginKey.Value(ctx), nodeID.String()).Inc()
		}
	}
}

func (n *Notifier) sendAll(update types.StateUpdate) {
	start := time.Now()
	notifierWaitersForLock.WithLabelValues("rlock", "send-all").Inc()
	n.l.RLock()
	defer n.l.RUnlock()
	notifierWaitersForLock.WithLabelValues("rlock", "send-all").Dec()
	notifierWaitForLock.WithLabelValues("send-all").Observe(time.Since(start).Seconds())

	for id, c := range n.nodes {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
		defer cancel()
		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Uint64("node.id", id.Uint64()).
				Msgf("update not sent, context cancelled")
			notifierUpdateSent.WithLabelValues("cancelled", update.Type.String(), "send-all", id.String()).Inc()

			return
		case c <- update:
			notifierUpdateSent.WithLabelValues("ok", update.Type.String(), "send-all", id.String()).Inc()
		}
	}
}

func (n *Notifier) String() string {
	notifierWaitersForLock.WithLabelValues("rlock", "string").Inc()
	n.l.RLock()
	defer n.l.RUnlock()
	notifierWaitersForLock.WithLabelValues("rlock", "string").Dec()

	var b strings.Builder
	fmt.Fprintf(&b, "chans (%d):\n", len(n.nodes))

	var keys []types.NodeID
	n.connected.Range(func(key types.NodeID, value bool) bool {
		keys = append(keys, key)
		return true
	})
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
	})

	for _, key := range keys {
		fmt.Fprintf(&b, "\t%d: %p\n", key, n.nodes[key])
	}

	b.WriteString("\n")
	fmt.Fprintf(&b, "connected (%d):\n", len(n.nodes))

	for _, key := range keys {
		val, _ := n.connected.Load(key)
		fmt.Fprintf(&b, "\t%d: %t\n", key, val)
	}

	return b.String()
}

type batcher struct {
	tick *time.Ticker

	mu sync.Mutex

	cancelCh chan struct{}

	changedNodeIDs set.Slice[types.NodeID]
	nodesChanged   bool
	patches        map[types.NodeID]tailcfg.PeerChange
	patchesChanged bool

	n *Notifier
}

func newBatcher(batchTime time.Duration, n *Notifier) *batcher {
	return &batcher{
		tick:     time.NewTicker(batchTime),
		cancelCh: make(chan struct{}),
		patches:  make(map[types.NodeID]tailcfg.PeerChange),
		n:        n,
	}

}

func (b *batcher) close() {
	b.cancelCh <- struct{}{}
}

// addOrPassthrough adds the update to the batcher, if it is not a
// type that is currently batched, it will be sent immediately.
func (b *batcher) addOrPassthrough(update types.StateUpdate) {
	notifierBatcherWaitersForLock.WithLabelValues("lock", "add").Inc()
	b.mu.Lock()
	defer b.mu.Unlock()
	notifierBatcherWaitersForLock.WithLabelValues("lock", "add").Dec()

	switch update.Type {
	case types.StatePeerChanged:
		b.changedNodeIDs.Add(update.ChangeNodes...)
		b.nodesChanged = true
		notifierBatcherChanges.WithLabelValues().Set(float64(b.changedNodeIDs.Len()))

	case types.StatePeerChangedPatch:
		for _, newPatch := range update.ChangePatches {
			if curr, ok := b.patches[types.NodeID(newPatch.NodeID)]; ok {
				overwritePatch(&curr, newPatch)
				b.patches[types.NodeID(newPatch.NodeID)] = curr
			} else {
				b.patches[types.NodeID(newPatch.NodeID)] = *newPatch
			}
		}
		b.patchesChanged = true
		notifierBatcherPatches.WithLabelValues().Set(float64(len(b.patches)))

	default:
		b.n.sendAll(update)
	}
}

// flush sends all the accumulated patches to all
// nodes in the notifier.
func (b *batcher) flush() {
	notifierBatcherWaitersForLock.WithLabelValues("lock", "flush").Inc()
	b.mu.Lock()
	defer b.mu.Unlock()
	notifierBatcherWaitersForLock.WithLabelValues("lock", "flush").Dec()

	if b.nodesChanged || b.patchesChanged {
		var patches []*tailcfg.PeerChange
		// If a node is getting a full update from a change
		// node update, then the patch can be dropped.
		for nodeID, patch := range b.patches {
			if b.changedNodeIDs.Contains(nodeID) {
				delete(b.patches, nodeID)
			} else {
				patches = append(patches, &patch)
			}
		}

		changedNodes := b.changedNodeIDs.Slice().AsSlice()
		sort.Slice(changedNodes, func(i, j int) bool {
			return changedNodes[i] < changedNodes[j]
		})

		if b.changedNodeIDs.Slice().Len() > 0 {
			update := types.StateUpdate{
				Type:        types.StatePeerChanged,
				ChangeNodes: changedNodes,
			}

			b.n.sendAll(update)
		}

		if len(patches) > 0 {
			patchUpdate := types.StateUpdate{
				Type:          types.StatePeerChangedPatch,
				ChangePatches: patches,
			}

			b.n.sendAll(patchUpdate)
		}

		b.changedNodeIDs = set.Slice[types.NodeID]{}
		notifierBatcherChanges.WithLabelValues().Set(0)
		b.nodesChanged = false
		b.patches = make(map[types.NodeID]tailcfg.PeerChange, len(b.patches))
		notifierBatcherPatches.WithLabelValues().Set(0)
		b.patchesChanged = false
	}
}

func (b *batcher) doWork() {
	for {
		select {
		case <-b.cancelCh:
			return
		case <-b.tick.C:
			b.flush()
		}
	}
}

// overwritePatch takes the current patch and a newer patch
// and override any field that has changed
func overwritePatch(currPatch, newPatch *tailcfg.PeerChange) {
	if newPatch.DERPRegion != 0 {
		currPatch.DERPRegion = newPatch.DERPRegion
	}

	if newPatch.Cap != 0 {
		currPatch.Cap = newPatch.Cap
	}

	if newPatch.CapMap != nil {
		currPatch.CapMap = newPatch.CapMap
	}

	if newPatch.Endpoints != nil {
		currPatch.Endpoints = newPatch.Endpoints
	}

	if newPatch.Key != nil {
		currPatch.Key = newPatch.Key
	}

	if newPatch.KeySignature != nil {
		currPatch.KeySignature = newPatch.KeySignature
	}

	if newPatch.DiscoKey != nil {
		currPatch.DiscoKey = newPatch.DiscoKey
	}

	if newPatch.Online != nil {
		currPatch.Online = newPatch.Online
	}

	if newPatch.LastSeen != nil {
		currPatch.LastSeen = newPatch.LastSeen
	}

	if newPatch.KeyExpiry != nil {
		currPatch.KeyExpiry = newPatch.KeyExpiry
	}
}
