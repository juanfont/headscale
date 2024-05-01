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
	// TODO(kradalby): clean this up
	go b.doWork()
	return n
}

// Close stops the batcher inside the notifier.
func (n *Notifier) Close() {
	n.b.close()
}

func (n *Notifier) AddNode(nodeID types.NodeID, c chan<- types.StateUpdate) {
	log.Trace().Caller().Uint64("node.id", nodeID.Uint64()).Msg("acquiring lock to add node")
	defer log.Trace().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Msg("releasing lock to add node")

	start := time.Now()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitForLock.WithLabelValues("add").Observe(time.Since(start).Seconds())

	n.nodes[nodeID] = c
	n.connected.Store(nodeID, true)

	log.Trace().
		Uint64("node.id", nodeID.Uint64()).
		Int("open_chans", len(n.nodes)).
		Msg("Added new channel")
	notifierNodeUpdateChans.Inc()
}

func (n *Notifier) RemoveNode(nodeID types.NodeID) {
	log.Trace().Caller().Uint64("node.id", nodeID.Uint64()).Msg("acquiring lock to remove node")
	defer log.Trace().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Msg("releasing lock to remove node")

	start := time.Now()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitForLock.WithLabelValues("remove").Observe(time.Since(start).Seconds())

	if len(n.nodes) == 0 {
		return
	}

	delete(n.nodes, nodeID)
	n.connected.Store(nodeID, false)

	log.Trace().
		Uint64("node.id", nodeID.Uint64()).
		Int("open_chans", len(n.nodes)).
		Msg("Removed channel")
	notifierNodeUpdateChans.Dec()
}

// IsConnected reports if a node is connected to headscale and has a
// poll session open.
func (n *Notifier) IsConnected(nodeID types.NodeID) bool {
	n.l.RLock()
	defer n.l.RUnlock()

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
	log.Trace().Caller().Str("type", update.Type.String()).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Str("type", update.Type.String()).
		Msg("releasing lock, finished notifying")

	start := time.Now()
	n.l.RLock()
	defer n.l.RUnlock()
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
			notifierUpdateSent.WithLabelValues("cancelled", update.Type.String(), types.NotifyOriginKey.Value(ctx)).Inc()

			return
		case c <- update:
			log.Trace().
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
			notifierUpdateSent.WithLabelValues("ok", update.Type.String(), types.NotifyOriginKey.Value(ctx)).Inc()
		}
	}
}

func (n *Notifier) sendAll(update types.StateUpdate) {
	start := time.Now()
	n.l.RLock()
	defer n.l.RUnlock()
	notifierWaitForLock.WithLabelValues("send-all").Observe(time.Since(start).Seconds())

	for _, c := range n.nodes {
		c <- update
		notifierUpdateSent.WithLabelValues("ok", update.Type.String(), "send-all").Inc()
	}
}

func (n *Notifier) String() string {
	n.l.RLock()
	defer n.l.RUnlock()

	var b strings.Builder
	b.WriteString("chans:\n")

	for k, v := range n.nodes {
		fmt.Fprintf(&b, "\t%d: %p\n", k, v)
	}

	b.WriteString("\n")
	b.WriteString("connected:\n")

	n.connected.Range(func(k types.NodeID, v bool) bool {
		fmt.Fprintf(&b, "\t%d: %t\n", k, v)
		return true
	})

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
	b.mu.Lock()
	defer b.mu.Unlock()

	switch update.Type {
	case types.StatePeerChanged:
		b.changedNodeIDs.Add(update.ChangeNodes...)
		b.nodesChanged = true

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

	default:
		b.n.sendAll(update)
	}
}

// flush sends all the accumulated patches to all
// nodes in the notifier.
func (b *batcher) flush() {
	b.mu.Lock()
	defer b.mu.Unlock()

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
		b.nodesChanged = false
		b.patches = make(map[types.NodeID]tailcfg.PeerChange, len(b.patches))
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

	if newPatch.Capabilities != nil {
		currPatch.Capabilities = newPatch.Capabilities
	}
}
