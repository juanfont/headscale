package notifier

import (
	"context"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

var (
	debugDeadlock        = envknob.Bool("HEADSCALE_DEBUG_DEADLOCK")
	debugDeadlockTimeout = envknob.RegisterDuration("HEADSCALE_DEBUG_DEADLOCK_TIMEOUT")
)

func init() {
	deadlock.Opts.Disable = !debugDeadlock
	if debugDeadlock {
		deadlock.Opts.DeadlockTimeout = debugDeadlockTimeout()
		deadlock.Opts.PrintAllCurrentGoroutines = true
	}
}

type Notifier struct {
	l        deadlock.Mutex
	b        *batcher
	cfg      *types.Config
	closed   bool
	mbatcher *mapper.Batcher
}

func NewNotifier(cfg *types.Config, mbatch *mapper.Batcher) *Notifier {
	n := &Notifier{
		mbatcher: mbatch,
		cfg:      cfg,
		closed:   false,
	}
	b := newBatcher(cfg.Tuning.BatchChangeDelay, n)
	n.b = b

	go b.doWork()
	return n
}

// Close stops the batcher and closes all channels.
func (n *Notifier) Close() {
	notifierWaitersForLock.WithLabelValues("lock", "close").Inc()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitersForLock.WithLabelValues("lock", "close").Dec()

	n.closed = true
	n.b.close()
}

// safeCloseChannel closes a channel and panic recovers if already closed
func (n *Notifier) safeCloseChannel(nodeID types.NodeID, c chan<- types.StateUpdate) {
	defer func() {
		if r := recover(); r != nil {
			log.Error().
				Uint64("node.id", nodeID.Uint64()).
				Any("recover", r).
				Msg("recovered from panic when closing channel in Close()")
		}
	}()
	close(c)
}

func (n *Notifier) tracef(nID types.NodeID, msg string, args ...any) {
	log.Trace().
		Uint64("node.id", nID.Uint64()).Msgf(msg, args...)
}

// IsConnected reports if a node is connected to headscale and has a
// poll session open.
func (n *Notifier) IsConnected(nodeID types.NodeID) bool {
	return n.mbatcher.IsConnected(nodeID)
}

// IsLikelyConnected reports if a node is connected to headscale and has a
// poll session open, but doesn't lock, so might be wrong.
func (n *Notifier) IsLikelyConnected(nodeID types.NodeID) bool {
	return n.mbatcher.IsLikelyConnected(nodeID)
}

// LikelyConnectedMap returns a thread safe map of connected nodes
func (n *Notifier) LikelyConnectedMap() *xsync.MapOf[types.NodeID, bool] {
	return n.mbatcher.LikelyConnectedMap()
}

func (n *Notifier) NotifyAll(ctx context.Context, update types.StateUpdate) {
	n.NotifyWithIgnore(ctx, update)
}

func (n *Notifier) NotifyWithIgnore(
	ctx context.Context,
	update types.StateUpdate,
	ignoreNodeIDs ...types.NodeID,
) {
	if n.closed {
		return
	}

	notifierUpdateReceived.WithLabelValues(update.Type.String(), types.NotifyOriginKey.Value(ctx)).Inc()
	n.b.addOrPassthrough(update)
}

func (n *Notifier) NotifyByNodeID(
	ctx context.Context,
	update types.StateUpdate,
	nodeID types.NodeID,
) {
	n.mbatcher.AddWork(&mapper.ChangeWork{
		NodeID: &nodeID,
		Update: update,
	})
}

func (n *Notifier) sendAll(update types.StateUpdate) {
	n.mbatcher.AddWork(&mapper.ChangeWork{
		Update: update,
	})
}

func (n *Notifier) String() string {
	notifierWaitersForLock.WithLabelValues("lock", "string").Inc()
	n.l.Lock()
	defer n.l.Unlock()
	notifierWaitersForLock.WithLabelValues("lock", "string").Dec()

	var b strings.Builder

	var keys []types.NodeID
	sort.Slice(keys, func(i, j int) bool {
		return keys[i] < keys[j]
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
			update := types.UpdatePeerChanged(changedNodes...)

			b.n.sendAll(update)
		}

		if len(patches) > 0 {
			patchUpdate := types.UpdatePeerPatch(patches...)

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
// and override any field that has changed.
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
