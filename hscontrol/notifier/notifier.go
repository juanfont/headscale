package notifier

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/rs/zerolog/log"
)

type Notifier struct {
	l         sync.RWMutex
	nodes     map[types.NodeID]chan<- types.StateUpdate
	connected *xsync.MapOf[types.NodeID, bool]
}

func NewNotifier() *Notifier {
	return &Notifier{
		nodes:     make(map[types.NodeID]chan<- types.StateUpdate),
		connected: xsync.NewMapOf[types.NodeID, bool](),
	}
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
	for nodeID := range n.nodes {
		if slices.Contains(ignoreNodeIDs, nodeID) {
			continue
		}

		n.NotifyByNodeID(ctx, update, nodeID)
	}
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
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update not sent, context cancelled")
			notifierUpdateSent.WithLabelValues("cancelled", update.Type.String()).Inc()

			return
		case c <- update:
			log.Trace().
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
			notifierUpdateSent.WithLabelValues("ok", update.Type.String()).Inc()
		}
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
