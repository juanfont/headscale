package notifier

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
)

type Notifier struct {
	l         sync.RWMutex
	nodes     map[types.NodeID]chan<- types.StateUpdate
	connected types.NodeConnectedMap
}

func NewNotifier() *Notifier {
	return &Notifier{
		nodes:     make(map[types.NodeID]chan<- types.StateUpdate),
		connected: make(types.NodeConnectedMap),
	}
}

func (n *Notifier) AddNode(nodeID types.NodeID, c chan<- types.StateUpdate) {
	log.Trace().Caller().Uint64("node.id", nodeID.Uint64()).Msg("acquiring lock to add node")
	defer log.Trace().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Msg("releasing lock to add node")

	n.l.Lock()
	defer n.l.Unlock()

	n.nodes[nodeID] = c
	n.connected[nodeID] = true

	log.Trace().
		Uint64("node.id", nodeID.Uint64()).
		Int("open_chans", len(n.nodes)).
		Msg("Added new channel")
}

func (n *Notifier) RemoveNode(nodeID types.NodeID) {
	log.Trace().Caller().Uint64("node.id", nodeID.Uint64()).Msg("acquiring lock to remove node")
	defer log.Trace().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Msg("releasing lock to remove node")

	n.l.Lock()
	defer n.l.Unlock()

	if len(n.nodes) == 0 {
		return
	}

	delete(n.nodes, nodeID)
	n.connected[nodeID] = false

	log.Trace().
		Uint64("node.id", nodeID.Uint64()).
		Int("open_chans", len(n.nodes)).
		Msg("Removed channel")
}

// IsConnected reports if a node is connected to headscale and has a
// poll session open.
func (n *Notifier) IsConnected(nodeID types.NodeID) bool {
	n.l.RLock()
	defer n.l.RUnlock()

	return n.connected[nodeID]
}

// IsLikelyConnected reports if a node is connected to headscale and has a
// poll session open, but doesnt lock, so might be wrong.
func (n *Notifier) IsLikelyConnected(nodeID types.NodeID) bool {
	return n.connected[nodeID]
}

// TODO(kradalby): This returns a pointer and can be dangerous.
func (n *Notifier) ConnectedMap() types.NodeConnectedMap {
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
	log.Trace().Caller().Str("type", update.Type.String()).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Str("type", update.Type.String()).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	if update.Type == types.StatePeerChangedPatch {
		log.Trace().Interface("update", update).Interface("online", n.connected).Msg("PATCH UPDATE SENT")
	}

	for nodeID, c := range n.nodes {
		if slices.Contains(ignoreNodeIDs, nodeID) {
			continue
		}

		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update not sent, context cancelled")

			return
		case c <- update:
			log.Trace().
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
		}
	}
}

func (n *Notifier) NotifyByMachineKey(
	ctx context.Context,
	update types.StateUpdate,
	nodeID types.NodeID,
) {
	log.Trace().Caller().Str("type", update.Type.String()).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Str("type", update.Type.String()).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	if c, ok := n.nodes[nodeID]; ok {
		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update not sent, context cancelled")

			return
		case c <- update:
			log.Trace().
				Uint64("node.id", nodeID.Uint64()).
				Any("origin", ctx.Value("origin")).
				Any("origin-hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
		}
	}
}

func (n *Notifier) String() string {
	n.l.RLock()
	defer n.l.RUnlock()

	str := []string{"Notifier, in map:\n"}

	for k, v := range n.nodes {
		str = append(str, fmt.Sprintf("\t%d: %v\n", k, v))
	}

	return strings.Join(str, "")
}
