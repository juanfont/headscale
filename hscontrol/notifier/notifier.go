package notifier

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

type Notifier struct {
	l         sync.RWMutex
	nodes     map[string]chan<- types.StateUpdate
	connected map[key.MachinePublic]bool
}

func NewNotifier() *Notifier {
	return &Notifier{
		nodes:     make(map[string]chan<- types.StateUpdate),
		connected: make(map[key.MachinePublic]bool),
	}
}

func (n *Notifier) AddNode(machineKey key.MachinePublic, c chan<- types.StateUpdate) {
	log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("acquiring lock to add node")
	defer log.Trace().
		Caller().
		Str("key", machineKey.ShortString()).
		Msg("releasing lock to add node")

	n.l.Lock()
	defer n.l.Unlock()

	n.nodes[machineKey.String()] = c
	n.connected[machineKey] = true

	log.Trace().
		Str("machine_key", machineKey.ShortString()).
		Int("open_chans", len(n.nodes)).
		Msg("Added new channel")
}

func (n *Notifier) RemoveNode(machineKey key.MachinePublic) {
	log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("acquiring lock to remove node")
	defer log.Trace().
		Caller().
		Str("key", machineKey.ShortString()).
		Msg("releasing lock to remove node")

	n.l.Lock()
	defer n.l.Unlock()

	if len(n.nodes) == 0 {
		return
	}

	delete(n.nodes, machineKey.String())
	n.connected[machineKey] = false

	log.Trace().
		Str("machine_key", machineKey.ShortString()).
		Int("open_chans", len(n.nodes)).
		Msg("Removed channel")
}

// IsConnected reports if a node is connected to headscale and has a
// poll session open.
func (n *Notifier) IsConnected(machineKey key.MachinePublic) bool {
	n.l.RLock()
	defer n.l.RUnlock()

	return n.connected[machineKey]
}

// TODO(kradalby): This returns a pointer and can be dangerous.
func (n *Notifier) ConnectedMap() map[key.MachinePublic]bool {
	return n.connected
}

func (n *Notifier) NotifyAll(ctx context.Context, update types.StateUpdate) {
	n.NotifyWithIgnore(ctx, update)
}

func (n *Notifier) NotifyWithIgnore(
	ctx context.Context,
	update types.StateUpdate,
	ignore ...string,
) {
	log.Trace().Caller().Interface("type", update.Type).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Interface("type", update.Type).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	for key, c := range n.nodes {
		if util.IsStringInSlice(ignore, key) {
			continue
		}

		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Str("mkey", key).
				Any("origin", ctx.Value("origin")).
				Any("hostname", ctx.Value("hostname")).
				Msgf("update not sent, context cancelled")

			return
		case c <- update:
			log.Trace().
				Str("mkey", key).
				Any("origin", ctx.Value("origin")).
				Any("hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
		}
	}
}

func (n *Notifier) NotifyByMachineKey(
	ctx context.Context,
	update types.StateUpdate,
	mKey key.MachinePublic,
) {
	log.Trace().Caller().Interface("type", update.Type).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Interface("type", update.Type).
		Msg("releasing lock, finished notifying")

	n.l.RLock()
	defer n.l.RUnlock()

	if c, ok := n.nodes[mKey.String()]; ok {
		select {
		case <-ctx.Done():
			log.Error().
				Err(ctx.Err()).
				Str("mkey", mKey.String()).
				Any("origin", ctx.Value("origin")).
				Any("hostname", ctx.Value("hostname")).
				Msgf("update not sent, context cancelled")

			return
		case c <- update:
			log.Trace().
				Str("mkey", mKey.String()).
				Any("origin", ctx.Value("origin")).
				Any("hostname", ctx.Value("hostname")).
				Msgf("update successfully sent on chan")
		}
	}
}

func (n *Notifier) String() string {
	n.l.RLock()
	defer n.l.RUnlock()

	str := []string{"Notifier, in map:\n"}

	for k, v := range n.nodes {
		str = append(str, fmt.Sprintf("\t%s: %v\n", k, v))
	}

	return strings.Join(str, "")
}
