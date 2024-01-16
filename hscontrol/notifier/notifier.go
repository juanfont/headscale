package notifier

import (
	"fmt"
	"strings"
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/types/key"
)

type Notifier struct {
	l     sync.RWMutex
	nodes map[string]chan<- types.StateUpdate
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) AddNode(machineKey key.MachinePublic, c chan<- types.StateUpdate) {
	log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("acquiring lock to add node")
	defer log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("releasing lock to add node")

	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		n.nodes = make(map[string]chan<- types.StateUpdate)
	}

	n.nodes[machineKey.String()] = c

	log.Trace().
		Str("machine_key", machineKey.ShortString()).
		Int("open_chans", len(n.nodes)).
		Msg("Added new channel")
}

func (n *Notifier) RemoveNode(machineKey key.MachinePublic) {
	log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("acquiring lock to remove node")
	defer log.Trace().Caller().Str("key", machineKey.ShortString()).Msg("releasing lock to remove node")

	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		return
	}

	delete(n.nodes, machineKey.String())

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

	if _, ok := n.nodes[machineKey.String()]; ok {
		return true
	}

	return false
}

func (n *Notifier) NotifyAll(update types.StateUpdate) {
	n.NotifyWithIgnore(update)
}

func (n *Notifier) NotifyWithIgnore(update types.StateUpdate, ignore ...string) {
	log.Trace().Caller().Interface("type", update.Type).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Interface("type", update.Type).
		Msg("releasing lock, finished notifing")

	n.l.RLock()
	defer n.l.RUnlock()

	for key, c := range n.nodes {
		if util.IsStringInSlice(ignore, key) {
			continue
		}

		log.Trace().Caller().Str("machine", key).Strs("ignoring", ignore).Msg("sending update")
		c <- update
	}
}

func (n *Notifier) NotifyByMachineKey(update types.StateUpdate, mKey key.MachinePublic) {
	log.Trace().Caller().Interface("type", update.Type).Msg("acquiring lock to notify")
	defer log.Trace().
		Caller().
		Interface("type", update.Type).
		Msg("releasing lock, finished notifing")

	n.l.RLock()
	defer n.l.RUnlock()

	if c, ok := n.nodes[mKey.String()]; ok {
		c <- update
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
