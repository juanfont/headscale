package notifier

import (
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
)

type Notifier struct {
	l     sync.RWMutex
	nodes map[string]chan<- types.StateUpdate
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) AddNode(machineKey string, c chan<- types.StateUpdate) {
	log.Trace().Caller().Str("key", machineKey).Msg("acquiring lock to add node")
	defer log.Trace().Caller().Str("key", machineKey).Msg("releasing lock to add node")

	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		n.nodes = make(map[string]chan<- types.StateUpdate)
	}

	n.nodes[machineKey] = c

	log.Trace().
		Str("machine_key", machineKey).
		Int("open_chans", len(n.nodes)).
		Msg("Added new channel")
}

func (n *Notifier) RemoveNode(machineKey string) {
	log.Trace().Caller().Str("key", machineKey).Msg("acquiring lock to remove node")
	defer log.Trace().Caller().Str("key", machineKey).Msg("releasing lock to remove node")

	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		return
	}

	delete(n.nodes, machineKey)

	log.Trace().
		Str("machine_key", machineKey).
		Int("open_chans", len(n.nodes)).
		Msg("Removed channel")
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
