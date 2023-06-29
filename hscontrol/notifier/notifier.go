package notifier

import (
	"sync"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

type Notifier struct {
	l     sync.RWMutex
	nodes map[string]chan<- types.StateUpdate
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) AddNode(machineKey string, c chan<- types.StateUpdate) {
	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		n.nodes = make(map[string]chan<- types.StateUpdate)
	}

	n.nodes[machineKey] = c
}

func (n *Notifier) RemoveNode(machineKey string) {
	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		return
	}

	delete(n.nodes, machineKey)
}

func (n *Notifier) NotifyAll(update types.StateUpdate) {
	n.NotifyWithIgnore(update)
}

func (n *Notifier) NotifyWithIgnore(update types.StateUpdate, ignore ...string) {
	n.l.RLock()
	defer n.l.RUnlock()

	for key, c := range n.nodes {
		if util.IsStringInSlice(ignore, key) {
			continue
		}

		c <- update
	}
}
