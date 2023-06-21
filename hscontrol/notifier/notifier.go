package notifier

import (
	"sync"

	"github.com/juanfont/headscale/hscontrol/util"
)

type Notifier struct {
	l     sync.RWMutex
	nodes map[string]chan<- struct{}
}

func NewNotifier() *Notifier {
	return &Notifier{}
}

func (n *Notifier) AddNode(machineKey string, c chan<- struct{}) {
	n.l.Lock()
	defer n.l.Unlock()

	if n.nodes == nil {
		n.nodes = make(map[string]chan<- struct{})
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

func (n *Notifier) NotifyAll() {
	n.NotifyWithIgnore()
}

func (n *Notifier) NotifyWithIgnore(ignore ...string) {
	n.l.RLock()
	defer n.l.RUnlock()

	for key, c := range n.nodes {
		if util.IsStringInSlice(ignore, key) {
			continue
		}

		c <- struct{}{}
	}
}
