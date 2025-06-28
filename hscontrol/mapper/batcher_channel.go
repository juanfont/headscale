package mapper

import (
	"context"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

// Command types for channel-based coordination
type batcherCommand interface {
	execute(b *ChannelBatcher)
}

type addNodeCmd struct {
	id       types.NodeID
	c        chan<- []byte
	compress string
	version  tailcfg.CapabilityVersion
	response chan error
}

func (cmd *addNodeCmd) execute(b *ChannelBatcher) {
	// Update node without external locking
	newConn := &nodeConn{
		id:       cmd.id,
		c:        cmd.c,
		compress: cmd.compress,
		version:  cmd.version,
		mapper:   b.mapper,
	}

	if existing, ok := b.nodes[cmd.id]; ok {
		existing.updateConnectionUnsafe(cmd.c, cmd.compress, cmd.version)
	} else {
		b.nodes[cmd.id] = newConn
	}

	b.connected[cmd.id] = nil // connected
	
	// Generate online event
	chg := change.NodeOnline(cmd.id)
	b.addWorkUnsafe(chg)
	
	cmd.response <- nil
}

type removeNodeCmd struct {
	id       types.NodeID
	c        chan<- []byte
	response chan error
}

func (cmd *removeNodeCmd) execute(b *ChannelBatcher) {
	if existing, ok := b.nodes[cmd.id]; ok {
		if existing.matchesChannelUnsafe(cmd.c) {
			delete(b.nodes, cmd.id)
			b.connected[cmd.id] = ptr.To(time.Now())
		}
	}
	cmd.response <- nil
}

type addWorkCmd struct {
	change   change.Change
	response chan error
}

func (cmd *addWorkCmd) execute(b *ChannelBatcher) {
	b.addWorkUnsafe(cmd.change)
	cmd.response <- nil
}

type flushCmd struct {
	full     bool
	response chan error
}

func (cmd *flushCmd) execute(b *ChannelBatcher) {
	b.flushUnsafe(cmd.full)
	cmd.response <- nil
}

type isConnectedQuery struct {
	id       types.NodeID
	response chan bool
}

func (cmd *isConnectedQuery) execute(b *ChannelBatcher) {
	connected := false
	if val, ok := b.connected[cmd.id]; ok {
		connected = val == nil
	}
	cmd.response <- connected
}

// ChannelBatcher eliminates mutex by using a single-threaded event loop
type ChannelBatcher struct {
	tick   *time.Ticker
	mapper *mapper

	// State managed by single goroutine - no mutex needed
	nodes          map[types.NodeID]*nodeConn
	connected      map[types.NodeID]*time.Time
	partialChanges map[types.NodeID]change.Change
	hasPartialChanges bool

	// Command channel for serialized access
	commandCh chan batcherCommand
	workCh    chan work
	cancelCh  chan struct{}

	// Worker pool for concurrent work processing
	workers sync.WaitGroup
}

func NewChannelBatcher(batchTime time.Duration, mapper *mapper) *ChannelBatcher {
	return &ChannelBatcher{
		mapper:     mapper,
		tick:       time.NewTicker(batchTime),
		commandCh:  make(chan batcherCommand, 1000), // Buffered for performance
		workCh:     make(chan work, (1<<16)-1),
		cancelCh:   make(chan struct{}),
		nodes:      make(map[types.NodeID]*nodeConn),
		connected:  make(map[types.NodeID]*time.Time),
		partialChanges: make(map[types.NodeID]change.Change),
	}
}

func (b *ChannelBatcher) Start() {
	go b.eventLoop()
	
	// Start worker pool
	for i := 0; i < 4; i++ {
		b.workers.Add(1)
		go b.worker()
	}
}

func (b *ChannelBatcher) Close() {
	close(b.commandCh)
	close(b.cancelCh)
	b.workers.Wait()
}

// Event loop - single threaded, no locks needed
func (b *ChannelBatcher) eventLoop() {
	defer close(b.workCh)
	
	for {
		select {
		case cmd := <-b.commandCh:
			if cmd == nil {
				return // Channel closed
			}
			cmd.execute(b)
			
		case <-b.tick.C:
			b.flushUnsafe(false)
			
		case <-b.cancelCh:
			return
		}
	}
}

// Worker processes work items concurrently
func (b *ChannelBatcher) worker() {
	defer b.workers.Done()
	
	for {
		select {
		case w, ok := <-b.workCh:
			if !ok {
				return
			}
			
			// Look up node without locking (nodeConn has internal sync)
			if nodeConn := b.getNodeUnsafe(w.nodeID); nodeConn != nil {
				nodeConn.change(w.c)
			}
			
		case <-b.cancelCh:
			return
		}
	}
}

// Public API - all go through command channel
func (b *ChannelBatcher) AddNode(id types.NodeID, c chan<- []byte, compress string, version tailcfg.CapabilityVersion) error {
	response := make(chan error, 1)
	cmd := &addNodeCmd{
		id:       id,
		c:        c,
		compress: compress,
		version:  version,
		response: response,
	}
	
	select {
	case b.commandCh <- cmd:
		return <-response
	case <-b.cancelCh:
		return context.Canceled
	}
}

func (b *ChannelBatcher) RemoveNode(id types.NodeID, c chan<- []byte) error {
	response := make(chan error, 1)
	cmd := &removeNodeCmd{
		id:       id,
		c:        c,
		response: response,
	}
	
	select {
	case b.commandCh <- cmd:
		return <-response
	case <-b.cancelCh:
		return context.Canceled
	}
}

func (b *ChannelBatcher) AddWork(c change.Change) error {
	response := make(chan error, 1)
	cmd := &addWorkCmd{
		change:   c,
		response: response,
	}
	
	select {
	case b.commandCh <- cmd:
		return <-response
	case <-b.cancelCh:
		return context.Canceled
	}
}

func (b *ChannelBatcher) IsConnected(id types.NodeID) bool {
	response := make(chan bool, 1)
	cmd := &isConnectedQuery{
		id:       id,
		response: response,
	}
	
	select {
	case b.commandCh <- cmd:
		return <-response
	case <-b.cancelCh:
		return false
	}
}

// Internal methods - only called from event loop (no locking needed)
func (b *ChannelBatcher) getNodeUnsafe(id types.NodeID) *nodeConn {
	return b.nodes[id]
}

func (b *ChannelBatcher) addWorkUnsafe(c change.Change) {
	switch determineChange(c) {
	case partialUpdate:
		b.addPartialUnsafe(c)
	case fullUpdate:
		b.flushUnsafe(true)
	}
}

func (b *ChannelBatcher) addPartialUnsafe(c change.Change) {
	if existing, ok := b.partialChanges[c.Node.ID]; ok {
		b.partialChanges[c.Node.ID] = existing.Merge(c)
	} else {
		b.partialChanges[c.Node.ID] = c
	}
	b.hasPartialChanges = true
}

func (b *ChannelBatcher) flushUnsafe(full bool) {
	if full {
		b.hasPartialChanges = false
		clear(b.partialChanges)
		
		for nodeID := range b.nodes {
			select {
			case b.workCh <- work{change.Full, nodeID}:
			default:
				// Work channel full - could add metrics
			}
		}
	}
	
	if b.hasPartialChanges {
		for _, c := range b.partialChanges {
			for nodeID := range b.nodes {
				select {
				case b.workCh <- work{c, nodeID}:
				default:
					// Work channel full
				}
			}
		}
		b.hasPartialChanges = false
		clear(b.partialChanges)
	}
}