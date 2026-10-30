package state

import (
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/util/rands"
)

const pingIDLength = 16

// pingTracker correlates outgoing [tailcfg.PingRequest]s with incoming HEAD
// callbacks. Entries have no server-side TTL: callers are responsible
// for cleaning up via [pingTracker.cancel] or by reading from the response
// channel within their own timeout.
type pingTracker struct {
	mu      sync.Mutex
	pending map[string]*pendingPing
	c2n     map[string]*pendingC2N
}

type pendingPing struct {
	nodeID     types.NodeID
	startTime  time.Time
	responseCh chan time.Duration
}

// pendingC2N is a c2n [tailcfg.PingRequest] waiting for the node to POST
// back the raw HTTP response produced by its c2n handler.
type pendingC2N struct {
	nodeID     types.NodeID
	responseCh chan []byte
}

func newPingTracker() *pingTracker {
	return &pingTracker{
		pending: make(map[string]*pendingPing),
		c2n:     make(map[string]*pendingC2N),
	}
}

// register creates a pending ping and returns a unique ping ID and a
// channel that receives the round-trip latency once the response
// arrives.
func (pt *pingTracker) register(nodeID types.NodeID) (string, <-chan time.Duration) {
	pingID := rands.HexString(pingIDLength)
	ch := make(chan time.Duration, 1)

	pt.mu.Lock()
	pt.pending[pingID] = &pendingPing{
		nodeID:     nodeID,
		startTime:  time.Now(),
		responseCh: ch,
	}
	pt.mu.Unlock()

	return pingID, ch
}

// complete sends the measured latency on the response channel and
// returns true. Returns false if the pingID is unknown (already
// completed or cancelled).
func (pt *pingTracker) complete(pingID string) bool {
	pt.mu.Lock()

	pp, ok := pt.pending[pingID]
	if ok {
		delete(pt.pending, pingID)
	}
	pt.mu.Unlock()

	if ok {
		pp.responseCh <- time.Since(pp.startTime)

		close(pp.responseCh)

		return true
	}

	return false
}

// cancel removes a pending ping without completing it. Idempotent.
func (pt *pingTracker) cancel(pingID string) {
	pt.mu.Lock()
	delete(pt.pending, pingID)
	pt.mu.Unlock()
}

// drain closes every outstanding response channel and clears the map.
// Called from [State.Close] to unblock any caller still waiting on a
// channel that will never receive.
func (pt *pingTracker) drain() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	for id, pp := range pt.pending {
		close(pp.responseCh)
		delete(pt.pending, id)
	}

	for id, pc := range pt.c2n {
		close(pc.responseCh)
		delete(pt.c2n, id)
	}
}

// registerC2N creates a pending c2n request for nodeID and returns a
// unique ID and a channel that receives the raw HTTP response the node
// sends back.
func (pt *pingTracker) registerC2N(nodeID types.NodeID) (string, <-chan []byte) {
	c2nID := rands.HexString(pingIDLength)
	ch := make(chan []byte, 1)

	pt.mu.Lock()
	pt.c2n[c2nID] = &pendingC2N{
		nodeID:     nodeID,
		responseCh: ch,
	}
	pt.mu.Unlock()

	return c2nID, ch
}

// c2nTarget returns the node a pending c2n request was sent to.
func (pt *pingTracker) c2nTarget(c2nID string) (types.NodeID, bool) {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	pc, ok := pt.c2n[c2nID]
	if !ok {
		return 0, false
	}

	return pc.nodeID, true
}

// completeC2N delivers body on the response channel and returns true.
// Returns false if the c2nID is unknown (already completed or cancelled).
func (pt *pingTracker) completeC2N(c2nID string, body []byte) bool {
	pt.mu.Lock()

	pc, ok := pt.c2n[c2nID]
	if ok {
		delete(pt.c2n, c2nID)
	}
	pt.mu.Unlock()

	if !ok {
		return false
	}

	pc.responseCh <- body

	close(pc.responseCh)

	return true
}

// cancelC2N removes a pending c2n request without completing it. Idempotent.
func (pt *pingTracker) cancelC2N(c2nID string) {
	pt.mu.Lock()
	delete(pt.c2n, c2nID)
	pt.mu.Unlock()
}

// RegisterPing tracks a pending ping and returns its ID and a channel
// for the latency. Callers must defer [State.CancelPing] or read the channel
// within their own timeout; there is no server-side TTL.
func (s *State) RegisterPing(nodeID types.NodeID) (string, <-chan time.Duration) {
	return s.pings.register(nodeID)
}

// CompletePing signals that a ping response arrived. Returns true if
// the ID was known, false otherwise.
func (s *State) CompletePing(pingID string) bool {
	return s.pings.complete(pingID)
}

// CancelPing removes a pending ping. Idempotent.
func (s *State) CancelPing(pingID string) {
	s.pings.cancel(pingID)
}

// RegisterC2N tracks a pending c2n request to nodeID and returns its ID
// and a channel for the node's raw HTTP response. Callers must defer
// [State.CancelC2N] or read the channel within their own timeout; there
// is no server-side TTL.
func (s *State) RegisterC2N(nodeID types.NodeID) (string, <-chan []byte) {
	return s.pings.registerC2N(nodeID)
}

// C2NTarget returns the node a pending c2n request was sent to, so the
// response handler can check that the answer comes from that node.
func (s *State) C2NTarget(c2nID string) (types.NodeID, bool) {
	return s.pings.c2nTarget(c2nID)
}

// CompleteC2N delivers a c2n response. Returns true if the ID was known,
// false otherwise.
func (s *State) CompleteC2N(c2nID string, body []byte) bool {
	return s.pings.completeC2N(c2nID, body)
}

// CancelC2N removes a pending c2n request. Idempotent.
func (s *State) CancelC2N(c2nID string) {
	s.pings.cancelC2N(c2nID)
}
