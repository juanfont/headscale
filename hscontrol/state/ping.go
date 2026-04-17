package state

import (
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

const pingIDLength = 16

// pingTracker correlates outgoing PingRequests with incoming HEAD
// callbacks. Entries have no server-side TTL: callers are responsible
// for cleaning up via CancelPing or by reading from the response channel
// within their own timeout.
type pingTracker struct {
	mu      sync.Mutex
	pending map[string]*pendingPing
}

type pendingPing struct {
	nodeID     types.NodeID
	startTime  time.Time
	responseCh chan time.Duration
}

func newPingTracker() *pingTracker {
	return &pingTracker{
		pending: make(map[string]*pendingPing),
	}
}

// register creates a pending ping and returns a unique ping ID and a
// channel that receives the round-trip latency once the response
// arrives.
func (pt *pingTracker) register(nodeID types.NodeID) (string, <-chan time.Duration) {
	pingID, _ := util.GenerateRandomStringDNSSafe(pingIDLength)
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
// Called from State.Close to unblock any caller still waiting on a
// channel that will never receive.
func (pt *pingTracker) drain() {
	pt.mu.Lock()
	defer pt.mu.Unlock()

	for id, pp := range pt.pending {
		close(pp.responseCh)
		delete(pt.pending, id)
	}
}

// RegisterPing tracks a pending ping and returns its ID and a channel
// for the latency. Callers must defer CancelPing or read the channel
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
