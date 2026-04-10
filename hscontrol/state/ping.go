package state

import (
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

const pingIDLength = 16

// pingTracker manages pending ping requests and their response channels.
// It correlates outgoing PingRequests with incoming HEAD callbacks.
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

// register creates a new pending ping and returns a unique ping ID
// and a channel that will receive the round-trip latency when the
// ping response arrives.
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

// complete signals that a ping response was received.
// It sends the measured latency on the response channel and returns true.
// Returns false if the pingID is unknown (already completed, cancelled, or expired).
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

// cancel removes a pending ping without completing it.
// Used for cleanup when the caller times out or disconnects.
func (pt *pingTracker) cancel(pingID string) {
	pt.mu.Lock()
	delete(pt.pending, pingID)
	pt.mu.Unlock()
}

// RegisterPing creates a pending ping for the given node and returns
// a unique ping ID and a channel that receives the round-trip latency
// when the response arrives.
func (s *State) RegisterPing(nodeID types.NodeID) (string, <-chan time.Duration) {
	return s.pings.register(nodeID)
}

// CompletePing signals that a ping response was received for the given ID.
// Returns true if the ping was found and completed, false otherwise.
func (s *State) CompletePing(pingID string) bool {
	return s.pings.complete(pingID)
}

// CancelPing removes a pending ping without completing it.
func (s *State) CancelPing(pingID string) {
	s.pings.cancel(pingID)
}
