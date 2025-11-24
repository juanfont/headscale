package hscontrol

import (
	"context"
	"crypto/rand"
	"math/big"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// PingScheduler manages periodic health check pings to nodes to verify liveness.
// It distributes pings across time windows with jitter to prevent bunching.
type PingScheduler struct {
	mu              sync.RWMutex
	enabled         bool
	interval        time.Duration
	jitter          time.Duration
	timeout         time.Duration
	app             *Headscale
	ctx             context.Context
	cancel          context.CancelFunc
	scheduledChecks map[types.NodeID]time.Time
}

// PingSchedulerConfig contains the configuration for the ping scheduler.
type PingSchedulerConfig struct {
	Enabled  bool
	Interval time.Duration
	Jitter   time.Duration
	Timeout  time.Duration
}

// NewPingScheduler creates a new ping scheduler.
func NewPingScheduler(app *Headscale, cfg PingSchedulerConfig) *PingScheduler {
	ctx, cancel := context.WithCancel(context.Background())

	return &PingScheduler{
		enabled:         cfg.Enabled,
		interval:        cfg.Interval,
		jitter:          cfg.Jitter,
		timeout:         cfg.Timeout,
		app:             app,
		ctx:             ctx,
		cancel:          cancel,
		scheduledChecks: make(map[types.NodeID]time.Time),
	}
}

// Start begins the periodic ping scheduler.
func (ps *PingScheduler) Start() {
	if !ps.enabled {
		log.Info().Msg("Ping scheduler is disabled")
		return
	}

	log.Info().
		Dur("interval", ps.interval).
		Dur("jitter", ps.jitter).
		Msg("Starting ping scheduler for node liveness checks")

	go ps.run()
}

// Stop gracefully stops the ping scheduler.
func (ps *PingScheduler) Stop() {
	if ps.cancel != nil {
		ps.cancel()
	}
}

// run contains the main scheduler loop.
func (ps *PingScheduler) run() {
	// Initial check after a short delay
	initialDelay := time.Second * 30
	timer := time.NewTimer(initialDelay)
	defer timer.Stop()

	for {
		select {
		case <-ps.ctx.Done():
			log.Info().Msg("Ping scheduler shutting down")
			return
		case <-timer.C:
			ps.schedulePingRound()
			timer.Reset(ps.interval)
		}
	}
}

// schedulePingRound schedules a round of pings for all nodes with distributed timing.
func (ps *PingScheduler) schedulePingRound() {
	nodes := ps.app.state.ListNodes()
	if nodes.Len() == 0 {
		return
	}

	log.Debug().
		Int("node_count", nodes.Len()).
		Msg("Scheduling ping round for nodes")

	// Calculate time slots to distribute pings across the interval
	// This prevents all pings from bunching at the same time
	windowSize := ps.interval
	if ps.jitter > 0 {
		// Use the jitter to determine the distribution window
		windowSize = ps.jitter
	}

	// For each node, calculate a distributed delay
	for idx := range nodes.Len() {
		nodeView := nodes.At(idx)

		// Skip offline nodes that have expired
		if nodeView.IsExpired() {
			continue
		}

		// Calculate base delay distributed across the window
		// This ensures pings are spread evenly
		baseDelay := time.Duration(idx) * windowSize / time.Duration(nodes.Len())

		// Add random jitter to prevent synchronized pings
		jitterAmount := ps.calculateJitter()
		totalDelay := baseDelay + jitterAmount

		// Ensure delay doesn't exceed the interval
		if totalDelay > ps.interval {
			totalDelay = ps.interval - time.Second
		}

		// Schedule the ping
		go ps.schedulePingForNodeView(nodeView, totalDelay)
	}
}

// calculateJitter returns a random jitter duration up to the configured maximum.
func (ps *PingScheduler) calculateJitter() time.Duration {
	if ps.jitter == 0 {
		return 0
	}

	// Generate cryptographically secure random jitter
	maxJitterNanos := ps.jitter.Nanoseconds()
	if maxJitterNanos <= 0 {
		return 0
	}

	n, err := rand.Int(rand.Reader, big.NewInt(maxJitterNanos))
	if err != nil {
		log.Warn().Err(err).Msg("Failed to generate random jitter, using zero")
		return 0
	}

	return time.Duration(n.Int64())
}

// schedulePingForNodeView schedules a ping for a specific node after the given delay.
func (ps *PingScheduler) schedulePingForNodeView(nodeView types.NodeView, delay time.Duration) {
	// Wait for the calculated delay
	timer := time.NewTimer(delay)
	defer timer.Stop()

	select {
	case <-ps.ctx.Done():
		return
	case <-timer.C:
		ps.pingNodeView(nodeView)
	}
}

// pingNodeView performs a health check ping on a node.
func (ps *PingScheduler) pingNodeView(nodeView types.NodeView) {
	nodeID := nodeView.ID()

	ps.mu.Lock()
	ps.scheduledChecks[nodeID] = time.Now()
	ps.mu.Unlock()

	defer func() {
		ps.mu.Lock()
		delete(ps.scheduledChecks, nodeID)
		ps.mu.Unlock()
	}()

	// Get the node's primary IP for the ping target
	ips := nodeView.IPs()
	if len(ips) == 0 {
		log.Warn().
			Uint64("node.id", nodeID.Uint64()).
			Str("node.name", nodeView.Hostname()).
			Msg("Node has no IP addresses, skipping ping")
		return
	}

	targetIP := ips[0].String()

	log.Debug().
		Uint64("node.id", nodeID.Uint64()).
		Str("node.name", nodeView.Hostname()).
		Str("target_ip", targetIP).
		Msg("Sending liveness ping to node")

	// Create a context with timeout for the ping
	ctx, cancel := context.WithTimeout(ps.ctx, ps.timeout)
	defer cancel()

	// Perform the ping check
	response, err := ps.pingNodeWithContext(ctx, nodeID, targetIP)
	if err != nil {
		log.Warn().
			Err(err).
			Uint64("node.id", nodeID.Uint64()).
			Str("node.name", nodeView.Hostname()).
			Msg("Node liveness ping failed - node may be offline")

		// Node didn't respond, it may be offline
		ps.handleUnresponsiveNodeView(nodeView)
		return
	}

	log.Debug().
		Uint64("node.id", nodeID.Uint64()).
		Str("node.name", nodeView.Hostname()).
		Str("response_type", string(response.Type)).
		Msg("Node liveness ping succeeded")
}

// pingNodeWithContext performs a ping with context support.
func (ps *PingScheduler) pingNodeWithContext(ctx context.Context, nodeID types.NodeID, targetIP string) (*tailcfg.PingResponse, error) {
	// Use a channel to handle the response with context
	responseChan := make(chan *tailcfg.PingResponse, 1)
	errorChan := make(chan error, 1)

	go func() {
		response, err := ps.app.CheckNodeOnline(nodeID, targetIP)
		if err != nil {
			errorChan <- err
		} else {
			responseChan <- response
		}
	}()

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errorChan:
		return nil, err
	case response := <-responseChan:
		return response, nil
	}
}

// handleUnresponsiveNodeView handles a node that failed to respond to a ping.
func (ps *PingScheduler) handleUnresponsiveNodeView(nodeView types.NodeView) {
	// For now, we log the issue. In the future, this could:
	// 1. Mark the node as potentially offline in the database
	// 2. Trigger additional verification checks
	// 3. Send notifications
	// 4. Update route failover status

	log.Info().
		Uint64("node.id", nodeView.ID().Uint64()).
		Str("node.name", nodeView.Hostname()).
		Msg("Node failed liveness check - connection may be severed")
}

// GetScheduledChecksCount returns the number of currently scheduled checks.
func (ps *PingScheduler) GetScheduledChecksCount() int {
	ps.mu.RLock()
	defer ps.mu.RUnlock()
	return len(ps.scheduledChecks)
}

// IsEnabled returns whether the ping scheduler is enabled.
func (ps *PingScheduler) IsEnabled() bool {
	return ps.enabled
}
