package state

import (
	"context"
	"sync"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/util/set"
)

// HAHealthProber periodically pings HA subnet router nodes and
// triggers failover when a primary stops responding.
type HAHealthProber struct {
	state       *State
	cfg         types.HARouteConfig
	serverURL   string
	isConnected func(types.NodeID) bool

	// stableEpoch tracks the most recent SessionEpoch the prober has
	// already observed at the start of a probe. A timeout is allowed
	// to fail a node only if the epoch was already present in this
	// map for the current cycle — i.e., the session survived a prior
	// cycle. Sessions younger than one probe interval are excluded.
	stableMu    sync.Mutex
	stableEpoch map[types.NodeID]uint64
}

// NewHAHealthProber creates a prober that uses the given State for
// ping tracking and primary route management.
// isConnected should return true if a node has an active map session.
func NewHAHealthProber(
	s *State,
	cfg types.HARouteConfig,
	serverURL string,
	isConnected func(types.NodeID) bool,
) *HAHealthProber {
	return &HAHealthProber{
		state:       s,
		cfg:         cfg,
		serverURL:   serverURL,
		isConnected: isConnected,
		stableEpoch: make(map[types.NodeID]uint64),
	}
}

// observeEpoch returns whether the given (id, epoch) pair was already
// recorded as the node's most recent stable epoch. After the call the
// map is updated to the new epoch so the next probe cycle will see it
// as stable (provided the session does not bounce again first).
//
// A change in epoch means the node reconnected between probe cycles
// and is still warming up: returning false defers the unhealthy
// decision by one cycle, which is enough time for wgengine to finish
// applying the new netmap and answer the next PingRequest.
func (p *HAHealthProber) observeEpoch(id types.NodeID, epoch uint64) bool {
	p.stableMu.Lock()
	defer p.stableMu.Unlock()

	prev, ok := p.stableEpoch[id]
	p.stableEpoch[id] = epoch

	return ok && prev == epoch
}

// forgetEpoch drops an entry so a node that left HA candidacy (e.g.
// route approval removed) starts fresh next time it returns.
func (p *HAHealthProber) forgetEpoch(id types.NodeID) {
	p.stableMu.Lock()
	defer p.stableMu.Unlock()

	delete(p.stableEpoch, id)
}

// ProbeOnce pings all HA subnet router nodes. PingNode changes are
// dispatched immediately via dispatch so nodes can respond before the
// timeout. Health-related policy changes are also dispatched inline.
//
// Each probe records the target's SessionEpoch at dispatch time. A
// timeout that fires after the node reconnected (epoch advanced) is
// dropped: the in-flight PingRequest was queued against the previous
// session and was never delivered, so its silence proves nothing about
// the new session. The prober also requires the SessionEpoch to have
// survived a prior cycle before marking the node unhealthy: a freshly
// reconnected node needs roughly 10 seconds for wgengine to apply the
// new netmap and answer pings, and a 5 second probe timeout dropped in
// the middle of that window would otherwise force a spurious failover
// (see [TestHAHealthProbe_ReconnectDuringProbeKeepsHealthy]).
func (p *HAHealthProber) ProbeOnce(
	ctx context.Context,
	dispatch func(...change.Change),
) {
	haNodes := p.state.nodeStore.HANodes()

	// Drop stable-epoch entries for nodes that are no longer HA
	// candidates so a future reappearance starts fresh.
	seen := make(set.Set[types.NodeID])

	for _, nodes := range haNodes {
		for _, id := range nodes {
			seen.Add(id)
		}
	}

	p.stableMu.Lock()
	for id := range p.stableEpoch {
		if !seen.Contains(id) {
			delete(p.stableEpoch, id)
		}
	}
	p.stableMu.Unlock()

	if len(haNodes) == 0 {
		return
	}

	// Deduplicate node IDs across prefixes.
	var nodeIDs []types.NodeID

	dedup := make(set.Set[types.NodeID])

	for _, nodes := range haNodes {
		for _, id := range nodes {
			if !dedup.Contains(id) {
				dedup.Add(id)
				nodeIDs = append(nodeIDs, id)
			}
		}
	}

	log.Debug().
		Int("haNodes", len(nodeIDs)).
		Msg("HA health prober starting probe cycle")

	var wg sync.WaitGroup

	for _, id := range nodeIDs {
		if !p.isConnected(id) {
			log.Debug().
				Uint64(zf.NodeID, id.Uint64()).
				Msg("HA probe: skipping offline node")

			p.forgetEpoch(id)

			continue
		}

		nv, ok := p.state.GetNodeByID(id)
		if !ok {
			continue
		}

		probeEpoch := nv.SessionEpoch()
		stable := p.observeEpoch(id, probeEpoch)

		pingID, responseCh := p.state.RegisterPing(id)
		callbackURL := p.serverURL + "/machine/ping-response?id=" + pingID

		dispatch(change.PingNode(id, &tailcfg.PingRequest{
			URL: callbackURL,
		}))

		wg.Go(func() {
			timer := time.NewTimer(p.cfg.ProbeTimeout)
			defer timer.Stop()

			select {
			case latency := <-responseCh:
				log.Debug().
					Uint64(zf.NodeID, id.Uint64()).
					Dur("latency", latency).
					Msg("HA probe: node responded")

				if p.state.SetNodeUnhealthy(id, false) {
					dispatch(change.PolicyChange())

					log.Info().
						Uint64(zf.NodeID, id.Uint64()).
						Msg("HA probe: node recovered, recalculating primaries")
				}

			case <-timer.C:
				p.state.CancelPing(pingID)

				if !p.isConnected(id) {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Msg("HA probe: node went offline during probe, skipping")

					return
				}

				curr, ok := p.state.GetNodeByID(id)
				if !ok {
					return
				}

				if curr.SessionEpoch() != probeEpoch {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Uint64("probe_epoch", probeEpoch).
						Uint64("current_epoch", curr.SessionEpoch()).
						Msg("HA probe: node reconnected during probe, skipping")

					return
				}

				if !stable {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Uint64("probe_epoch", probeEpoch).
						Msg("HA probe: probe of fresh session timed out, deferring to next cycle")

					return
				}

				log.Warn().
					Uint64(zf.NodeID, id.Uint64()).
					Dur("timeout", p.cfg.ProbeTimeout).
					Msg("HA probe: node did not respond")

				if p.state.SetNodeUnhealthy(id, true) {
					dispatch(change.PolicyChange())

					log.Info().
						Uint64(zf.NodeID, id.Uint64()).
						Msg("HA probe: node unhealthy, triggering failover")
				}

			case <-ctx.Done():
				p.state.CancelPing(pingID)
			}
		})
	}

	wg.Wait()
}
