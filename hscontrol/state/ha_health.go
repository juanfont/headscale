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
	}
}

// ProbeOnce pings all HA subnet router nodes. PingNode changes are
// dispatched immediately via dispatch so nodes can respond before the
// timeout. Health-related policy changes are also dispatched inline.
func (p *HAHealthProber) ProbeOnce(
	ctx context.Context,
	dispatch func(...change.Change),
) {
	haNodes := p.state.nodeStore.HANodes()
	if len(haNodes) == 0 {
		return
	}

	// Deduplicate node IDs across prefixes.
	seen := make(set.Set[types.NodeID])

	var nodeIDs []types.NodeID

	for _, nodes := range haNodes {
		for _, id := range nodes {
			if !seen.Contains(id) {
				seen.Add(id)
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

			continue
		}

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
