package state

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/puzpuzpuz/xsync/v4"
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

	// lastStableSession defers a timeout-driven unhealthy decision
	// for sessions younger than one probe cycle, giving wgengine
	// time to apply the new netmap on a freshly reconnected node.
	lastStableSession *xsync.Map[types.NodeID, uint64]
}

// NewHAHealthProber creates a prober that uses the given [State] for
// ping tracking and primary route management.
// isConnected should return true if a node has an active map session.
func NewHAHealthProber(
	s *State,
	cfg types.HARouteConfig,
	serverURL string,
	isConnected func(types.NodeID) bool,
) *HAHealthProber {
	return &HAHealthProber{
		state:             s,
		cfg:               cfg,
		serverURL:         serverURL,
		isConnected:       isConnected,
		lastStableSession: xsync.NewMap[types.NodeID, uint64](),
	}
}

// markSessionStable records session and returns true iff the same
// value was already present from a prior cycle.
func (p *HAHealthProber) markSessionStable(id types.NodeID, session uint64) bool {
	prev, loaded := p.lastStableSession.LoadAndStore(id, session)
	return loaded && prev == session
}

// forgetSession drops the recorded session so a node returning to
// HA candidacy starts fresh.
func (p *HAHealthProber) forgetSession(id types.NodeID) {
	p.lastStableSession.Delete(id)
}

// ProbeOnce pings every HA subnet router and applies the cycle's
// results in one batch so the election sees a single transition.
// Per-result snapshots could otherwise elect a node that the next
// snapshot demotes again, flipping primary onto an unreachable peer.
// A timeout that fires after the node reconnected, or against a
// session younger than one probe cycle, is dropped so wgengine has
// time to apply the new netmap before silence is read as
// unreachability.
func (p *HAHealthProber) ProbeOnce(
	ctx context.Context,
	dispatch func(...change.Change),
) {
	haNodes := p.state.nodeStore.HANodes()

	// Drop stable-session entries for nodes that are no longer HA
	// candidates so a future reappearance starts fresh.
	seen := make(set.Set[types.NodeID])

	for _, nodes := range haNodes {
		for _, id := range nodes {
			seen.Add(id)
		}
	}

	p.lastStableSession.Range(func(id types.NodeID, _ uint64) bool {
		if !seen.Contains(id) {
			p.lastStableSession.Delete(id)
		}

		return true
	})

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

	var (
		wg       sync.WaitGroup
		results  = xsync.NewMap[types.NodeID, bool]()
		deferred atomic.Bool
	)

	for _, id := range nodeIDs {
		if !p.isConnected(id) {
			log.Debug().
				Uint64(zf.NodeID, id.Uint64()).
				Msg("HA probe: skipping offline node")

			p.forgetSession(id)

			continue
		}

		nv, ok := p.state.GetNodeByID(id)
		if !ok {
			continue
		}

		probeSession := nv.SessionEpoch()
		stable := p.markSessionStable(id, probeSession)

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

				results.Store(id, true)

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

				if curr.SessionEpoch() != probeSession {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Uint64("probe_session", probeSession).
						Uint64("current_session", curr.SessionEpoch()).
						Msg("HA probe: node reconnected during probe, skipping")

					deferred.Store(true)

					return
				}

				if !stable {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Uint64("probe_session", probeSession).
						Msg("HA probe: probe of fresh session timed out, deferring to next cycle")

					deferred.Store(true)

					return
				}

				log.Warn().
					Uint64(zf.NodeID, id.Uint64()).
					Dur("timeout", p.cfg.ProbeTimeout).
					Msg("HA probe: node did not respond")

				results.Store(id, false)

			case <-ctx.Done():
				p.state.CancelPing(pingID)
			}
		})
	}

	wg.Wait()

	// When any probe in the cycle was deferred (fresh session or
	// reconnected mid-probe), drop the whole cycle's results: a partial
	// batch lets the election pick a node whose connectivity is still
	// unknown. The next cycle will run with stable sessions for every
	// candidate and can decide on a complete picture.
	if deferred.Load() {
		return
	}

	healthByNode := make(map[types.NodeID]bool, results.Size())
	results.Range(func(id types.NodeID, healthy bool) bool {
		healthByNode[id] = healthy

		return true
	})

	if p.state.BatchSetNodeHealth(healthByNode) {
		dispatch(change.PolicyChange())

		log.Info().
			Int("haNodes", len(healthByNode)).
			Msg("HA probe: health changed, triggering failover/recovery")
	}
}
