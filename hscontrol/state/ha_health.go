package state

import (
	"context"
	"net/netip"
	"slices"
	"sync"
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

// ProbeOnce applies HA probe results in one batch to avoid transient elections.
// Fresh or reconnected sessions defer their whole group of routers linked
// through shared prefixes, giving wgengine time to apply the new netmap.
// Other groups can still apply their complete results.
func (p *HAHealthProber) ProbeOnce(
	ctx context.Context,
	dispatch func(...change.Change),
) {
	haNodes := p.state.nodeStore.HANodes()

	// Build the deduplicated node-ID set and slice in one pass.
	var nodeIDs []types.NodeID

	seen := make(set.Set[types.NodeID])

	for _, nodes := range haNodes {
		for _, id := range nodes {
			if seen.Contains(id) {
				continue
			}

			seen.Add(id)
			nodeIDs = append(nodeIDs, id)
		}
	}

	// Drop stable-session entries for nodes that are no longer HA
	// candidates so a future reappearance starts fresh.
	p.lastStableSession.Range(func(id types.NodeID, _ uint64) bool {
		if !seen.Contains(id) {
			p.lastStableSession.Delete(id)
		}

		return true
	})

	if len(haNodes) == 0 {
		return
	}

	log.Debug().
		Int("haNodes", len(nodeIDs)).
		Msg("HA health prober starting probe cycle")

	var (
		wg       sync.WaitGroup
		results  = xsync.NewMap[types.NodeID, bool]()
		deferred = xsync.NewMap[types.NodeID, struct{}]()
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

					deferred.Store(id, struct{}{})

					return
				}

				if !stable {
					log.Debug().
						Uint64(zf.NodeID, id.Uint64()).
						Uint64("probe_session", probeSession).
						Msg("HA probe: probe of fresh session timed out, deferring to next cycle")

					deferred.Store(id, struct{}{})

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

	// Withhold incomplete HA groups; independent groups can apply their results.
	undecided := undecidedHANodes(haNodes, deferred)

	healthByNode := make(map[types.NodeID]bool, results.Size())
	results.Range(func(id types.NodeID, healthy bool) bool {
		if !undecided.Contains(id) {
			healthByNode[id] = healthy
		}

		return true
	})

	if p.state.BatchSetNodeHealth(healthByNode) {
		dispatch(change.PolicyChange())

		log.Info().
			Int("haNodes", len(healthByNode)).
			Msg("HA probe: health changed, triggering failover/recovery")
	}
}

// undecidedHANodes follows shared prefixes because one node's health affects
// every prefix it advertises. Each remaining group must have a complete batch.
func undecidedHANodes(
	haNodes map[netip.Prefix][]types.NodeID,
	deferred *xsync.Map[types.NodeID, struct{}],
) set.Set[types.NodeID] {
	undecided := make(set.Set[types.NodeID])

	deferred.Range(func(id types.NodeID, _ struct{}) bool {
		undecided.Add(id)

		return true
	})

	for grown := true; grown; {
		grown = false

		for _, ids := range haNodes {
			if !slices.ContainsFunc(ids, undecided.Contains) {
				continue
			}

			for _, id := range ids {
				if !undecided.Contains(id) {
					undecided.Add(id)

					grown = true
				}
			}
		}
	}

	return undecided
}
