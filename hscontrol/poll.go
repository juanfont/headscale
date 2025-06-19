package hscontrol

import (
	"context"
	"encoding/json"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	xslices "golang.org/x/exp/slices"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
	"tailscale.com/util/must"
	"tailscale.com/util/zstdframe"
)

const (
	keepAliveInterval = 50 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context
	capVer tailcfg.CapabilityVersion

	cancelChMu deadlock.Mutex

	ch           chan []byte
	cancelCh     chan struct{}
	cancelChOpen bool

	keepAlive       time.Duration
	keepAliveTicker *time.Ticker

	node *types.Node
	w    http.ResponseWriter

	warnf  func(string, ...any)
	infof  func(string, ...any)
	tracef func(string, ...any)
	errf   func(error, string, ...any)
}

func (h *Headscale) newMapSession(
	ctx context.Context,
	req tailcfg.MapRequest,
	w http.ResponseWriter,
	node *types.Node,
) *mapSession {
	warnf, infof, tracef, errf := logPollFunc(req, node)

	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond)

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		ch:           make(chan []byte, h.cfg.Tuning.NodeMapSessionBufferedChanSize),
		cancelCh:     make(chan struct{}),
		cancelChOpen: true,

		keepAlive:       ka,
		keepAliveTicker: nil,

		// Loggers
		warnf:  warnf,
		infof:  infof,
		tracef: tracef,
		errf:   errf,
	}
}

func (m *mapSession) close() {
	m.cancelChMu.Lock()
	defer m.cancelChMu.Unlock()

	if !m.cancelChOpen {
		mapResponseClosed.WithLabelValues("chanclosed").Inc()
		return
	}

	m.tracef("mapSession (%p) sending message on cancel chan", m)
	select {
	case m.cancelCh <- struct{}{}:
		mapResponseClosed.WithLabelValues("sent").Inc()
		m.tracef("mapSession (%p) sent message on cancel chan", m)
	case <-time.After(30 * time.Second):
		mapResponseClosed.WithLabelValues("timeout").Inc()
		m.tracef("mapSession (%p) timed out sending close message", m)
	}
}

func (m *mapSession) isStreaming() bool {
	return m.req.Stream
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers
}

func (m *mapSession) resetKeepAlive() {
	m.keepAliveTicker.Reset(m.keepAlive)
}

func (m *mapSession) beforeServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Cancel(m.node.ID)
	}
}

func (m *mapSession) afterServeLongPoll() {
	if m.node.IsEphemeral() {
		m.h.ephemeralGC.Schedule(m.node.ID, m.h.cfg.EphemeralNodeInactivityTimeout)
	}
}

// serve handles non-streaming requests.
func (m *mapSession) serve() {
	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// If OmitPeers is true and Stream is false
	// then the server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// This is what Tailscale calls a Lite update, the client ignores
	// the response and just wants a 200.
	// !req.stream && req.OmitPeers
	if m.isEndpointUpdate() {
		m.handleEndpointUpdate()

		return
	}
}

// serveLongPoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
func (m *mapSession) serveLongPoll() {
	m.beforeServeLongPoll()

	// Clean up the session when the client disconnects
	defer func() {
		m.cancelChMu.Lock()
		m.cancelChOpen = false
		close(m.cancelCh)
		m.cancelChMu.Unlock()

		m.h.mapBatcher.RemoveNode(m.node.ID, m.ch)

		m.afterServeLongPoll()
		m.infof("node has disconnected, mapSession: %p, chan: %p", m, m.ch)
	}()

	// Set up the client stream
	m.h.pollNetMapStreamWG.Add(1)
	defer m.h.pollNetMapStreamWG.Done()

	// TODO(kradalby): I think this didnt really work and can be reverted back to a normal write thing.
	// Upgrade the writer to a ResponseController
	rc := http.NewResponseController(m.w)

	// Longpolling will break if there is a write timeout,
	// so it needs to be disabled.
	rc.SetWriteDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	m.h.mapBatcher.AddNode(m.node.ID, m.ch, m.req.Compress, m.req.Version)

	m.infof("node has connected, mapSession: %p, chan: %p", m, m.ch)

	// Loop through updates and continuously send them to the
	// client.
	for {
		// consume channels with update, keep alives or "batch" blocking signals
		select {
		case <-m.cancelCh:
			m.tracef("poll cancelled received")
			mapResponseEnded.WithLabelValues("cancelled").Inc()
			return

		case <-ctx.Done():
			m.tracef("poll context done")
			mapResponseEnded.WithLabelValues("done").Inc()
			return

		// Consume updates sent to node
		case update, ok := <-m.ch:
			m.tracef("received update from channel, ok: %t, len: %d", ok, len(update))
			if !ok {
				m.tracef("update channel closed, streaming session is likely being replaced")
				return
			}

			if err := m.write(rc, update); err != nil {
				m.errf(err, "cannot write update to client")
				return
			}

			m.tracef("update sent")
			m.resetKeepAlive()

		case <-m.keepAliveTicker.C:
			var err error
			switch m.req.Compress {
			case "zstd":
				err = m.write(rc, keepAliveZstd)
			default:
				err = m.write(rc, keepAlivePlain)
			}

			if err != nil {
				m.errf(err, "cannot write keep alive")
				return
			}

			if debugHighCardinalityMetrics {
				mapResponseLastSentSeconds.WithLabelValues("keepalive", m.node.ID.String()).Set(float64(time.Now().Unix()))
			}
			mapResponseSent.WithLabelValues("ok", "keepalive").Inc()
		}
	}
}

func (m *mapSession) write(rc *http.ResponseController, data []byte) error {
	startWrite := time.Now()
	_, err := m.w.Write(data)
	if err != nil {
		return err
	}

	err = rc.Flush()
	if err != nil {
		return err
	}

	log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startWrite).Str("mkey", m.node.MachineKey.String()).Msg("finished writing mapresp to node")
	return nil
}

var keepAlivePlain = must.Get(json.Marshal(tailcfg.MapResponse{
	KeepAlive: true,
}))

var keepAliveZstd = (func() []byte {
	msg := must.Get(json.Marshal(tailcfg.MapResponse{
		KeepAlive: true,
	}))
	return zstdframe.AppendEncode(nil, msg, zstdframe.FastestCompression)
})()

func (m *mapSession) handleEndpointUpdate() {
	m.tracef("received endpoint update")

	change := m.node.PeerChangeFromMapRequest(m.req)

	m.node.ApplyPeerChange(&change)

	sendUpdate, routesChanged := hostInfoChanged(m.node.Hostinfo, m.req.Hostinfo)

	// The node might not set NetInfo if it has not changed and if
	// the full HostInfo object is overwritten, the information is lost.
	// If there is no NetInfo, keep the previous one.
	// From 1.66 the client only sends it if changed:
	// https://github.com/tailscale/tailscale/commit/e1011f138737286ecf5123ff887a7a5800d129a2
	// TODO(kradalby): evaluate if we need better comparing of hostinfo
	// before we take the changes.
	if m.req.Hostinfo.NetInfo == nil && m.node.Hostinfo != nil {
		m.req.Hostinfo.NetInfo = m.node.Hostinfo.NetInfo
	}
	m.node.Hostinfo = m.req.Hostinfo

	logTracePeerChange(m.node.Hostname, sendUpdate, &change)

	// If there is no changes and nothing to save,
	// return early.
	if peerChangeEmpty(change) && !sendUpdate {
		mapResponseEndpointUpdates.WithLabelValues("noop").Inc()
		return
	}

	c := types.Change{NodeChange: types.NodeChange{
		ID:              m.node.ID,
		HostinfoChanged: true,
	}}

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		c.NodeChange.RoutesChanged = true

		// TODO(kradalby): I am not sure if we will ultimatly move this
		// to a more central part as part of this effort.
		// Do we want to make a thing where when you "save" a node, all the
		// changes are calculated based on that and updating the right subsystems?
		//
		// Approve any route that has been defined in policy as
		// auto approved. Any change here is not important as any
		// actual state change will be detected when the route manager
		// is updated.
		policy.AutoApproveRoutes(m.h.polMan, m.node)

		// Update the routes of the given node in the route manager to
		// see if an update needs to be sent.
		m.h.primaryRoutes.SetRoutes(m.node.ID, m.node.SubnetRoutes()...)
	}

	// Check if there has been a change to Hostname and update them
	// in the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the hostname change.
	m.node.ApplyHostnameFromHostInfo(m.req.Hostinfo)

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		m.errf(err, "Failed to persist/update node in the database")
		http.Error(m.w, "", http.StatusInternalServerError)
		mapResponseEndpointUpdates.WithLabelValues("error").Inc()

		return
	}

	m.h.Change(c)

	m.w.WriteHeader(http.StatusOK)
	mapResponseEndpointUpdates.WithLabelValues("ok").Inc()
}

func logTracePeerChange(hostname string, hostinfoChange bool, change *tailcfg.PeerChange) {
	trace := log.Trace().Uint64("node.id", uint64(change.NodeID)).Str("hostname", hostname)

	if change.Key != nil {
		trace = trace.Str("node_key", change.Key.ShortString())
	}

	if change.DiscoKey != nil {
		trace = trace.Str("disco_key", change.DiscoKey.ShortString())
	}

	if change.Online != nil {
		trace = trace.Bool("online", *change.Online)
	}

	if change.Endpoints != nil {
		eps := make([]string, len(change.Endpoints))
		for idx, ep := range change.Endpoints {
			eps[idx] = ep.String()
		}

		trace = trace.Strs("endpoints", eps)
	}

	if hostinfoChange {
		trace = trace.Bool("hostinfo_changed", hostinfoChange)
	}

	if change.DERPRegion != 0 {
		trace = trace.Int("derp_region", change.DERPRegion)
	}

	trace.Time("last_seen", *change.LastSeen).Msg("PeerChange received")
}

func peerChangeEmpty(chng tailcfg.PeerChange) bool {
	return chng.Key == nil &&
		chng.DiscoKey == nil &&
		chng.Online == nil &&
		chng.Endpoints == nil &&
		chng.DERPRegion == 0 &&
		chng.LastSeen == nil &&
		chng.KeyExpiry == nil
}

func logPollFunc(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
) (func(string, ...any), func(string, ...any), func(string, ...any), func(error, string, ...any)) {
	return func(msg string, a ...any) {
			log.Warn().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Err(err).
				Msgf(msg, a...)
		}
}

// hostInfoChanged reports if hostInfo has changed in two ways,
// - first bool reports if an update needs to be sent to nodes
// - second reports if there has been changes to routes
// the caller can then use this info to save and update nodes
// and routes as needed.
func hostInfoChanged(old, new *tailcfg.Hostinfo) (bool, bool) {
	if old.Equal(new) {
		return false, false
	}

	if old == nil && new != nil {
		return true, true
	}

	// Routes
	oldRoutes := make([]netip.Prefix, 0)
	if old != nil {
		oldRoutes = old.RoutableIPs
	}
	newRoutes := new.RoutableIPs

	tsaddr.SortPrefixes(oldRoutes)
	tsaddr.SortPrefixes(newRoutes)

	if !xslices.Equal(oldRoutes, newRoutes) {
		return true, true
	}

	// Services is mostly useful for discovery and not critical,
	// except for peerapi, which is how nodes talk to each other.
	// If peerapi was not part of the initial mapresponse, we
	// need to make sure its sent out later as it is needed for
	// Taildrop.
	// TODO(kradalby): Length comparison is a bit naive, replace.
	if len(old.Services) != len(new.Services) {
		return true, false
	}

	return false, false
}
