package hscontrol

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"github.com/sasha-s/go-deadlock"
	xslices "golang.org/x/exp/slices"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
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
	mapper *mapper.Mapper

	cancelChMu deadlock.Mutex

	ch           chan types.StateUpdate
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

	var updateChan chan types.StateUpdate
	if req.Stream {
		// Use a buffered channel in case a node is not fully ready
		// to receive a message to make sure we dont block the entire
		// notifier.
		updateChan = make(chan types.StateUpdate, h.cfg.Tuning.NodeMapSessionBufferedChanSize)
		updateChan <- types.StateUpdate{
			Type: types.StateFullUpdate,
		}
	}

	ka := keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond)

	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,
		mapper: h.mapper,

		ch:           updateChan,
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
	return m.req.Stream && !m.req.ReadOnly
}

func (m *mapSession) isEndpointUpdate() bool {
	return !m.req.Stream && !m.req.ReadOnly && m.req.OmitPeers
}

func (m *mapSession) isReadOnlyUpdate() bool {
	return !m.req.Stream && m.req.OmitPeers && m.req.ReadOnly
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
	// TODO(kradalby): A set todos to harden:
	// - func to tell the stream to die, readonly -> false, !stream && omitpeers -> false, true

	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then te server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	//
	// This is what Tailscale calls a Lite update, the client ignores
	// the response and just wants a 200.
	// !req.stream && !req.ReadOnly && req.OmitPeers
	//
	// TODO(kradalby): remove ReadOnly when we only support capVer 68+
	if m.isEndpointUpdate() {
		m.handleEndpointUpdate()

		return
	}

	// ReadOnly is whether the client just wants to fetch the
	// MapResponse, without updating their Endpoints. The
	// Endpoints field will be ignored and LastSeen will not be
	// updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at
	// start-up before their first real endpoint update.
	if m.isReadOnlyUpdate() {
		m.handleReadOnlyRequest()

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

		// only update node status if the node channel was removed.
		// in principal, it will be removed, but the client rapidly
		// reconnects, the channel might be of another connection.
		// In that case, it is not closed and the node is still online.
		if m.h.nodeNotifier.RemoveNode(m.node.ID, m.ch) {
			// Failover the node's routes if any.
			m.h.updateNodeOnlineStatus(false, m.node)
			m.pollFailoverRoutes("node closing connection", m.node)
		}

		m.afterServeLongPoll()
		m.infof("node has disconnected, mapSession: %p, chan: %p", m, m.ch)
	}()

	// Set up the client stream
	m.h.pollNetMapStreamWG.Add(1)
	defer m.h.pollNetMapStreamWG.Done()

	m.pollFailoverRoutes("node connected", m.node)

	// Upgrade the writer to a ResponseController
	rc := http.NewResponseController(m.w)

	// Longpolling will break if there is a write timeout,
	// so it needs to be disabled.
	rc.SetWriteDeadline(time.Time{})

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	m.keepAliveTicker = time.NewTicker(m.keepAlive)

	m.h.nodeNotifier.AddNode(m.node.ID, m.ch)
	go m.h.updateNodeOnlineStatus(true, m.node)

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
			if !ok {
				m.tracef("update channel closed, streaming session is likely being replaced")
				return
			}

			// If the node has been removed from headscale, close the stream
			if slices.Contains(update.Removed, m.node.ID) {
				m.tracef("node removed, closing stream")
				return
			}

			m.tracef("received stream update: %s %s", update.Type.String(), update.Message)
			mapResponseUpdateReceived.WithLabelValues(update.Type.String()).Inc()

			var data []byte
			var err error
			var lastMessage string

			// Ensure the node object is updated, for example, there
			// might have been a hostinfo update in a sidechannel
			// which contains data needed to generate a map response.
			m.node, err = m.h.db.GetNodeByID(m.node.ID)
			if err != nil {
				m.errf(err, "Could not get machine from db")

				return
			}

			updateType := "full"
			switch update.Type {
			case types.StateFullUpdate:
				m.tracef("Sending Full MapResponse")
				data, err = m.mapper.FullMapResponse(m.req, m.node, fmt.Sprintf("from mapSession: %p, stream: %t", m, m.isStreaming()))
			case types.StatePeerChanged:
				changed := make(map[types.NodeID]bool, len(update.ChangeNodes))

				for _, nodeID := range update.ChangeNodes {
					changed[nodeID] = true
				}

				lastMessage = update.Message
				m.tracef(fmt.Sprintf("Sending Changed MapResponse: %v", lastMessage))
				data, err = m.mapper.PeerChangedResponse(m.req, m.node, changed, update.ChangePatches, lastMessage)
				updateType = "change"

			case types.StatePeerChangedPatch:
				m.tracef(fmt.Sprintf("Sending Changed Patch MapResponse: %v", lastMessage))
				data, err = m.mapper.PeerChangedPatchResponse(m.req, m.node, update.ChangePatches)
				updateType = "patch"
			case types.StatePeerRemoved:
				changed := make(map[types.NodeID]bool, len(update.Removed))

				for _, nodeID := range update.Removed {
					changed[nodeID] = false
				}
				m.tracef(fmt.Sprintf("Sending Changed MapResponse: %v", lastMessage))
				data, err = m.mapper.PeerChangedResponse(m.req, m.node, changed, update.ChangePatches, lastMessage)
				updateType = "remove"
			case types.StateSelfUpdate:
				lastMessage = update.Message
				m.tracef(fmt.Sprintf("Sending Changed MapResponse: %v", lastMessage))
				// create the map so an empty (self) update is sent
				data, err = m.mapper.PeerChangedResponse(m.req, m.node, make(map[types.NodeID]bool), update.ChangePatches, lastMessage)
				updateType = "remove"
			case types.StateDERPUpdated:
				m.tracef("Sending DERPUpdate MapResponse")
				data, err = m.mapper.DERPMapResponse(m.req, m.node, m.h.DERPMap)
				updateType = "derp"
			}

			if err != nil {
				m.errf(err, "Could not get the create map update")

				return
			}

			// Only send update if there is change
			if data != nil {
				startWrite := time.Now()
				_, err = m.w.Write(data)
				if err != nil {
					mapResponseSent.WithLabelValues("error", updateType).Inc()
					m.errf(err, "could not write the map response(%s), for mapSession: %p", update.Type.String(), m)
					return
				}

				err = rc.Flush()
				if err != nil {
					mapResponseSent.WithLabelValues("error", updateType).Inc()
					m.errf(err, "flushing the map response to client, for mapSession: %p", m)
					return
				}

				log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startWrite).Str("mkey", m.node.MachineKey.String()).Msg("finished writing mapresp to node")

				if debugHighCardinalityMetrics {
					mapResponseLastSentSeconds.WithLabelValues(updateType, m.node.ID.String()).Set(float64(time.Now().Unix()))
				}
				mapResponseSent.WithLabelValues("ok", updateType).Inc()
				m.tracef("update sent")
				m.resetKeepAlive()
			}

		case <-m.keepAliveTicker.C:
			data, err := m.mapper.KeepAliveResponse(m.req, m.node)
			if err != nil {
				m.errf(err, "Error generating the keep alive msg")
				mapResponseSent.WithLabelValues("error", "keepalive").Inc()
				return
			}
			_, err = m.w.Write(data)
			if err != nil {
				m.errf(err, "Cannot write keep alive message")
				mapResponseSent.WithLabelValues("error", "keepalive").Inc()
				return
			}
			err = rc.Flush()
			if err != nil {
				m.errf(err, "flushing keep alive to client, for mapSession: %p", m)
				mapResponseSent.WithLabelValues("error", "keepalive").Inc()
				return
			}

			if debugHighCardinalityMetrics {
				mapResponseLastSentSeconds.WithLabelValues("keepalive", m.node.ID.String()).Set(float64(time.Now().Unix()))
			}
			mapResponseSent.WithLabelValues("ok", "keepalive").Inc()
		}
	}
}

func (m *mapSession) pollFailoverRoutes(where string, node *types.Node) {
	update, err := db.Write(m.h.db.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return db.FailoverNodeRoutesIfNecessary(tx, m.h.nodeNotifier.LikelyConnectedMap(), node)
	})
	if err != nil {
		m.errf(err, fmt.Sprintf("failed to ensure failover routes, %s", where))

		return
	}

	if update != nil && !update.Empty() {
		ctx := types.NotifyCtx(context.Background(), fmt.Sprintf("poll-%s-routes-ensurefailover", strings.ReplaceAll(where, " ", "-")), node.Hostname)
		m.h.nodeNotifier.NotifyWithIgnore(ctx, *update, node.ID)
	}
}

// updateNodeOnlineStatus records the last seen status of a node and notifies peers
// about change in their online/offline status.
// It takes a StateUpdateType of either StatePeerOnlineChanged or StatePeerOfflineChanged.
func (h *Headscale) updateNodeOnlineStatus(online bool, node *types.Node) {
	change := &tailcfg.PeerChange{
		NodeID: tailcfg.NodeID(node.ID),
		Online: &online,
	}

	if !online {
		now := time.Now()

		// lastSeen is only relevant if the node is disconnected.
		node.LastSeen = &now
		change.LastSeen = &now

		err := h.db.Write(func(tx *gorm.DB) error {
			return db.SetLastSeen(tx, node.ID, *node.LastSeen)
		})
		if err != nil {
			log.Error().Err(err).Msg("Cannot update node LastSeen")

			return
		}
	}

	ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-onlinestatus", node.Hostname)
	h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdate{
		Type: types.StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{
			change,
		},
	}, node.ID)
}

func (m *mapSession) handleEndpointUpdate() {
	m.tracef("received endpoint update")

	change := m.node.PeerChangeFromMapRequest(m.req)

	online := m.h.nodeNotifier.IsLikelyConnected(m.node.ID)
	change.Online = &online

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

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change to
	// the routable IPs of the host and update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if routesChanged {
		var err error
		_, err = m.h.db.SaveNodeRoutes(m.node)
		if err != nil {
			m.errf(err, "Error processing node routes")
			http.Error(m.w, "", http.StatusInternalServerError)
			mapResponseEndpointUpdates.WithLabelValues("error").Inc()

			return
		}

		// TODO(kradalby): Only update the node that has actually changed
		nodesChangedHook(m.h.db, m.h.polMan, m.h.nodeNotifier)

		if m.h.polMan != nil {
			// update routes with peer information
			err := m.h.db.EnableAutoApprovedRoutes(m.h.polMan, m.node)
			if err != nil {
				m.errf(err, "Error running auto approved routes")
				mapResponseEndpointUpdates.WithLabelValues("error").Inc()
			}
		}

		// Send an update to the node itself with to ensure it
		// has an updated packetfilter allowing the new route
		// if it is defined in the ACL.
		ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-self-hostinfochange", m.node.Hostname)
		m.h.nodeNotifier.NotifyByNodeID(
			ctx,
			types.StateUpdate{
				Type:        types.StateSelfUpdate,
				ChangeNodes: []types.NodeID{m.node.ID},
			},
			m.node.ID)
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

	ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-peers-patch", m.node.Hostname)
	m.h.nodeNotifier.NotifyWithIgnore(
		ctx,
		types.StateUpdate{
			Type:        types.StatePeerChanged,
			ChangeNodes: []types.NodeID{m.node.ID},
			Message:     "called from handlePoll -> update",
		},
		m.node.ID,
	)

	m.w.WriteHeader(http.StatusOK)
	mapResponseEndpointUpdates.WithLabelValues("ok").Inc()

	return
}

func (m *mapSession) handleReadOnlyRequest() {
	m.tracef("Client asked for a lite update, responding without peers")

	mapResp, err := m.mapper.ReadOnlyMapResponse(m.req, m.node)
	if err != nil {
		m.errf(err, "Failed to create MapResponse")
		http.Error(m.w, "", http.StatusInternalServerError)
		mapResponseReadOnly.WithLabelValues("error").Inc()
		return
	}

	m.w.Header().Set("Content-Type", "application/json; charset=utf-8")
	m.w.WriteHeader(http.StatusOK)
	_, err = m.w.Write(mapResp)
	if err != nil {
		m.errf(err, "Failed to write response")
		mapResponseReadOnly.WithLabelValues("error").Inc()
		return
	}

	m.w.WriteHeader(http.StatusOK)
	mapResponseReadOnly.WithLabelValues("ok").Inc()

	return
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
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Uint64("node.id", node.ID.Uint64()).
				Str("node", node.Hostname).
				Msgf(msg, a...)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
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
	// except for peerapi, which is how nodes talk to eachother.
	// If peerapi was not part of the initial mapresponse, we
	// need to make sure its sent out later as it is needed for
	// Taildrop.
	// TODO(kradalby): Length comparison is a bit naive, replace.
	if len(old.Services) != len(new.Services) {
		return true, false
	}

	return false, false
}
