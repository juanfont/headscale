package hscontrol

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	xslices "golang.org/x/exp/slices"
	"gorm.io/gorm"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

const (
	keepAliveInterval = 50 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type UpdateNode func()

type mapSession struct {
	h      *Headscale
	req    tailcfg.MapRequest
	ctx    context.Context
	capVer tailcfg.CapabilityVersion

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
	warnf, tracef, infof, errf := logPollFunc(req, node)
	return &mapSession{
		h:      h,
		ctx:    ctx,
		req:    req,
		w:      w,
		node:   node,
		capVer: req.Version,

		warnf:  warnf,
		infof:  infof,
		tracef: tracef,
		errf:   errf,
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

func (m *mapSession) flush200() {
	m.w.WriteHeader(http.StatusOK)
	if f, ok := m.w.(http.Flusher); ok {
		f.Flush()
	}
}

// handlePoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
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

	// After version, all streaming requests can be treated as read only.
	if m.capVer < 68 {
		// Error has been handled/written to client in the func
		// return
		err := m.handleSaveNode()
		if err != nil {
			return
		}
	}

	// Set up the client stream
	m.h.pollNetMapStreamWG.Add(1)
	defer m.h.pollNetMapStreamWG.Done()

	// Use a buffered channel in case a node is not fully ready
	// to receive a message to make sure we dont block the entire
	// notifier.
	// 12 is arbitrarily chosen.
	chanSize := 3
	if size, ok := envknob.LookupInt("HEADSCALE_TUNING_POLL_QUEUE_SIZE"); ok {
		chanSize = size
	}
	updateChan := make(chan types.StateUpdate, chanSize)
	defer closeChanWithLog(updateChan, m.node.Hostname, "updateChan")

	// Register the node's update channel
	m.h.nodeNotifier.AddNode(m.node.MachineKey, updateChan)
	defer m.h.nodeNotifier.RemoveNode(m.node.MachineKey)

	mapp := mapper.NewMapper(
		m.node,
		m.h.DERPMap,
		m.h.cfg.BaseDomain,
		m.h.cfg.DNSConfig,
		m.h.cfg.LogTail.Enabled,
		m.h.cfg.RandomizeClientPort,
	)

	// update ACLRules with peer informations (to update server tags if necessary)
	if m.h.ACLPolicy != nil {
		// update routes with peer information
		// This state update is ignored as it will be sent
		// as part of the whole node
		// TODO(kradalby): figure out if that is actually correct
		_, err := m.h.db.EnableAutoApprovedRoutes(m.h.ACLPolicy, m.node)
		if err != nil {
			m.errf(err, "Error running auto approved routes")
		}
	}

	m.tracef("Sending initial map")

	peers, err := m.h.db.ListPeers(m.node)
	if err != nil {
		m.errf(err, "Failed to list peers when opening poller")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	isConnected := m.h.nodeNotifier.ConnectedMap()
	for _, peer := range peers {
		online := isConnected[peer.MachineKey]
		peer.IsOnline = &online
	}

	mapResp, err := mapp.FullMapResponse(m.req, m.node, peers, m.h.ACLPolicy)
	if err != nil {
		m.errf(err, "Failed to create MapResponse")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	// Send the client an update to make sure we send an initial mapresponse
	_, err = m.w.Write(mapResp)
	if err != nil {
		m.errf(err, "Could not write the map response")

		return
	}

	if flusher, ok := m.w.(http.Flusher); ok {
		flusher.Flush()
	} else {
		return
	}

	stateUpdate := types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: types.Nodes{m.node},
		Message:     "called from handlePoll -> new node added",
	}
	if stateUpdate.Valid() {
		ctx := types.NotifyCtx(context.Background(), "poll-newnode-peers", m.node.Hostname)
		m.h.nodeNotifier.NotifyWithIgnore(
			ctx,
			stateUpdate,
			m.node.MachineKey.String())
	}

	if len(m.node.Routes) > 0 {
		go m.pollFailoverRoutes("new node", m.node)
	}

	keepAliveTicker := time.NewTicker(keepAliveInterval + (time.Duration(rand.IntN(9000)) * time.Millisecond))

	ctx, cancel := context.WithCancel(context.WithValue(m.ctx, nodeNameContextKey, m.node.Hostname))
	defer cancel()

	for {
		m.tracef("Waiting for update on stream channel")
		select {
		case <-keepAliveTicker.C:
			data, err := mapp.KeepAliveResponse(m.req, m.node)
			if err != nil {
				m.errf(err, "Error generating the keep alive msg")

				return
			}
			_, err = m.w.Write(data)
			if err != nil {
				m.errf(err, "Cannot write keep alive message")

				return
			}
			if flusher, ok := m.w.(http.Flusher); ok {
				flusher.Flush()
			} else {
				log.Error().Msg("Failed to create http flusher")

				return
			}

			// This goroutine is not ideal, but we have a potential issue here
			// where it blocks too long and that holds up updates.
			// One alternative is to split these different channels into
			// goroutines, but then you might have a problem without a lock
			// if a keepalive is written at the same time as an update.
			go m.h.updateNodeOnlineStatus(true, m.node)

		case update := <-updateChan:
			m.tracef("Received update")
			var data []byte
			var err error

			// Ensure the node object is updated, for example, there
			// might have been a hostinfo update in a sidechannel
			// which contains data needed to generate a map response.
			m.node, err = m.h.db.GetNodeByMachineKey(m.node.MachineKey)
			if err != nil {
				m.errf(err, "Could not get machine from db")

				return
			}

			peers, err := m.h.db.ListPeers(m.node)
			if err != nil {
				m.errf(err, "Failed to list peers when opening poller")
				http.Error(m.w, "", http.StatusInternalServerError)

				return
			}

			isConnected := m.h.nodeNotifier.ConnectedMap()
			for _, peer := range peers {
				online := isConnected[peer.MachineKey]
				peer.IsOnline = &online
			}

			startMapResp := time.Now()
			switch update.Type {
			case types.StateFullUpdate:
				m.tracef("Sending Full MapResponse")

				data, err = mapp.FullMapResponse(m.req, m.node, peers, m.h.ACLPolicy)
			case types.StatePeerChanged:
				m.tracef(fmt.Sprintf("Sending Changed MapResponse: %s", update.Message))

				isConnectedMap := m.h.nodeNotifier.ConnectedMap()
				for _, node := range update.ChangeNodes {
					// If a node is not reported to be online, it might be
					// because the value is outdated, check with the notifier.
					// However, if it is set to Online, and not in the notifier,
					// this might be because it has announced itself, but not
					// reached the stage to actually create the notifier channel.
					if node.IsOnline != nil && !*node.IsOnline {
						isOnline := isConnectedMap[node.MachineKey]
						node.IsOnline = &isOnline
					}
				}

				data, err = mapp.PeerChangedResponse(m.req, m.node, peers, update.ChangeNodes, m.h.ACLPolicy, update.Message)
			case types.StatePeerChangedPatch:
				m.tracef("Sending PeerChangedPatch MapResponse")
				data, err = mapp.PeerChangedPatchResponse(m.req, m.node, update.ChangePatches, m.h.ACLPolicy)
			case types.StatePeerRemoved:
				m.tracef("Sending PeerRemoved MapResponse")
				data, err = mapp.PeerRemovedResponse(m.req, m.node, update.Removed)
			case types.StateSelfUpdate:
				if len(update.ChangeNodes) == 1 {
					m.tracef("Sending SelfUpdate MapResponse")
					m.node = update.ChangeNodes[0]
					data, err = mapp.ReadOnlyMapResponse(m.req, m.node, m.h.ACLPolicy, types.SelfUpdateIdentifier)
				} else {
					m.warnf("SelfUpdate contained too many nodes, this is likely a bug in the code, please report.")
				}
			case types.StateDERPUpdated:
				m.tracef("Sending DERPUpdate MapResponse")
				data, err = mapp.DERPMapResponse(m.req, m.node, update.DERPMap)
			}

			if err != nil {
				m.errf(err, "Could not get the create map update")

				return
			}

			log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startMapResp).Str("mkey", m.node.MachineKey.String()).Int("type", int(update.Type)).Msg("finished making map response")

			// Only send update if there is change
			if data != nil {
				startWrite := time.Now()
				_, err = m.w.Write(data)
				if err != nil {
					m.errf(err, "Could not write the map response")

					updateRequestsSentToNode.WithLabelValues(m.node.User.Name, m.node.Hostname, "failed").
						Inc()

					return
				}

				if flusher, ok := m.w.(http.Flusher); ok {
					flusher.Flush()
				} else {
					log.Error().Msg("Failed to create http flusher")

					return
				}
				log.Trace().Str("node", m.node.Hostname).TimeDiff("timeSpent", time.Now(), startWrite).Str("mkey", m.node.MachineKey.String()).Int("type", int(update.Type)).Msg("finished writing mapresp to node")

				m.infof("update sent")
			}

		case <-ctx.Done():
			m.tracef("The client has closed the connection")

			go m.h.updateNodeOnlineStatus(false, m.node)

			// Failover the node's routes if any.
			go m.pollFailoverRoutes("node closing connection", m.node)

			// The connection has been closed, so we can stop polling.
			return

		case <-m.h.shutdownChan:
			m.tracef("The long-poll handler is shutting down")

			return
		}
	}
}

func (m *mapSession) pollFailoverRoutes(where string, node *types.Node) {
	update, err := db.Write(m.h.db.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
		return db.EnsureFailoverRouteIsAvailable(tx, m.h.nodeNotifier.ConnectedMap(), node)
	})
	if err != nil {
		m.errf(err, fmt.Sprintf("failed to ensure failover routes, %s", where))

		return
	}

	if update != nil && !update.Empty() && update.Valid() {
		ctx := types.NotifyCtx(context.Background(), fmt.Sprintf("poll-%s-routes-ensurefailover", strings.ReplaceAll(where, " ", "-")), node.Hostname)
		m.h.nodeNotifier.NotifyWithIgnore(ctx, *update, node.MachineKey.String())
	}
}

// updateNodeOnlineStatus records the last seen status of a node and notifies peers
// about change in their online/offline status.
// It takes a StateUpdateType of either StatePeerOnlineChanged or StatePeerOfflineChanged.
func (h *Headscale) updateNodeOnlineStatus(online bool, node *types.Node) {
	now := time.Now()

	node.LastSeen = &now

	statusUpdate := types.StateUpdate{
		Type: types.StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{
			{
				NodeID:   tailcfg.NodeID(node.ID),
				Online:   &online,
				LastSeen: &now,
			},
		},
	}
	if statusUpdate.Valid() {
		ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-onlinestatus", node.Hostname)
		h.nodeNotifier.NotifyWithIgnore(ctx, statusUpdate, node.MachineKey.String())
	}

	err := h.db.DB.Transaction(func(tx *gorm.DB) error {
		return db.UpdateLastSeen(tx, node.ID, *node.LastSeen)
	})
	if err != nil {
		log.Error().Err(err).Msg("Cannot update node LastSeen")

		return
	}
}

func closeChanWithLog[C chan []byte | chan struct{} | chan types.StateUpdate](channel C, node, name string) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("node", node).
		Str("channel", "Done").
		Msg(fmt.Sprintf("Closing %s channel", name))

	close(channel)
}

func (m *mapSession) handleEndpointUpdate() {
	m.infof("Received update")

	change := m.node.PeerChangeFromMapRequest(m.req)

	online := m.h.nodeNotifier.IsConnected(m.node.MachineKey)
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	hostInfoChange := m.node.Hostinfo.Equal(m.req.Hostinfo)

	logTracePeerChange(m.node.Hostname, hostInfoChange, &change)

	// Check if the Hostinfo of the node has changed.
	// If it has changed, check if there has been a change tod
	// the routable IPs of the host and update update them in
	// the database. Then send a Changed update
	// (containing the whole node object) to peers to inform about
	// the route change.
	// If the hostinfo has changed, but not the routes, just update
	// hostinfo and let the function continue.
	if !hostInfoChange {
		oldRoutes := m.node.Hostinfo.RoutableIPs
		newRoutes := m.req.Hostinfo.RoutableIPs

		oldServicesCount := len(m.node.Hostinfo.Services)
		newServicesCount := len(m.req.Hostinfo.Services)

		m.node.Hostinfo = m.req.Hostinfo

		sendUpdate := false

		// Route changes come as part of Hostinfo, which means that
		// when an update comes, the Node Route logic need to run.
		// This will require a "change" in comparison to a "patch",
		// which is more costly.
		if !xslices.Equal(oldRoutes, newRoutes) {
			var err error
			sendUpdate, err = m.h.db.SaveNodeRoutes(m.node)
			if err != nil {
				m.errf(err, "Error processing node routes")
				http.Error(m.w, "", http.StatusInternalServerError)

				return
			}

			if m.h.ACLPolicy != nil {
				// update routes with peer information
				update, err := m.h.db.EnableAutoApprovedRoutes(m.h.ACLPolicy, m.node)
				if err != nil {
					m.errf(err, "Error running auto approved routes")
				}

				if update != nil {
					sendUpdate = true
				}
			}
		}

		// Services is mostly useful for discovery and not critical,
		// except for peerapi, which is how nodes talk to eachother.
		// If peerapi was not part of the initial mapresponse, we
		// need to make sure its sent out later as it is needed for
		// Taildrop.
		// TODO(kradalby): Length comparison is a bit naive, replace.
		if oldServicesCount != newServicesCount {
			sendUpdate = true
		}

		if sendUpdate {
			if err := m.h.db.DB.Save(m.node).Error; err != nil {
				m.errf(err, "Failed to persist/update node in the database")
				http.Error(m.w, "", http.StatusInternalServerError)

				return
			}

			// Send an update to all peers to propagate the new routes
			// available.
			stateUpdate := types.StateUpdate{
				Type:        types.StatePeerChanged,
				ChangeNodes: types.Nodes{m.node},
				Message:     "called from handlePoll -> update -> new hostinfo",
			}
			if stateUpdate.Valid() {
				ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-peers-hostinfochange", m.node.Hostname)
				m.h.nodeNotifier.NotifyWithIgnore(
					ctx,
					stateUpdate,
					m.node.MachineKey.String())
			}

			// Send an update to the node itself with to ensure it
			// has an updated packetfilter allowing the new route
			// if it is defined in the ACL.
			selfUpdate := types.StateUpdate{
				Type:        types.StateSelfUpdate,
				ChangeNodes: types.Nodes{m.node},
			}
			if selfUpdate.Valid() {
				ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-self-hostinfochange", m.node.Hostname)
				m.h.nodeNotifier.NotifyByMachineKey(
					ctx,
					selfUpdate,
					m.node.MachineKey)
			}

			return
		}
	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		m.errf(err, "Failed to persist/update node in the database")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	stateUpdate := types.StateUpdate{
		Type:          types.StatePeerChangedPatch,
		ChangePatches: []*tailcfg.PeerChange{&change},
	}
	if stateUpdate.Valid() {
		ctx := types.NotifyCtx(context.Background(), "poll-nodeupdate-peers-patch", m.node.Hostname)
		m.h.nodeNotifier.NotifyWithIgnore(
			ctx,
			stateUpdate,
			m.node.MachineKey.String())
	}

	m.flush200()

	return
}

func (m *mapSession) handleSaveNode() error {
	change := m.node.PeerChangeFromMapRequest(m.req)

	// A stream is being set up, the node is Online
	online := true
	change.Online = &online

	m.node.ApplyPeerChange(&change)

	// Only save HostInfo if changed, update routes if changed
	// TODO(kradalby): Remove when capver is over 68
	if !m.node.Hostinfo.Equal(m.req.Hostinfo) {
		oldRoutes := m.node.Hostinfo.RoutableIPs
		newRoutes := m.req.Hostinfo.RoutableIPs

		m.node.Hostinfo = m.req.Hostinfo

		if !xslices.Equal(oldRoutes, newRoutes) {
			_, err := m.h.db.SaveNodeRoutes(m.node)
			if err != nil {
				m.errf(err, "Error processing node routes")
				http.Error(m.w, "", http.StatusInternalServerError)

				return err
			}
		}
	}

	if err := m.h.db.DB.Save(m.node).Error; err != nil {
		m.errf(err, "Failed to persist/update node in the database")
		http.Error(m.w, "", http.StatusInternalServerError)

		return err
	}

	return nil
}

func (m *mapSession) handleReadOnlyRequest() {
	mapp := mapper.NewMapper(
		m.node,
		m.h.DERPMap,
		m.h.cfg.BaseDomain,
		m.h.cfg.DNSConfig,
		m.h.cfg.LogTail.Enabled,
		m.h.cfg.RandomizeClientPort,
	)

	m.tracef("Client asked for a lite update, responding without peers")

	mapResp, err := mapp.ReadOnlyMapResponse(m.req, m.node, m.h.ACLPolicy)
	if err != nil {
		m.errf(err, "Failed to create MapResponse")
		http.Error(m.w, "", http.StatusInternalServerError)

		return
	}

	m.w.Header().Set("Content-Type", "application/json; charset=utf-8")
	m.w.WriteHeader(http.StatusOK)
	_, err = m.w.Write(mapResp)
	if err != nil {
		m.errf(err, "Failed to write response")
	}

	m.flush200()
}

func logTracePeerChange(hostname string, hostinfoChange bool, change *tailcfg.PeerChange) {
	trace := log.Trace().Str("node_id", change.NodeID.String()).Str("hostname", hostname)

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
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a)
		},
		func(msg string, a ...any) {
			log.Info().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a)
		},
		func(msg string, a ...any) {
			log.Trace().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msgf(msg, a)
		},
		func(err error, msg string, a ...any) {
			log.Error().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Err(err).
				Msgf(msg, a)
		}
}
