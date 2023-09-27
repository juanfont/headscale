package hscontrol

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	xslices "golang.org/x/exp/slices"
	"tailscale.com/tailcfg"
)

const (
	keepAliveInterval = 60 * time.Second
)

type contextKey string

const nodeNameContextKey = contextKey("nodeName")

type UpdateNode func()

func logPollFunc(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
) (func(string), func(error, string)) {
	return func(msg string) {
			log.Info().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Msg(msg)
		},
		func(err error, msg string) {
			log.Error().
				Caller().
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey.ShortString()).
				Str("node", node.Hostname).
				Err(err).
				Msg(msg)
		}
}

// handlePoll ensures the node gets the appropriate updates from either
// polling or immediate responses.
//
//nolint:gocyclo
func (h *Headscale) handlePoll(
	writer http.ResponseWriter,
	ctx context.Context,
	node *types.Node,
	mapRequest tailcfg.MapRequest,
) {
	logInfo, logErr := logPollFunc(mapRequest, node)

	// This is the mechanism where the node gives us information about its
	// current configuration.
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then te server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	// TODO(kradalby): remove ReadOnly when we only support capVer 68+
	if mapRequest.OmitPeers && !mapRequest.Stream && !mapRequest.ReadOnly {
		log.Info().
			Caller().
			Bool("readOnly", mapRequest.ReadOnly).
			Bool("omitPeers", mapRequest.OmitPeers).
			Bool("stream", mapRequest.Stream).
			Str("node_key", node.NodeKey.ShortString()).
			Str("node", node.Hostname).
			Int("cap_ver", int(mapRequest.Version)).
			Msg("Received endpoint update")

		change := node.PeerChangeFromMapRequest(mapRequest)

		online := h.nodeNotifier.IsConnected(node.MachineKey)
		change.Online = &online

		node.ApplyPeerChange(&change)

		// Check if the Hostinfo of the node has changed.
		// If it has changed, check if there has been a change tod
		// the routable IPs of the host and update update them in
		// the database. Then send a Changed update
		// (containing the whole node object) to peers to inform about
		// the route change.
		// If the hostinfo has changed, but not the routes, just update
		// hostinfo and let the function continue.
		if !node.Hostinfo.Equal(mapRequest.Hostinfo) {
			oldRoutes := node.Hostinfo.RoutableIPs
			newRoutes := mapRequest.Hostinfo.RoutableIPs

			node.Hostinfo = mapRequest.Hostinfo

			if !xslices.Equal(oldRoutes, newRoutes) {
				err := h.db.SaveNodeRoutes(node)
				if err != nil {
					logErr(err, "Error processing node routes")
					http.Error(writer, "", http.StatusInternalServerError)

					return
				}

				if err := h.db.NodeSave(node); err != nil {
					logErr(err, "Failed to persist/update node in the database")
					http.Error(writer, "", http.StatusInternalServerError)

					return
				}

				stateUpdate := types.StateUpdate{
					Type:        types.StatePeerChanged,
					ChangeNodes: types.Nodes{node},
				}
				if stateUpdate.Valid() {
					h.nodeNotifier.NotifyWithIgnore(
						stateUpdate,
						node.MachineKey.String())
				}

				return
			}
		}

		if err := h.db.NodeSave(node); err != nil {
			logErr(err, "Failed to persist/update node in the database")
			http.Error(writer, "", http.StatusInternalServerError)

			return
		}

		stateUpdate := types.StateUpdate{
			Type:          types.StatePeerChangedPatch,
			ChangePatches: []*tailcfg.PeerChange{&change},
		}
		if stateUpdate.Valid() {
			h.nodeNotifier.NotifyWithIgnore(
				stateUpdate,
				node.MachineKey.String())
		}

		writer.WriteHeader(http.StatusOK)
		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}

		return
	} else if mapRequest.OmitPeers && !mapRequest.Stream && mapRequest.ReadOnly {
		// ReadOnly is whether the client just wants to fetch the
		// MapResponse, without updating their Endpoints. The
		// Endpoints field will be ignored and LastSeen will not be
		// updated and peers will not be notified of changes.
		//
		// The intended use is for clients to discover the DERP map at
		// start-up before their first real endpoint update.
	} else if mapRequest.OmitPeers && !mapRequest.Stream && mapRequest.ReadOnly {
		h.handleLiteRequest(writer, node, mapRequest)

		return
	} else if mapRequest.OmitPeers && mapRequest.Stream {
		logErr(nil, "Ignoring request, don't know how to handle it")

		return
	}

	change := node.PeerChangeFromMapRequest(mapRequest)

	// A stream is being set up, the node is Online
	online := true
	change.Online = &online

	node.ApplyPeerChange(&change)

	// Only save HostInfo if changed, update routes if changed
	// TODO(kradalby): Remove when capver is over 68
	if !node.Hostinfo.Equal(mapRequest.Hostinfo) {
		oldRoutes := node.Hostinfo.RoutableIPs
		newRoutes := mapRequest.Hostinfo.RoutableIPs

		node.Hostinfo = mapRequest.Hostinfo

		if !xslices.Equal(oldRoutes, newRoutes) {
			err := h.db.SaveNodeRoutes(node)
			if err != nil {
				logErr(err, "Error processing node routes")
				http.Error(writer, "", http.StatusInternalServerError)

				return
			}
		}
	}

	if err := h.db.NodeSave(node); err != nil {
		logErr(err, "Failed to persist/update node in the database")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	// When a node connects to control, list the peers it has at
	// that given point, further updates are kept in memory in
	// the Mapper, which lives for the duration of the polling
	// session.
	peers, err := h.db.ListPeers(node)
	if err != nil {
		logErr(err, "Failed to list peers when opening poller")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	for _, peer := range peers {
		online := h.nodeNotifier.IsConnected(peer.MachineKey)
		peer.IsOnline = &online
	}

	mapp := mapper.NewMapper(
		node,
		peers,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
	)

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.ACLPolicy != nil {
		// update routes with peer information
		err = h.db.EnableAutoApprovedRoutes(h.ACLPolicy, node)
		if err != nil {
			logErr(err, "Error running auto approved routes")
		}
	}

	logInfo("Sending initial map")

	log.Trace().Msgf("NODE FULLMAP BEGIN %s", node.Hostname)
	mapResp, err := mapp.FullMapResponse(mapRequest, node, h.ACLPolicy)
	if err != nil {
		logErr(err, "Failed to create MapResponse")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}
	log.Trace().Msgf("NODE FULLMAP END %s", node.Hostname)

	// Send the client an update to make sure we send an initial mapresponse
	_, err = writer.Write(mapResp)
	if err != nil {
		logErr(err, "Could not write the map response")

		return
	}

	if flusher, ok := writer.(http.Flusher); ok {
		flusher.Flush()
	} else {
		return
	}

	stateUpdate := types.StateUpdate{
		Type:        types.StatePeerChanged,
		ChangeNodes: types.Nodes{node},
	}
	if stateUpdate.Valid() {
		h.nodeNotifier.NotifyWithIgnore(
			stateUpdate,
			node.MachineKey.String())
	}

	// Set up the client stream
	h.pollNetMapStreamWG.Add(1)
	defer h.pollNetMapStreamWG.Done()

	// Use a buffered channel in case a node is not fully ready
	// to receive a message to make sure we dont block the entire
	// notifier.
	// 12 is arbitrarily chosen.
	updateChan := make(chan types.StateUpdate, 12)
	defer closeChanWithLog(updateChan, node.Hostname, "updateChan")

	// Register the node's update channel
	h.nodeNotifier.AddNode(node.MachineKey, updateChan)
	defer h.nodeNotifier.RemoveNode(node.MachineKey)

	keepAliveTicker := time.NewTicker(keepAliveInterval)

	ctx = context.WithValue(ctx, nodeNameContextKey, node.Hostname)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	if len(node.Routes) > 0 {
		go h.db.EnsureFailoverRouteIsAvailable(node)
	}

	for {
		logInfo("Waiting for update on stream channel")
		select {
		case <-keepAliveTicker.C:
			data, err := mapp.KeepAliveResponse(mapRequest, node)
			if err != nil {
				logErr(err, "Error generating the keep alive msg")

				return
			}
			_, err = writer.Write(data)
			if err != nil {
				logErr(err, "Cannot write keep alive message")

				return
			}
			if flusher, ok := writer.(http.Flusher); ok {
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
			go h.updateNodeOnlineStatus(true, node)

		case update := <-updateChan:
			logInfo("Received update")
			now := time.Now()

			var data []byte
			var err error

			switch update.Type {
			case types.StateFullUpdate:
				logInfo("Sending Full MapResponse")

				data, err = mapp.FullMapResponse(mapRequest, node, h.ACLPolicy)
			case types.StatePeerChanged:
				logInfo("Sending Changed MapResponse")

				for _, node := range update.ChangeNodes {
					isOnline := h.nodeNotifier.IsConnected(node.MachineKey)
					node.IsOnline = &isOnline
				}

				data, err = mapp.PeerChangedResponse(mapRequest, node, update.ChangeNodes, h.ACLPolicy)
			case types.StatePeerChangedNoPolicy:
				logInfo("Sending PeerChangedWithoutACL MapResponse")

				for _, node := range update.ChangeNodes {
					isOnline := h.nodeNotifier.IsConnected(node.MachineKey)
					node.IsOnline = &isOnline
				}

				data, err = mapp.PeerChangedWithoutACLResponse(mapRequest, node, update.ChangeNodes, h.ACLPolicy)
			case types.StatePeerChangedPatch:
				logInfo("Sending PeerChangedPatch MapResponse")
				data, err = mapp.PeerChangedPatchResponse(mapRequest, node, update.ChangePatches, h.ACLPolicy)
			case types.StatePeerRemoved:
				logInfo("Sending PeerRemoved MapResponse")
				data, err = mapp.PeerRemovedResponse(mapRequest, node, update.Removed)
			case types.StateDERPUpdated:
				logInfo("Sending DERPUpdate MapResponse")
				data, err = mapp.DERPMapResponse(mapRequest, node, update.DERPMap)
			}

			if err != nil {
				logErr(err, "Could not get the create map update")

				return
			}

			// Only send update if there is change
			if data != nil {
				_, err = writer.Write(data)
				if err != nil {
					logErr(err, "Could not write the map response")

					updateRequestsSentToNode.WithLabelValues(node.User.Name, node.Hostname, "failed").
						Inc()

					return
				}

				if flusher, ok := writer.(http.Flusher); ok {
					flusher.Flush()
				} else {
					log.Error().Msg("Failed to create http flusher")

					return
				}

				log.Info().
					Caller().
					Bool("readOnly", mapRequest.ReadOnly).
					Bool("omitPeers", mapRequest.OmitPeers).
					Bool("stream", mapRequest.Stream).
					Str("node_key", node.NodeKey.ShortString()).
					Str("machine_key", node.MachineKey.ShortString()).
					Str("node", node.Hostname).
					TimeDiff("timeSpent", time.Now(), now).
					Msg("update sent")
			}

		case <-ctx.Done():
			logInfo("The client has closed the connection")

			go h.updateNodeOnlineStatus(false, node)

			// Failover the node's routes if any.
			go h.db.FailoverNodeRoutesWithNotify(node)

			// The connection has been closed, so we can stop polling.
			return

		case <-h.shutdownChan:
			logInfo("The long-poll handler is shutting down")

			return
		}
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
		h.nodeNotifier.NotifyWithIgnore(statusUpdate, node.MachineKey.String())
	}

	err := h.db.UpdateLastSeen(node)
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

func (h *Headscale) handleLiteRequest(
	writer http.ResponseWriter,
	node *types.Node,
	mapRequest tailcfg.MapRequest,
) {
	logInfo, logErr := logPollFunc(mapRequest, node)

	mapp := mapper.NewMapper(
		node,
		types.Nodes{},
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
	)

	logInfo("Client asked for a lite update, responding without peers")

	mapResp, err := mapp.LiteMapResponse(mapRequest, node, h.ACLPolicy)
	if err != nil {
		logErr(err, "Failed to create MapResponse")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(mapResp)
	if err != nil {
		logErr(err, "Failed to write response")
	}
}
