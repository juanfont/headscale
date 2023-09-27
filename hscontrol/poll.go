package hscontrol

import (
	"context"
	"fmt"
	"net/http"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
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
	isNoise bool,
) (func(string), func(error, string)) {
	return func(msg string) {
			log.Info().
				Caller().
				Bool("noise", isNoise).
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey).
				Str("node", node.Hostname).
				Msg(msg)
		},
		func(err error, msg string) {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey).
				Str("node", node.Hostname).
				Err(err).
				Msg(msg)
		}
}

// handlePoll is the common code for the legacy and Noise protocols to
// managed the poll loop.
//
//nolint:gocyclo
func (h *Headscale) handlePoll(
	writer http.ResponseWriter,
	ctx context.Context,
	node *types.Node,
	mapRequest tailcfg.MapRequest,
	isNoise bool,
	capVer tailcfg.CapabilityVersion,
) {
	logInfo, logErr := logPollFunc(mapRequest, node, isNoise)

	// This is the mechanism where the node gives us inforamtion about its
	// current configuration.
	//
	// If OmitPeers is true, Stream is false, and ReadOnly is false,
	// then te server will let clients update their endpoints without
	// breaking existing long-polling (Stream == true) connections.
	// In this case, the server can omit the entire response; the client
	// only checks the HTTP response status code.
	if mapRequest.OmitPeers && !mapRequest.Stream && !mapRequest.ReadOnly {
		log.Info().
			Caller().
			Bool("noise", isNoise).
			Bool("readOnly", mapRequest.ReadOnly).
			Bool("omitPeers", mapRequest.OmitPeers).
			Bool("stream", mapRequest.Stream).
			Str("node_key", node.NodeKey).
			Str("node", node.Hostname).
			Strs("endpoints", node.Endpoints).
			Msg("Received endpoint update")

		now := time.Now().UTC()
		node.LastSeen = &now
		node.Hostname = mapRequest.Hostinfo.Hostname
		node.HostInfo = types.HostInfo(*mapRequest.Hostinfo)
		node.DiscoKey = util.DiscoPublicKeyStripPrefix(mapRequest.DiscoKey)
		node.Endpoints = mapRequest.Endpoints

		if err := h.db.NodeSave(node); err != nil {
			logErr(err, "Failed to persist/update node in the database")
			http.Error(writer, "", http.StatusInternalServerError)

			return
		}

		err := h.db.SaveNodeRoutes(node)
		if err != nil {
			logErr(err, "Error processing node routes")
			http.Error(writer, "", http.StatusInternalServerError)

			return
		}

		h.nodeNotifier.NotifyWithIgnore(
			types.StateUpdate{
				Type:    types.StatePeerChanged,
				Changed: types.Nodes{node},
			},
			node.MachineKey)

		writer.WriteHeader(http.StatusOK)
		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}

		return

		// ReadOnly is whether the client just wants to fetch the
		// MapResponse, without updating their Endpoints. The
		// Endpoints field will be ignored and LastSeen will not be
		// updated and peers will not be notified of changes.
		//
		// The intended use is for clients to discover the DERP map at
		// start-up before their first real endpoint update.
	} else if mapRequest.OmitPeers && !mapRequest.Stream && mapRequest.ReadOnly {
		h.handleLiteRequest(writer, node, mapRequest, isNoise, capVer)

		return
	} else if mapRequest.OmitPeers && mapRequest.Stream {
		logErr(nil, "Ignoring request, don't know how to handle it")

		return
	}

	now := time.Now().UTC()
	node.LastSeen = &now
	node.Hostname = mapRequest.Hostinfo.Hostname
	node.HostInfo = types.HostInfo(*mapRequest.Hostinfo)
	node.DiscoKey = util.DiscoPublicKeyStripPrefix(mapRequest.DiscoKey)
	node.Endpoints = mapRequest.Endpoints

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

	mapp := mapper.NewMapper(
		node,
		peers,
		h.privateKey2019,
		isNoise,
		capVer,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
	)

	err = h.db.SaveNodeRoutes(node)
	if err != nil {
		logErr(err, "Error processing node routes")
	}

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.ACLPolicy != nil {
		// update routes with peer information
		err = h.db.EnableAutoApprovedRoutes(h.ACLPolicy, node)
		if err != nil {
			logErr(err, "Error running auto approved routes")
		}
	}

	// TODO(kradalby): Save specific stuff, not whole object.
	if err := h.db.NodeSave(node); err != nil {
		logErr(err, "Failed to persist/update node in the database")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	logInfo("Sending initial map")

	mapResp, err := mapp.FullMapResponse(mapRequest, node, h.ACLPolicy)
	if err != nil {
		logErr(err, "Failed to create MapResponse")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

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

	h.nodeNotifier.NotifyWithIgnore(
		types.StateUpdate{
			Type:    types.StatePeerChanged,
			Changed: types.Nodes{node},
		},
		node.MachineKey)

	// Set up the client stream
	h.pollNetMapStreamWG.Add(1)
	defer h.pollNetMapStreamWG.Done()

	updateChan := make(chan types.StateUpdate)
	defer closeChanWithLog(updateChan, node.Hostname, "updateChan")

	// Register the node's update channel
	h.nodeNotifier.AddNode(node.MachineKey, updateChan)
	defer h.nodeNotifier.RemoveNode(node.MachineKey)

	keepAliveTicker := time.NewTicker(keepAliveInterval)

	ctx = context.WithValue(ctx, nodeNameContextKey, node.Hostname)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

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
			go func() {
				err = h.db.UpdateLastSeen(node)
				if err != nil {
					logErr(err, "Cannot update node LastSeen")

					return
				}
			}()

		case update := <-updateChan:
			logInfo("Received update")
			now := time.Now()

			var data []byte
			var err error

			switch update.Type {
			case types.StatePeerChanged:
				logInfo("Sending PeerChanged MapResponse")
				data, err = mapp.PeerChangedResponse(mapRequest, node, update.Changed, h.ACLPolicy)
			case types.StatePeerRemoved:
				logInfo("Sending PeerRemoved MapResponse")
				data, err = mapp.PeerRemovedResponse(mapRequest, node, update.Removed)
			case types.StateDERPUpdated:
				logInfo("Sending DERPUpdate MapResponse")
				data, err = mapp.DERPMapResponse(mapRequest, node, update.DERPMap)
			case types.StateFullUpdate:
				logInfo("Sending Full MapResponse")
				data, err = mapp.FullMapResponse(mapRequest, node, h.ACLPolicy)
			}

			if err != nil {
				logErr(err, "Could not get the create map update")

				return
			}

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

			// See comment in keepAliveTicker
			go func() {
				err = h.db.UpdateLastSeen(node)
				if err != nil {
					logErr(err, "Cannot update node LastSeen")

					return
				}
			}()

			log.Info().
				Caller().
				Bool("noise", isNoise).
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", node.NodeKey).
				Str("node", node.Hostname).
				TimeDiff("timeSpent", time.Now(), now).
				Msg("update sent")
		case <-ctx.Done():
			logInfo("The client has closed the connection")

			go func() {
				err = h.db.UpdateLastSeen(node)
				if err != nil {
					logErr(err, "Cannot update node LastSeen")

					return
				}
			}()

			// The connection has been closed, so we can stop polling.
			return

		case <-h.shutdownChan:
			logInfo("The long-poll handler is shutting down")

			return
		}
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
	isNoise bool,
	capVer tailcfg.CapabilityVersion,
) {
	logInfo, logErr := logPollFunc(mapRequest, node, isNoise)

	mapp := mapper.NewMapper(
		node,
		// TODO(kradalby): It might not be acceptable to send
		// an empty peer list here.
		types.Nodes{},
		h.privateKey2019,
		isNoise,
		capVer,
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
