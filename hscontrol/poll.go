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

const machineNameContextKey = contextKey("machineName")

type UpdateNode func()

func logPollFunc(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	isNoise bool,
) (func(string), func(error, string)) {
	return func(msg string) {
			log.Info().
				Caller().
				Bool("noise", isNoise).
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", machine.NodeKey).
				Str("machine", machine.Hostname).
				Msg(msg)
		},
		func(err error, msg string) {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Bool("readOnly", mapRequest.ReadOnly).
				Bool("omitPeers", mapRequest.OmitPeers).
				Bool("stream", mapRequest.Stream).
				Str("node_key", machine.NodeKey).
				Str("machine", machine.Hostname).
				Err(err).
				Msg(msg)
		}
}

// handlePoll is the common code for the legacy and Noise protocols to
// managed the poll loop.
func (h *Headscale) handlePoll(
	writer http.ResponseWriter,
	ctx context.Context,
	machine *types.Machine,
	mapRequest tailcfg.MapRequest,
	isNoise bool,
) {
	logInfo, logErr := logPollFunc(mapRequest, machine, isNoise)

	mapp := mapper.NewMapper(
		h.db,
		h.privateKey2019,
		isNoise,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
	)

	machine.Hostname = mapRequest.Hostinfo.Hostname
	machine.HostInfo = types.HostInfo(*mapRequest.Hostinfo)
	machine.DiscoKey = util.DiscoPublicKeyStripPrefix(mapRequest.DiscoKey)
	now := time.Now().UTC()

	err := h.db.ProcessMachineRoutes(machine)
	if err != nil {
		logErr(err, "Error processing machine routes")
	}

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.ACLPolicy != nil {
		// update routes with peer information
		err = h.db.EnableAutoApprovedRoutes(h.ACLPolicy, machine)
		if err != nil {
			logErr(err, "Error running auto approved routes")
		}
	}

	// From Tailscale client:
	//
	// ReadOnly is whether the client just wants to fetch the MapResponse,
	// without updating their Endpoints. The Endpoints field will be ignored and
	// LastSeen will not be updated and peers will not be notified of changes.
	//
	// The intended use is for clients to discover the DERP map at start-up
	// before their first real endpoint update.
	if !mapRequest.ReadOnly {
		machine.Endpoints = mapRequest.Endpoints
		machine.LastSeen = &now
	}

	// TODO(kradalby): Save specific stuff, not whole object.
	if err := h.db.MachineSave(machine); err != nil {
		logErr(err, "Failed to persist/update machine in the database")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	mapResp, err := mapp.FullMapResponse(mapRequest, machine, h.ACLPolicy)
	if err != nil {
		logErr(err, "Failed to create MapResponse")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	logInfo("Client map request processed")

	if mapRequest.ReadOnly {
		logInfo("Client is starting up. Probably interested in a DERP map")

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(mapResp)
		if err != nil {
			logErr(err, "Failed to write response")
		}

		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}

		return
	}

	if mapRequest.OmitPeers && !mapRequest.Stream {
		logInfo("Client sent endpoint update and is ok with a response without peer list")

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(mapResp)
		if err != nil {
			logErr(err, "Failed to write response")
		}
		// It sounds like we should update the nodes when we have received a endpoint update
		// even tho the comments in the tailscale code dont explicitly say so.
		updateRequestsFromNode.WithLabelValues(machine.User.Name, machine.Hostname, "endpoint-update").
			Inc()

		// Tell all the other nodes about the new endpoint, but dont update ourselves.
		h.nodeNotifier.NotifyWithIgnore(
			types.StateUpdate{
				Type:    types.StatePeerChanged,
				Changed: []uint64{machine.ID},
			},
			machine.MachineKey)

		return
	} else if mapRequest.OmitPeers && mapRequest.Stream {
		log.Warn().
			Str("handler", "PollNetMap").
			Bool("noise", isNoise).
			Str("machine", machine.Hostname).
			Msg("Ignoring request, don't know how to handle it")
		http.Error(writer, "", http.StatusBadRequest)

		return
	}

	logInfo("Sending initial map")

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

	h.pollNetMapStream(
		writer,
		ctx,
		machine,
		mapp,
		mapRequest,
		isNoise,
	)

	logInfo("Finished stream, closing PollNetMap session")
}

// pollNetMapStream stream logic for /machine/map,
// ensuring we communicate updates and data to the connected clients.
func (h *Headscale) pollNetMapStream(
	writer http.ResponseWriter,
	ctxReq context.Context,
	machine *types.Machine,
	mapp *mapper.Mapper,
	mapRequest tailcfg.MapRequest,
	isNoise bool,
) {
	logInfo, logErr := logPollFunc(mapRequest, machine, isNoise)

	keepAliveTicker := time.NewTicker(keepAliveInterval)

	h.pollNetMapStreamWG.Add(1)
	defer h.pollNetMapStreamWG.Done()

	updateChan := make(chan types.StateUpdate)
	defer closeChanWithLog(updateChan, machine.Hostname, "updateChan")

	// Register the node's update channel
	h.nodeNotifier.AddNode(machine.MachineKey, updateChan)
	defer h.nodeNotifier.RemoveNode(machine.MachineKey)

	ctx := context.WithValue(ctxReq, machineNameContextKey, machine.Hostname)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	for {
		select {
		case <-keepAliveTicker.C:
			data, err := mapp.KeepAliveResponse(mapRequest, machine)
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
				return
			}

			err = h.db.TouchMachine(machine)
			if err != nil {
				logErr(err, "Cannot update machine LastSeen")

				return
			}

		case update := <-updateChan:
			var data []byte
			var err error

			switch update.Type {
			case types.StatePeerChanged:
				logInfo("Sending PeerChanged MapResponse")
				data, err = mapp.PeerChangedResponse(mapRequest, machine, update.Changed, h.ACLPolicy)
			case types.StatePeerRemoved:
				logInfo("Sending PeerRemoved MapResponse")
				data, err = mapp.PeerRemovedResponse(mapRequest, machine, update.Removed)
			case types.StateDERPUpdated:
				logInfo("Sending DERPUpdate MapResponse")
				data, err = mapp.DERPMapResponse(mapRequest, machine, update.DERPMap)
			case types.StateFullUpdate:
				logInfo("Sending Full MapResponse")
				data, err = mapp.FullMapResponse(mapRequest, machine, h.ACLPolicy)
			}

			if err != nil {
				logErr(err, "Could not get the create map update")

				return
			}

			_, err = writer.Write(data)
			if err != nil {
				logErr(err, "Could not write the map response")

				updateRequestsSentToNode.WithLabelValues(machine.User.Name, machine.Hostname, "failed").
					Inc()

				return
			}

			if flusher, ok := writer.(http.Flusher); ok {
				flusher.Flush()
			} else {
				return
			}

			// Keep track of the last successful update,
			// we sometimes end in a state were the update
			// is not picked up by a client and we use this
			// to determine if we should "force" an update.
			err = h.db.TouchMachine(machine)
			if err != nil {
				logErr(err, "Cannot update machine LastSuccessfulUpdate")

				return
			}

		case <-ctx.Done():
			logInfo("The client has closed the connection")

			err := h.db.TouchMachine(machine)
			if err != nil {
				logErr(err, "Cannot update machine LastSeen")
			}

			// The connection has been closed, so we can stop polling.
			return

		case <-h.shutdownChan:
			logInfo("The long-poll handler is shutting down")

			return
		}
	}
}

func closeChanWithLog[C chan []byte | chan struct{} | chan types.StateUpdate](channel C, machine, name string) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("machine", machine).
		Str("channel", "Done").
		Msg(fmt.Sprintf("Closing %s channel", name))

	close(channel)
}
