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

// handlePoll is the common code for the legacy and Noise protocols to
// managed the poll loop.
func (h *Headscale) handlePoll(
	writer http.ResponseWriter,
	ctx context.Context,
	machine *types.Machine,
	mapRequest tailcfg.MapRequest,
	isNoise bool,
) {
	// TODO(kradalby): This is a stepping stone, mapper should be initiated once
	// per client or something similar
	mapp := mapper.NewMapper(h.db,
		h.privateKey2019,
		isNoise,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
		h.cfg.OIDC.StripEmaildomain,
	)

	machine.Hostname = mapRequest.Hostinfo.Hostname
	machine.HostInfo = types.HostInfo(*mapRequest.Hostinfo)
	machine.DiscoKey = util.DiscoPublicKeyStripPrefix(mapRequest.DiscoKey)
	now := time.Now().UTC()

	err := h.db.ProcessMachineRoutes(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Error processing machine routes")
	}

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.ACLPolicy != nil {
		// update routes with peer information
		err = h.db.EnableAutoApprovedRoutes(h.ACLPolicy, machine)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Error running auto approved routes")
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

	if err := h.db.MachineSave(machine); err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Bool("noise", isNoise).
			Str("node_key", machine.NodeKey).
			Str("machine", machine.Hostname).
			Err(err).
			Msg("Failed to persist/update machine in the database")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	mapResp, err := mapp.CreateMapResponse(mapRequest, machine, h.ACLPolicy)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Bool("noise", isNoise).
			Str("node_key", machine.NodeKey).
			Str("machine", machine.Hostname).
			Err(err).
			Msg("Failed to get Map response")
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	log.Debug().
		Str("handler", "PollNetMap").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Bool("readOnly", mapRequest.ReadOnly).
		Bool("omitPeers", mapRequest.OmitPeers).
		Bool("stream", mapRequest.Stream).
		Msg("Client map request processed")

	if mapRequest.ReadOnly {
		log.Info().
			Str("handler", "PollNetMap").
			Bool("noise", isNoise).
			Str("machine", machine.Hostname).
			Msg("Client is starting up. Probably interested in a DERP map")

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(mapResp)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		if f, ok := writer.(http.Flusher); ok {
			f.Flush()
		}

		return
	}

	// There has been an update to _any_ of the nodes that the other nodes would
	// need to know about
	h.setLastStateChangeToNow()

	// The request is not ReadOnly, so we need to set up channels for updating
	// peers via longpoll

	// Only create update channel if it has not been created
	log.Trace().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Loading or creating update channel")

	const chanSize = 8
	updateChan := make(chan struct{}, chanSize)

	pollDataChan := make(chan []byte, chanSize)
	defer closeChanWithLog(pollDataChan, machine.Hostname, "pollDataChan")

	keepAliveChan := make(chan []byte)

	if mapRequest.OmitPeers && !mapRequest.Stream {
		log.Info().
			Str("handler", "PollNetMap").
			Bool("noise", isNoise).
			Str("machine", machine.Hostname).
			Msg("Client sent endpoint update and is ok with a response without peer list")
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(mapResp)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
		// It sounds like we should update the nodes when we have received a endpoint update
		// even tho the comments in the tailscale code dont explicitly say so.
		updateRequestsFromNode.WithLabelValues(machine.User.Name, machine.Hostname, "endpoint-update").
			Inc()
		updateChan <- struct{}{}

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

	log.Info().
		Str("handler", "PollNetMap").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Client is ready to access the tailnet")
	log.Info().
		Str("handler", "PollNetMap").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Sending initial map")
	pollDataChan <- mapResp

	log.Info().
		Str("handler", "PollNetMap").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Notifying peers")
	updateRequestsFromNode.WithLabelValues(machine.User.Name, machine.Hostname, "full-update").
		Inc()
	updateChan <- struct{}{}

	h.pollNetMapStream(
		writer,
		ctx,
		machine,
		mapRequest,
		pollDataChan,
		keepAliveChan,
		updateChan,
		isNoise,
	)

	log.Trace().
		Str("handler", "PollNetMap").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Finished stream, closing PollNetMap session")
}

// pollNetMapStream stream logic for /machine/map,
// ensuring we communicate updates and data to the connected clients.
func (h *Headscale) pollNetMapStream(
	writer http.ResponseWriter,
	ctxReq context.Context,
	machine *types.Machine,
	mapRequest tailcfg.MapRequest,
	pollDataChan chan []byte,
	keepAliveChan chan []byte,
	updateChan chan struct{},
	isNoise bool,
) {
	// TODO(kradalby): This is a stepping stone, mapper should be initiated once
	// per client or something similar
	mapp := mapper.NewMapper(h.db,
		h.privateKey2019,
		isNoise,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
		h.cfg.OIDC.StripEmaildomain,
	)

	h.pollNetMapStreamWG.Add(1)
	defer h.pollNetMapStreamWG.Done()

	ctx := context.WithValue(ctxReq, machineNameContextKey, machine.Hostname)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go h.scheduledPollWorker(
		ctx,
		updateChan,
		keepAliveChan,
		mapRequest,
		machine,
		isNoise,
	)

	log.Trace().
		Str("handler", "pollNetMapStream").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Waiting for data to stream...")

	log.Trace().
		Str("handler", "pollNetMapStream").
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msgf("pollData is %#v, keepAliveChan is %#v, updateChan is %#v", pollDataChan, keepAliveChan, updateChan)

	for {
		select {
		case data := <-pollDataChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Sending data received via pollData channel")
			_, err := writer.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot write data")

				return
			}

			flusher, ok := writer.(http.Flusher)
			if !ok {
				log.Error().
					Caller().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Msg("Cannot cast writer to http.Flusher")
			} else {
				flusher.Flush()
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Data from pollData channel written successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.db.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return
			}
			now := time.Now().UTC()
			machine.LastSeen = &now

			lastStateUpdate.WithLabelValues(machine.User.Name, machine.Hostname).
				Set(float64(now.Unix()))
			machine.LastSuccessfulUpdate = &now

			err = h.db.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot update machine LastSuccessfulUpdate")

				return
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Machine entry in database updated successfully after sending data")

		case data := <-keepAliveChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Sending keep alive message")
			_, err := writer.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot write keep alive message")

				return
			}
			flusher, ok := writer.(http.Flusher)
			if !ok {
				log.Error().
					Caller().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Msg("Cannot cast writer to http.Flusher")
			} else {
				flusher.Flush()
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Keep alive sent successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.db.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return
			}
			now := time.Now().UTC()
			machine.LastSeen = &now
			err = h.db.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot update machine LastSeen")

				return
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Machine updated successfully after sending keep alive")

		case <-updateChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Str("channel", "update").
				Msg("Received a request for update")
			updateRequestsReceivedOnChannel.WithLabelValues(machine.User.Name, machine.Hostname).
				Inc()

			if h.db.IsOutdated(machine, h.getLastStateChange()) {
				var lastUpdate time.Time
				if machine.LastSuccessfulUpdate != nil {
					lastUpdate = *machine.LastSuccessfulUpdate
				}
				log.Debug().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.User)).
					Msgf("There has been updates since the last successful update to %s", machine.Hostname)
				data, err := mapp.CreateMapResponse(mapRequest, machine, h.ACLPolicy)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Bool("noise", isNoise).
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Could not get the map update")

					return
				}
				_, err = writer.Write(data)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Bool("noise", isNoise).
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Could not write the map response")
					updateRequestsSentToNode.WithLabelValues(machine.User.Name, machine.Hostname, "failed").
						Inc()

					return
				}

				flusher, ok := writer.(http.Flusher)
				if !ok {
					log.Error().
						Caller().
						Str("handler", "PollNetMapStream").
						Bool("noise", isNoise).
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Msg("Cannot cast writer to http.Flusher")
				} else {
					flusher.Flush()
				}

				log.Trace().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "update").
					Msg("Updated Map has been sent")
				updateRequestsSentToNode.WithLabelValues(machine.User.Name, machine.Hostname, "success").
					Inc()

				// Keep track of the last successful update,
				// we sometimes end in a state were the update
				// is not picked up by a client and we use this
				// to determine if we should "force" an update.
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
				err = h.db.UpdateMachineFromDatabase(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Bool("noise", isNoise).
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Cannot update machine from database")

					// client has been removed from database
					// since the stream opened, terminate connection.
					return
				}
				now := time.Now().UTC()

				lastStateUpdate.WithLabelValues(machine.User.Name, machine.Hostname).
					Set(float64(now.Unix()))
				machine.LastSuccessfulUpdate = &now

				err = h.db.TouchMachine(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Bool("noise", isNoise).
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Cannot update machine LastSuccessfulUpdate")

					return
				}
			} else {
				var lastUpdate time.Time
				if machine.LastSuccessfulUpdate != nil {
					lastUpdate = *machine.LastSuccessfulUpdate
				}
				log.Trace().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.User)).
					Msgf("%s is up to date", machine.Hostname)
			}

		case <-ctx.Done():
			log.Info().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Msg("The client has closed the connection")
				// TODO: Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err := h.db.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "Done").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return
			}
			now := time.Now().UTC()
			machine.LastSeen = &now
			err = h.db.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Str("channel", "Done").
					Err(err).
					Msg("Cannot update machine LastSeen")
			}

			// The connection has been closed, so we can stop polling.
			return

		case <-h.shutdownChan:
			log.Info().
				Str("handler", "PollNetMapStream").
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Msg("The long-poll handler is shutting down")

			return
		}
	}
}

func (h *Headscale) scheduledPollWorker(
	ctx context.Context,
	updateChan chan struct{},
	keepAliveChan chan []byte,
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	isNoise bool,
) {
	// TODO(kradalby): This is a stepping stone, mapper should be initiated once
	// per client or something similar
	mapp := mapper.NewMapper(h.db,
		h.privateKey2019,
		isNoise,
		h.DERPMap,
		h.cfg.BaseDomain,
		h.cfg.DNSConfig,
		h.cfg.LogTail.Enabled,
		h.cfg.RandomizeClientPort,
		h.cfg.OIDC.StripEmaildomain,
	)

	keepAliveTicker := time.NewTicker(keepAliveInterval)
	updateCheckerTicker := time.NewTicker(h.cfg.NodeUpdateCheckInterval)

	defer closeChanWithLog(
		updateChan,
		fmt.Sprint(ctx.Value(machineNameContextKey)),
		"updateChan",
	)
	defer closeChanWithLog(
		keepAliveChan,
		fmt.Sprint(ctx.Value(machineNameContextKey)),
		"keepAliveChan",
	)

	for {
		select {
		case <-ctx.Done():
			return

		case <-keepAliveTicker.C:
			data, err := mapp.CreateKeepAliveResponse(mapRequest, machine)
			if err != nil {
				log.Error().
					Str("func", "keepAlive").
					Bool("noise", isNoise).
					Err(err).
					Msg("Error generating the keep alive msg")

				return
			}

			log.Debug().
				Str("func", "keepAlive").
				Str("machine", machine.Hostname).
				Bool("noise", isNoise).
				Msg("Sending keepalive")
			select {
			case keepAliveChan <- data:
			case <-ctx.Done():
				return
			}

		case <-updateCheckerTicker.C:
			log.Debug().
				Str("func", "scheduledPollWorker").
				Str("machine", machine.Hostname).
				Bool("noise", isNoise).
				Msg("Sending update request")
			updateRequestsFromNode.WithLabelValues(machine.User.Name, machine.Hostname, "scheduled-update").
				Inc()
			select {
			case updateChan <- struct{}{}:
			case <-ctx.Done():
				return
			}
		}
	}
}

func closeChanWithLog[C chan []byte | chan struct{}](channel C, machine, name string) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("machine", machine).
		Str("channel", "Done").
		Msg(fmt.Sprintf("Closing %s channel", name))

	close(channel)
}
