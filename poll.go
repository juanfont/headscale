package headscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	keepAliveInterval   = 60 * time.Second
	updateCheckInterval = 10 * time.Second
)

type contextKey string

const machineNameContextKey = contextKey("machineName")

// PollNetMapHandler takes care of /machine/:id/map
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (h *Headscale) PollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Str("handler", "PollNetMap").
			Msg("No machine key in request")
		http.Error(writer, "No machine key in request", http.StatusBadRequest)

		return
	}
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", machineKeyStr).
		Msg("PollNetMapHandler called")
	body, _ := io.ReadAll(req.Body)

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot parse client key")

		http.Error(writer, "Cannot parse client key", http.StatusBadRequest)

		return
	}
	mapRequest := tailcfg.MapRequest{}
	err = decode(body, &mapRequest, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot decode message")
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	machine, err := h.GetMachineByMachineKey(machineKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Str("handler", "PollNetMap").
				Msgf("Ignoring request, cannot find machine with key %s", machineKey.String())

			http.Error(writer, "", http.StatusUnauthorized)

			return
		}
		log.Error().
			Str("handler", "PollNetMap").
			Msgf("Failed to fetch machine from the database with Machine key: %s", machineKey.String())
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", machineKeyStr).
		Str("machine", machine.Hostname).
		Msg("Found machine in database")

	machine.Hostname = mapRequest.Hostinfo.Hostname
	machine.HostInfo = HostInfo(*mapRequest.Hostinfo)
	machine.DiscoKey = DiscoPublicKeyStripPrefix(mapRequest.DiscoKey)
	now := time.Now().UTC()

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.aclPolicy != nil {
		err = h.UpdateACLRules()
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKey").
				Str("machine", machine.Hostname).
				Err(err)
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

	if err := h.db.Updates(machine).Error; err != nil {
		if err != nil {
			log.Error().
				Str("handler", "PollNetMap").
				Str("id", machineKeyStr).
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Failed to persist/update machine in the database")
			http.Error(writer, "", http.StatusInternalServerError)

			return
		}
	}

	data, err := h.getMapResponse(machineKey, mapRequest, machine)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Str("id", machineKeyStr).
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
		Str("id", machineKeyStr).
		Str("machine", machine.Hostname).
		Bool("readOnly", mapRequest.ReadOnly).
		Bool("omitPeers", mapRequest.OmitPeers).
		Bool("stream", mapRequest.Stream).
		Msg("Client map request processed")

	if mapRequest.ReadOnly {
		log.Info().
			Str("handler", "PollNetMap").
			Str("machine", machine.Hostname).
			Msg("Client is starting up. Probably interested in a DERP map")

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(data)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		return
	}

	// There has been an update to _any_ of the nodes that the other nodes would
	// need to know about
	h.setLastStateChangeToNow(machine.Namespace.Name)

	// The request is not ReadOnly, so we need to set up channels for updating
	// peers via longpoll

	// Only create update channel if it has not been created
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", machineKeyStr).
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
			Str("machine", machine.Hostname).
			Msg("Client sent endpoint update and is ok with a response without peer list")
		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusOK)
		_, err := writer.Write(data)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}
		// It sounds like we should update the nodes when we have received a endpoint update
		// even tho the comments in the tailscale code dont explicitly say so.
		updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Hostname, "endpoint-update").
			Inc()
		updateChan <- struct{}{}

		return
	} else if mapRequest.OmitPeers && mapRequest.Stream {
		log.Warn().
			Str("handler", "PollNetMap").
			Str("machine", machine.Hostname).
			Msg("Ignoring request, don't know how to handle it")
		http.Error(writer, "", http.StatusBadRequest)

		return
	}

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Hostname).
		Msg("Client is ready to access the tailnet")
	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Hostname).
		Msg("Sending initial map")
	pollDataChan <- data

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Hostname).
		Msg("Notifying peers")
	updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Hostname, "full-update").
		Inc()
	updateChan <- struct{}{}

	h.PollNetMapStream(
		writer,
		req,
		machine,
		mapRequest,
		machineKey,
		pollDataChan,
		keepAliveChan,
		updateChan,
	)
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", machineKeyStr).
		Str("machine", machine.Hostname).
		Msg("Finished stream, closing PollNetMap session")
}

// PollNetMapStream takes care of /machine/:id/map
// stream logic, ensuring we communicate updates and data
// to the connected clients.
func (h *Headscale) PollNetMapStream(
	writer http.ResponseWriter,
	req *http.Request,
	machine *Machine,
	mapRequest tailcfg.MapRequest,
	machineKey key.MachinePublic,
	pollDataChan chan []byte,
	keepAliveChan chan []byte,
	updateChan chan struct{},
) {
	ctx := context.WithValue(
		ctx.Request.Context(),
		machineNameContextKey,
		machine.Hostname,
	)
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	go h.scheduledPollWorker(
		ctx,
		updateChan,
		keepAliveChan,
		machineKey,
		mapRequest,
		machine,
	)

	log.Trace().
		Str("handler", "PollNetMapStream").
		Str("machine", machine.Hostname).
		Msg("Waiting for data to stream...")

	log.Trace().
		Str("handler", "PollNetMapStream").
		Str("machine", machine.Hostname).
		Msgf("pollData is %#v, keepAliveChan is %#v, updateChan is %#v", pollDataChan, keepAliveChan, updateChan)

	for {
		select {
		case data := <-pollDataChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Sending data received via pollData channel")
			_, err := writer.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
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
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Msg("Cannot cast writer to http.Flusher")
			} else {
				flusher.Flush()
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Data from pollData channel written successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
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

			lastStateUpdate.WithLabelValues(machine.Namespace.Name, machine.Hostname).
				Set(float64(now.Unix()))
			machine.LastSuccessfulUpdate = &now

			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Hostname).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot update machine LastSuccessfulUpdate")

				return
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
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
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Msg("Cannot cast writer to http.Flusher")
			} else {
				flusher.Flush()
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Keep alive sent successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
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
			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Hostname).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot update machine LastSeen")

				return
			}

			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Machine updated successfully after sending keep alive")

		case <-updateChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Hostname).
				Str("channel", "update").
				Msg("Received a request for update")
			updateRequestsReceivedOnChannel.WithLabelValues(machine.Namespace.Name, machine.Hostname).
				Inc()

			if h.isOutdated(machine) {
				var lastUpdate time.Time
				if machine.LastSuccessfulUpdate != nil {
					lastUpdate = *machine.LastSuccessfulUpdate
				}
				log.Debug().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Hostname).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.Namespace.Name)).
					Msgf("There has been updates since the last successful update to %s", machine.Hostname)
				data, err := h.getMapResponse(machineKey, mapRequest, machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
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
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Could not write the map response")
					updateRequestsSentToNode.WithLabelValues(machine.Namespace.Name, machine.Hostname, "failed").
						Inc()

					return
				}

				flusher, ok := writer.(http.Flusher)
				if !ok {
					log.Error().
						Caller().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Msg("Cannot cast writer to http.Flusher")
				} else {
					flusher.Flush()
				}

				log.Trace().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Hostname).
					Str("channel", "update").
					Msg("Updated Map has been sent")
				updateRequestsSentToNode.WithLabelValues(machine.Namespace.Name, machine.Hostname, "success").
					Inc()

				// Keep track of the last successful update,
				// we sometimes end in a state were the update
				// is not picked up by a client and we use this
				// to determine if we should "force" an update.
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
				err = h.UpdateMachineFromDatabase(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Hostname).
						Str("channel", "update").
						Err(err).
						Msg("Cannot update machine from database")

					// client has been removed from database
					// since the stream opened, terminate connection.
					return
				}
				now := time.Now().UTC()

				lastStateUpdate.WithLabelValues(machine.Namespace.Name, machine.Hostname).
					Set(float64(now.Unix()))
				machine.LastSuccessfulUpdate = &now

				err = h.TouchMachine(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
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
					Str("machine", machine.Hostname).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.Namespace.Name)).
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
			err := h.UpdateMachineFromDatabase(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
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
			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
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
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
	machine *Machine,
) {
	keepAliveTicker := time.NewTicker(keepAliveInterval)
	updateCheckerTicker := time.NewTicker(updateCheckInterval)

	defer closeChanWithLog(
		updateChan,
		fmt.Sprint(ctx.Value(machineNameContextKey)),
		"updateChan",
	)
	defer closeChanWithLog(
		keepAliveChan,
		fmt.Sprint(ctx.Value(machineNameContextKey)),
		"updateChan",
	)

	for {
		select {
		case <-ctx.Done():
			return

		case <-keepAliveTicker.C:
			data, err := h.getMapKeepAliveResponse(machineKey, mapRequest)
			if err != nil {
				log.Error().
					Str("func", "keepAlive").
					Err(err).
					Msg("Error generating the keep alive msg")

				return
			}

			log.Debug().
				Str("func", "keepAlive").
				Str("machine", machine.Hostname).
				Msg("Sending keepalive")
			keepAliveChan <- data

		case <-updateCheckerTicker.C:
			log.Debug().
				Str("func", "scheduledPollWorker").
				Str("machine", machine.Hostname).
				Msg("Sending update request")
			updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Hostname, "scheduled-update").
				Inc()
			updateChan <- struct{}{}
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
