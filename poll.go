package headscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	keepAliveInterval   = 60 * time.Second
	updateCheckInterval = 10 * time.Second
)

// PollNetMapHandler takes care of /machine/:id/map
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (h *Headscale) PollNetMapHandler(ctx *gin.Context) {
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", ctx.Param("id")).
		Msg("PollNetMapHandler called")
	body, _ := io.ReadAll(ctx.Request.Body)
	machineKeyStr := ctx.Param("id")

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot parse client key")
		ctx.String(http.StatusBadRequest, "")

		return
	}
	req := tailcfg.MapRequest{}
	err = decode(body, &req, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot decode message")
		ctx.String(http.StatusBadRequest, "")

		return
	}

	machine, err := h.GetValidMachineByMachineKey(machineKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Str("handler", "PollNetMap").
				Msgf("Ignoring request, cannot find machine with key %s", machineKey.String())
			ctx.String(http.StatusUnauthorized, "")

			return
		}
		log.Error().
			Str("handler", "PollNetMap").
			Msgf("Failed to fetch machine from the database with Machine key: %s", machineKey.String())
		ctx.String(http.StatusInternalServerError, "")

		return
	}
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Msg("Found machine in database")

	hname, err := NormalizeToFQDNRules(
		req.Hostinfo.Hostname,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleAuthKey").
			Str("hostinfo.name", req.Hostinfo.Hostname).
			Err(err)
	}
	machine.Name = hname
	machine.HostInfo = HostInfo(*req.Hostinfo)
	machine.DiscoKey = DiscoPublicKeyStripPrefix(req.DiscoKey)
	now := time.Now().UTC()

	// update ACLRules with peer informations (to update server tags if necessary)
	if h.aclPolicy != nil {
		err = h.UpdateACLRules()
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKey").
				Str("machine", machine.Name).
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
	if !req.ReadOnly {
		machine.Endpoints = req.Endpoints
		machine.LastSeen = &now
	}
	h.db.Updates(machine)

	data, err := h.getMapResponse(machineKey, req, machine)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Str("id", ctx.Param("id")).
			Str("machine", machine.Name).
			Err(err).
			Msg("Failed to get Map response")
		ctx.String(http.StatusInternalServerError, ":(")

		return
	}

	// We update our peers if the client is not sending ReadOnly in the MapRequest
	// so we don't distribute its initial request (it comes with
	// empty endpoints to peers)

	// Details on the protocol can be found in https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L696
	log.Debug().
		Str("handler", "PollNetMap").
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Bool("readOnly", req.ReadOnly).
		Bool("omitPeers", req.OmitPeers).
		Bool("stream", req.Stream).
		Msg("Client map request processed")

	if req.ReadOnly {
		log.Info().
			Str("handler", "PollNetMap").
			Str("machine", machine.Name).
			Msg("Client is starting up. Probably interested in a DERP map")
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", data)

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
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Msg("Loading or creating update channel")

	// TODO: could probably remove all that duplication once generics land.
	closeChanWithLog := func(channel interface{}, name string) {
		log.Trace().
			Str("handler", "PollNetMap").
			Str("machine", machine.Name).
			Str("channel", "Done").
			Msg(fmt.Sprintf("Closing %s channel", name))

		switch c := channel.(type) {
		case (chan struct{}):
			close(c)

		case (chan []byte):
			close(c)
		}
	}

	const chanSize = 8
	updateChan := make(chan struct{}, chanSize)
	defer closeChanWithLog(updateChan, "updateChan")

	pollDataChan := make(chan []byte, chanSize)
	defer closeChanWithLog(pollDataChan, "pollDataChan")

	keepAliveChan := make(chan []byte)
	defer closeChanWithLog(keepAliveChan, "keepAliveChan")

	if req.OmitPeers && !req.Stream {
		log.Info().
			Str("handler", "PollNetMap").
			Str("machine", machine.Name).
			Msg("Client sent endpoint update and is ok with a response without peer list")
		ctx.Data(http.StatusOK, "application/json; charset=utf-8", data)

		// It sounds like we should update the nodes when we have received a endpoint update
		// even tho the comments in the tailscale code dont explicitly say so.
		updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Name, "endpoint-update").
			Inc()
		updateChan <- struct{}{}

		return
	} else if req.OmitPeers && req.Stream {
		log.Warn().
			Str("handler", "PollNetMap").
			Str("machine", machine.Name).
			Msg("Ignoring request, don't know how to handle it")
		ctx.String(http.StatusBadRequest, "")

		return
	}

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Name).
		Msg("Client is ready to access the tailnet")
	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Name).
		Msg("Sending initial map")
	pollDataChan <- data

	log.Info().
		Str("handler", "PollNetMap").
		Str("machine", machine.Name).
		Msg("Notifying peers")
	updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Name, "full-update").
		Inc()
	updateChan <- struct{}{}

	h.PollNetMapStream(
		ctx,
		machine,
		req,
		machineKey,
		pollDataChan,
		keepAliveChan,
		updateChan,
	)
	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", ctx.Param("id")).
		Str("machine", machine.Name).
		Msg("Finished stream, closing PollNetMap session")
}

// PollNetMapStream takes care of /machine/:id/map
// stream logic, ensuring we communicate updates and data
// to the connected clients.
func (h *Headscale) PollNetMapStream(
	ctx *gin.Context,
	machine *Machine,
	mapRequest tailcfg.MapRequest,
	machineKey key.MachinePublic,
	pollDataChan chan []byte,
	keepAliveChan chan []byte,
	updateChan chan struct{},
) {
	{
		ctx, cancel := context.WithCancel(ctx.Request.Context())
		defer cancel()

		go h.scheduledPollWorker(
			ctx,
			updateChan,
			keepAliveChan,
			machineKey,
			mapRequest,
			machine,
		)
	}

	ctx.Stream(func(writer io.Writer) bool {
		log.Trace().
			Str("handler", "PollNetMapStream").
			Str("machine", machine.Name).
			Msg("Waiting for data to stream...")

		log.Trace().
			Str("handler", "PollNetMapStream").
			Str("machine", machine.Name).
			Msgf("pollData is %#v, keepAliveChan is %#v, updateChan is %#v", pollDataChan, keepAliveChan, updateChan)

		select {
		case data := <-pollDataChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Sending data received via pollData channel")
			_, err := writer.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot write data")

				return false
			}
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Str("channel", "pollData").
				Int("bytes", len(data)).
				Msg("Data from pollData channel written successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.UpdateMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return false
			}
			now := time.Now().UTC()
			machine.LastSeen = &now

			lastStateUpdate.WithLabelValues(machine.Namespace.Name, machine.Name).
				Set(float64(now.Unix()))
			machine.LastSuccessfulUpdate = &now

			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "pollData").
					Err(err).
					Msg("Cannot update machine LastSuccessfulUpdate")
			} else {
				log.Trace().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "pollData").
					Int("bytes", len(data)).
					Msg("Machine entry in database updated successfully after sending pollData")
			}

			return true

		case data := <-keepAliveChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Sending keep alive message")
			_, err := writer.Write(data)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot write keep alive message")

				return false
			}
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Str("channel", "keepAlive").
				Int("bytes", len(data)).
				Msg("Keep alive sent successfully")
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err = h.UpdateMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return false
			}
			now := time.Now().UTC()
			machine.LastSeen = &now
			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "keepAlive").
					Err(err).
					Msg("Cannot update machine LastSeen")
			} else {
				log.Trace().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "keepAlive").
					Int("bytes", len(data)).
					Msg("Machine updated successfully after sending keep alive")
			}

			return true

		case <-updateChan:
			log.Trace().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Str("channel", "update").
				Msg("Received a request for update")
			updateRequestsReceivedOnChannel.WithLabelValues(machine.Namespace.Name, machine.Name).
				Inc()
			if h.isOutdated(machine) {
				var lastUpdate time.Time
				if machine.LastSuccessfulUpdate != nil {
					lastUpdate = *machine.LastSuccessfulUpdate
				}
				log.Debug().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.Namespace.Name)).
					Msgf("There has been updates since the last successful update to %s", machine.Name)
				data, err := h.getMapResponse(machineKey, mapRequest, machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Name).
						Str("channel", "update").
						Err(err).
						Msg("Could not get the map update")
				}
				_, err = writer.Write(data)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Name).
						Str("channel", "update").
						Err(err).
						Msg("Could not write the map response")
					updateRequestsSentToNode.WithLabelValues(machine.Namespace.Name, machine.Name, "failed").
						Inc()

					return false
				}
				log.Trace().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "update").
					Msg("Updated Map has been sent")
				updateRequestsSentToNode.WithLabelValues(machine.Namespace.Name, machine.Name, "success").
					Inc()

				// Keep track of the last successful update,
				// we sometimes end in a state were the update
				// is not picked up by a client and we use this
				// to determine if we should "force" an update.
				// TODO(kradalby): Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
				err = h.UpdateMachine(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Name).
						Str("channel", "update").
						Err(err).
						Msg("Cannot update machine from database")

					// client has been removed from database
					// since the stream opened, terminate connection.
					return false
				}
				now := time.Now().UTC()

				lastStateUpdate.WithLabelValues(machine.Namespace.Name, machine.Name).
					Set(float64(now.Unix()))
				machine.LastSuccessfulUpdate = &now

				err = h.TouchMachine(machine)
				if err != nil {
					log.Error().
						Str("handler", "PollNetMapStream").
						Str("machine", machine.Name).
						Str("channel", "update").
						Err(err).
						Msg("Cannot update machine LastSuccessfulUpdate")
				}
			} else {
				var lastUpdate time.Time
				if machine.LastSuccessfulUpdate != nil {
					lastUpdate = *machine.LastSuccessfulUpdate
				}
				log.Trace().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Time("last_successful_update", lastUpdate).
					Time("last_state_change", h.getLastStateChange(machine.Namespace.Name)).
					Msgf("%s is up to date", machine.Name)
			}

			return true

		case <-ctx.Request.Context().Done():
			log.Info().
				Str("handler", "PollNetMapStream").
				Str("machine", machine.Name).
				Msg("The client has closed the connection")
				// TODO: Abstract away all the database calls, this can cause race conditions
				// when an outdated machine object is kept alive, e.g. db is update from
				// command line, but then overwritten.
			err := h.UpdateMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "Done").
					Err(err).
					Msg("Cannot update machine from database")

				// client has been removed from database
				// since the stream opened, terminate connection.
				return false
			}
			now := time.Now().UTC()
			machine.LastSeen = &now
			err = h.TouchMachine(machine)
			if err != nil {
				log.Error().
					Str("handler", "PollNetMapStream").
					Str("machine", machine.Name).
					Str("channel", "Done").
					Err(err).
					Msg("Cannot update machine LastSeen")
			}

			return false
		}
	})
}

func (h *Headscale) scheduledPollWorker(
	ctx context.Context,
	updateChan chan<- struct{},
	keepAliveChan chan<- []byte,
	machineKey key.MachinePublic,
	mapRequest tailcfg.MapRequest,
	machine *Machine,
) {
	keepAliveTicker := time.NewTicker(keepAliveInterval)
	updateCheckerTicker := time.NewTicker(updateCheckInterval)

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
				Str("machine", machine.Name).
				Msg("Sending keepalive")
			keepAliveChan <- data

		case <-updateCheckerTicker.C:
			log.Debug().
				Str("func", "scheduledPollWorker").
				Str("machine", machine.Name).
				Msg("Sending update request")
			updateRequestsFromNode.WithLabelValues(machine.Namespace.Name, machine.Name, "scheduled-update").
				Inc()
			updateChan <- struct{}{}
		}
	}
}
