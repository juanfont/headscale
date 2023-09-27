//go:build ts2019

package hscontrol

import (
	"errors"
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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
	err := machineKey.UnmarshalText([]byte(util.MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot parse client key")

		http.Error(writer, "Cannot parse client key", http.StatusBadRequest)

		return
	}
	mapRequest := tailcfg.MapRequest{}
	err = util.DecodeAndUnmarshalNaCl(body, &mapRequest, &machineKey, h.privateKey2019)
	if err != nil {
		log.Error().
			Str("handler", "PollNetMap").
			Err(err).
			Msg("Cannot decode message")
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	node, err := h.db.GetNodeByMachineKey(machineKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Str("handler", "PollNetMap").
				Msgf("Ignoring request, cannot find node with key %s", machineKey.String())

			http.Error(writer, "", http.StatusUnauthorized)

			return
		}
		log.Error().
			Str("handler", "PollNetMap").
			Msgf("Failed to fetch node from the database with Machine key: %s", machineKey.String())
		http.Error(writer, "", http.StatusInternalServerError)

		return
	}

	log.Trace().
		Str("handler", "PollNetMap").
		Str("id", machineKeyStr).
		Str("node", node.Hostname).
		Msg("A node is sending a MapRequest via legacy protocol")

	capVer, err := parseCabailityVersion(req)
	if err != nil && !errors.Is(err, ErrNoCapabilityVersion) {
		log.Error().
			Caller().
			Err(err).
			Msg("failed to parse capVer")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	h.handlePoll(writer, req.Context(), node, mapRequest, false, capVer)
}
