package headscale

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// NoisePollNetMapHandler takes care of /machine/:id/map using the Noise protocol
//
// This is the busiest endpoint, as it keeps the HTTP long poll that updates
// the clients when something in the network changes.
//
// The clients POST stuff like HostInfo and their Endpoints here, but
// only after their first request (marked with the ReadOnly field).
//
// At this moment the updates are sent in a quite horrendous way, but they kinda work.
func (h *Headscale) NoisePollNetMapHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().
		Str("handler", "NoisePollNetMap").
		Msg("PollNetMapHandler called")
	body, _ := io.ReadAll(req.Body)

	mapRequest := tailcfg.MapRequest{}
	if err := json.Unmarshal(body, &mapRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse MapRequest")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	machine, err := h.GetMachineByAnyNodeKey(mapRequest.NodeKey, key.NodePublic{})
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			log.Warn().
				Str("handler", "NoisePollNetMap").
				Msgf("Ignoring request, cannot find machine with key %s", mapRequest.NodeKey.String())
			http.Error(writer, "Internal error", http.StatusNotFound)

			return
		}
		log.Error().
			Str("handler", "NoisePollNetMap").
			Msgf("Failed to fetch machine from the database with node key: %s", mapRequest.NodeKey.String())
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}
	log.Debug().
		Str("handler", "NoisePollNetMap").
		Str("machine", machine.Hostname).
		Msg("A machine is entering polling via the Noise protocol")

	h.handlePollCommon(writer, req.Context(), machine, mapRequest, true)
}
