//go:build ts2019

package hscontrol

import (
	"io"
	"net/http"

	"github.com/gorilla/mux"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// RegistrationHandler handles the actual registration process of a machine
// Endpoint /machine/:mkey.
func (h *Headscale) RegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	vars := mux.Vars(req)
	machineKeyStr, ok := vars["mkey"]
	if !ok || machineKeyStr == "" {
		log.Error().
			Str("handler", "RegistrationHandler").
			Msg("No machine ID in request")
		http.Error(writer, "No machine ID in request", http.StatusBadRequest)

		return
	}

	body, _ := io.ReadAll(req.Body)

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(util.MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse machine key")
		nodeRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot parse machine key", http.StatusBadRequest)

		return
	}
	registerRequest := tailcfg.RegisterRequest{}
	err = util.DecodeAndUnmarshalNaCl(body, &registerRequest, &machineKey, h.privateKey2019)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")
		nodeRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	h.handleRegister(writer, req, registerRequest, machineKey, false)
}
