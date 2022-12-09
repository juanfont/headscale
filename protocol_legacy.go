//go:build ts2019

package headscale

import (
	"io"
	"net/http"

	"github.com/gorilla/mux"
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
	err := machineKey.UnmarshalText([]byte(MachinePublicKeyEnsurePrefix(machineKeyStr)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse machine key")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot parse machine key", http.StatusBadRequest)

		return
	}
	registerRequest := tailcfg.RegisterRequest{}
	err = decode(body, &registerRequest, &machineKey, h.privateKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot decode message")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Cannot decode message", http.StatusBadRequest)

		return
	}

	h.handleRegisterCommon(writer, req, registerRequest, machineKey, false)
}
