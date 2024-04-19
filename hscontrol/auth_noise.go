package hscontrol

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// // NoiseRegistrationHandler handles the actual registration process of a node.
func (ns *noiseServer) NoiseRegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise registration handler for client %s", req.RemoteAddr)
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}

	log.Trace().
		Any("headers", req.Header).
		Caller().
		Msg("Headers")

	body, _ := io.ReadAll(req.Body)
	registerRequest := tailcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse RegisterRequest")
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	// Reject unsupported versions
	if registerRequest.Version < MinimumCapVersion {
		log.Info().
			Caller().
			Int("min_version", int(MinimumCapVersion)).
			Int("client_version", int(registerRequest.Version)).
			Msg("unsupported client connected")
		http.Error(writer, "Internal error", http.StatusBadRequest)

		return
	}

	ns.nodeKey = registerRequest.NodeKey

	ns.headscale.handleRegister(writer, req, registerRequest, ns.conn.Peer())
}
