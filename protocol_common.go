package headscale

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

const (
	// The CapabilityVersion is used by Tailscale clients to indicate
	// their codebase version. Tailscale clients can communicate over TS2021
	// from CapabilityVersion 28, but we only have good support for it
	// since https://github.com/tailscale/tailscale/pull/4323 (Noise in any HTTPS port).
	//
	// Related to this change, there is https://github.com/tailscale/tailscale/pull/5379,
	// where CapabilityVersion 39 is introduced to indicate #4323 was merged.
	//
	// See also https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go
	NoiseCapabilityVersion = 39
)

// KeyHandler provides the Headscale pub key
// Listens in /key.
func (h *Headscale) KeyHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	// New Tailscale clients send a 'v' parameter to indicate the CurrentCapabilityVersion
	clientCapabilityStr := req.URL.Query().Get("v")
	if clientCapabilityStr != "" {
		log.Debug().
			Str("handler", "/key").
			Str("v", clientCapabilityStr).
			Msg("New noise client")
		clientCapabilityVersion, err := strconv.Atoi(clientCapabilityStr)
		if err != nil {
			writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
			writer.WriteHeader(http.StatusBadRequest)
			_, err := writer.Write([]byte("Wrong params"))
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}

		if clientCapabilityVersion >= NoiseCapabilityVersion {
			// Tailscale has a different key for the TS2021 protocol
			resp := tailcfg.OverTLSPublicKeyResponse{
				LegacyPublicKey: h.privateKey.Public(),
				PublicKey:       h.noisePrivateKey.Public(),
			}
			writer.Header().Set("Content-Type", "application/json")
			writer.WriteHeader(http.StatusOK)
			err = json.NewEncoder(writer).Encode(resp)
			if err != nil {
				log.Error().
					Caller().
					Err(err).
					Msg("Failed to write response")
			}

			return
		}
	}
	log.Debug().
		Str("handler", "/key").
		Msg("New legacy client")

	// Old clients don't send a 'v' parameter, so we send the legacy public key
	writer.Header().Set("Content-Type", "text/plain; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err := writer.Write([]byte(MachinePublicKeyStripPrefix(h.privateKey.Public())))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to write response")
	}
}
