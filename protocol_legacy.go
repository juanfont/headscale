package headscale

import (
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
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

	now := time.Now().UTC()
	machine, err := h.GetMachineByMachineKey(machineKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		machineKeyStr := MachinePublicKeyStripPrefix(machineKey)

		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKey(writer, req, machineKey, registerRequest)

			return
		}

		// Check if the node is waiting for interactive login.
		//
		// TODO(juan): We could use this field to improve our protocol implementation,
		// and hold the request until the client closes it, or the interactive
		// login is completed (i.e., the user registers the machine).
		// This is not implemented yet, as it is no strictly required. The only side-effect
		// is that the client will hammer headscale with requests until it gets a
		// successful RegisterResponse.
		if registerRequest.Followup != "" {
			if _, ok := h.registrationCache.Get(NodePublicKeyStripPrefix(registerRequest.NodeKey)); ok {
				log.Debug().
					Caller().
					Str("machine", registerRequest.Hostinfo.Hostname).
					Str("node_key", registerRequest.NodeKey.ShortString()).
					Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
					Str("follow_up", registerRequest.Followup).
					Msg("Machine is waiting for interactive login")

				ticker := time.NewTicker(registrationHoldoff)
				select {
				case <-req.Context().Done():
					return
				case <-ticker.C:
					h.handleMachineRegistrationNew(writer, req, machineKey, registerRequest)

					return
				}
			}
		}

		log.Info().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Str("node_key", registerRequest.NodeKey.ShortString()).
			Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
			Str("follow_up", registerRequest.Followup).
			Msg("New machine not yet in the database")

		givenName, err := h.GenerateGivenName(registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		// The machine did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the machine and then keep it around until a callback
		// happens
		newMachine := Machine{
			MachineKey: machineKeyStr,
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    NodePublicKeyStripPrefix(registerRequest.NodeKey),
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			log.Trace().
				Caller().
				Str("machine", registerRequest.Hostinfo.Hostname).
				Time("expiry", registerRequest.Expiry).
				Msg("Non-zero expiry time requested")
			newMachine.Expiry = &registerRequest.Expiry
		}

		h.registrationCache.Set(
			newMachine.NodeKey,
			newMachine,
			registerCacheExpiration,
		)

		h.handleMachineRegistrationNew(writer, req, machineKey, registerRequest)

		return
	}

	// The machine is already registered, so we need to pass through reauth or key update.
	if machine != nil {
		// If the NodeKey stored in headscale is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered machine, looking for the node map
		// - Expired machine wanting to reauthenticate
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(now) {
				h.handleMachineLogOut(writer, req, machineKey, *machine)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleMachineValidRegistration(writer, req, machineKey, *machine)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!machine.isExpired() {
			h.handleMachineRefreshKey(
				writer,
				req,
				machineKey,
				registerRequest,
				*machine,
			)

			return
		}

		// The machine has expired
		h.handleMachineExpired(writer, req, machineKey, registerRequest, *machine)

		return
	}
}
