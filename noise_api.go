package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// // NoiseRegistrationHandler handles the actual registration process of a machine.
func (h *Headscale) NoiseRegistrationHandler(
	writer http.ResponseWriter,
	req *http.Request,
) {
	log.Trace().Caller().Msgf("Noise registration handler for client %s", req.RemoteAddr)
	if req.Method != http.MethodPost {
		http.Error(writer, "Wrong method", http.StatusMethodNotAllowed)

		return
	}
	body, _ := io.ReadAll(req.Body)
	registerRequest := tailcfg.RegisterRequest{}
	if err := json.Unmarshal(body, &registerRequest); err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse RegisterRequest")
		machineRegistrations.WithLabelValues("unknown", "web", "error", "unknown").Inc()
		http.Error(writer, "Internal error", http.StatusInternalServerError)

		return
	}

	log.Trace().Caller().
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("old_node_key", registerRequest.OldNodeKey.ShortString()).
		Msg("New node is registering")

	now := time.Now().UTC()
	machine, err := h.GetMachineByAnyNodeKey(registerRequest.NodeKey, registerRequest.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleNoiseAuthKey(writer, req, registerRequest)

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
					h.handleNoiseMachineRegistrationNew(writer, req, registerRequest)

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
			Msg("New Noise machine not yet in the database")

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
			MachineKey: "",
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
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
			newMachine,
			registerCacheExpiration,
		)

		h.handleNoiseMachineRegistrationNew(writer, req, registerRequest)

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
			if !registerRequest.Expiry.IsZero() && registerRequest.Expiry.UTC().Before(now) {
				h.handleNoiseNodeLogOut(writer, req, *machine)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleNoiseNodeValidRegistration(writer, req, *machine)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!machine.isExpired() {
			h.handleNoiseNodeRefreshKey(writer, req, registerRequest, *machine)

			return
		}

		// The node has expired
		h.handleNoiseNodeExpired(writer, req, registerRequest, *machine)

		return
	}
}

func (h *Headscale) handleNoiseAuthKey(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
) {
	log.Debug().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msgf("Processing auth key for %s over Noise", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.checkKeyValidity(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		writer.Header().Set("Content-Type", "application/json")
		writer.WriteHeader(http.StatusUnauthorized)
		err = json.NewEncoder(writer).Encode(resp)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to encode response")
		}

		log.Error().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey over Noise")

		if pak != nil {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
		} else {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.GetMachineByAnyNodeKey(registerRequest.NodeKey, registerRequest.OldNodeKey)
	if machine != nil {
		log.Trace().
			Caller().
			Str("machine", machine.Hostname).
			Msg("machine already registered, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		err = h.RefreshMachine(machine, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Failed to refresh machine")

			return
		}
	} else {
		now := time.Now().UTC()

		givenName, err := h.GenerateGivenName(registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		machineToRegister := Machine{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			NamespaceID:    pak.Namespace.ID,
			MachineKey:     "",
			RegisterMethod: RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			AuthKeyID:      uint(pak.ID),
		}

		machine, err = h.RegisterMachine(
			machineToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("could not register machine")
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
			http.Error(writer, "Internal error", http.StatusInternalServerError)

			return
		}
	}

	err = h.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to use pre-auth key")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()

	machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(resp)

	log.Info().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey on Noise")
}

func (h *Headscale) handleNoiseNodeValidRegistration(
	writer http.ResponseWriter,
	req *http.Request,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Str("machine", machine.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *machine.Namespace.toUser()
	resp.Login = *machine.Namespace.toLogin()

	machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
		Inc()
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(resp)
}

func (h *Headscale) handleNoiseMachineRegistrationNew(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("The node is sending us a new NodeKey, sending auth url")
	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), NodePublicKeyStripPrefix(registerRequest.NodeKey))
	}

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(resp)
}

func (h *Headscale) handleNoiseNodeLogOut(
	writer http.ResponseWriter,
	req *http.Request,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Str("machine", machine.Hostname).
		Msg("Client requested logout")

	err := h.ExpireMachine(&machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleMachineLogOut").
			Err(err).
			Msg("Failed to expire machine")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.User = *machine.Namespace.toUser()

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err = json.NewEncoder(writer).Encode(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("could not encode response")
	}
}

func (h *Headscale) handleNoiseNodeRefreshKey(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	log.Debug().
		Str("machine", machine.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")
	machine.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)
	h.db.Save(&machine)

	resp.AuthURL = ""
	resp.User = *machine.Namespace.toUser()

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	json.NewEncoder(writer).Encode(resp)
}

func (h *Headscale) handleNoiseNodeExpired(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
) {
	resp := tailcfg.RegisterResponse{}

	// The client has registered before, but has expired
	log.Debug().
		Caller().
		Str("machine", machine.Hostname).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleNoiseAuthKey(writer, req, registerRequest)

		return
	}

	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), NodePublicKeyStripPrefix(registerRequest.NodeKey))
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"), NodePublicKeyStripPrefix(registerRequest.NodeKey))
	}

	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(http.StatusOK)
	err := json.NewEncoder(writer).Encode(resp)
	if err != nil {
		log.Error().Caller().Err(err).Msg("Failed to encode response")
	}
}
