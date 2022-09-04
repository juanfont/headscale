package headscale

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
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

		// TS2021 (Tailscale v2 protocol) requires to have a different key
		if clientCapabilityVersion >= NoiseCapabilityVersion {
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

// handleRegisterCommon is the common logic for registering a client in the legacy and Noise protocols
//
// When using Noise, the machineKey is Zero.
func (h *Headscale) handleRegisterCommon(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	now := time.Now().UTC()
	machine, err := h.GetMachineByAnyNodeKey(registerRequest.NodeKey, registerRequest.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKeyCommon(writer, registerRequest, machineKey)

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
					Bool("noise", machineKey.IsZero()).
					Msg("Machine is waiting for interactive login")

				ticker := time.NewTicker(registrationHoldoff)
				select {
				case <-req.Context().Done():
					return
				case <-ticker.C:
					h.handleNewMachineCommon(writer, registerRequest, machineKey)

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
			Bool("noise", machineKey.IsZero()).
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
			MachineKey: MachinePublicKeyStripPrefix(machineKey),
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    NodePublicKeyStripPrefix(registerRequest.NodeKey),
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			log.Trace().
				Caller().
				Bool("noise", machineKey.IsZero()).
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

		h.handleNewMachineCommon(writer, registerRequest, machineKey)

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
				h.handleMachineLogOutCommon(writer, *machine, machineKey)

				return
			}

			// If machine is not expired, and is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.isExpired() {
				h.handleMachineValidRegistrationCommon(writer, *machine, machineKey)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!machine.isExpired() {
			h.handleMachineRefreshKeyCommon(
				writer,
				registerRequest,
				*machine,
				machineKey,
			)

			return
		}

		// The machine has expired
		h.handleMachineExpiredCommon(writer, registerRequest, *machine, machineKey)

		machine.Expiry = &time.Time{}
		h.registrationCache.Set(
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
			*machine,
			registerCacheExpiration,
		)

		return
	}
}

// handleAuthKeyCommon contains the logic to manage auth key client registration
// It is used both by the legacy and the new Noise protocol.
// When using Noise, the machineKey is Zero.
//
// TODO: check if any locks are needed around IP allocation.
func (h *Headscale) handleAuthKeyCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	log.Debug().
		Str("func", "handleAuthKeyCommon").
		Str("machine", registerRequest.Hostinfo.Hostname).
		Bool("noise", machineKey.IsZero()).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.checkKeyValidity(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleAuthKeyCommon").
			Bool("noise", machineKey.IsZero()).
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		respBody, err := h.marshalResponse(resp, machineKey)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKeyCommon").
				Bool("noise", machineKey.IsZero()).
				Str("machine", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()

			return
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err = writer.Write(respBody)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", machineKey.IsZero()).
				Err(err).
				Msg("Failed to write response")
		}

		log.Error().
			Caller().
			Str("func", "handleAuthKeyCommon").
			Bool("noise", machineKey.IsZero()).
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		if pak != nil {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
		} else {
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Str("func", "handleAuthKeyCommon").
		Bool("noise", machineKey.IsZero()).
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
			Bool("noise", machineKey.IsZero()).
			Str("machine", machine.Hostname).
			Msg("machine was already registered before, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		err := h.RefreshMachine(machine, registerRequest.Expiry)

		if err != nil {
			log.Error().
				Caller().
				Bool("noise", machineKey.IsZero()).
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Failed to refresh machine")

			return
		}

		aclTags := pak.toProto().AclTags
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour, although SaaS would reset the tags on auth-key login
			err = h.SetTags(machine, aclTags)
		}

		if err != nil {
			log.Error().
				Caller().
				Bool("noise", machineKey.IsZero()).
				Str("machine", machine.Hostname).
				Strs("aclTags", aclTags).
				Err(err).
				Msg("Failed to set tags after refreshing machine")

			return
		}

	} else {
		now := time.Now().UTC()

		givenName, err := h.GenerateGivenName(registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", machineKey.IsZero()).
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		machineToRegister := Machine{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			NamespaceID:    pak.Namespace.ID,
			MachineKey:     MachinePublicKeyStripPrefix(machineKey),
			RegisterMethod: RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			AuthKeyID:      uint(pak.ID),
			ForcedTags:     pak.toProto().AclTags,
		}

		machine, err = h.RegisterMachine(
			machineToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", machineKey.IsZero()).
				Err(err).
				Msg("could not register machine")
			machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
				Inc()
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	err = h.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Failed to use pre-auth key")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *pak.Namespace.toUser()
	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Str("func", "handleAuthKeyCommon").
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.Namespace.Name).
		Inc()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Str("func", "handleAuthKeyCommon").
		Bool("noise", machineKey.IsZero()).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewMachineCommon exposes for both legacy and Noise the functionality to get a URL
// for authorizing the machine. This url is then showed to the user by the local Tailscale client.
func (h *Headscale) handleNewMachineCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("The node seems to be new, sending auth url")
	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			NodePublicKeyStripPrefix(registerRequest.NodeKey))
	}

	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Bool("noise", machineKey.IsZero()).
			Caller().
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Successfully sent auth url")
}

func (h *Headscale) handleMachineLogOutCommon(
	writer http.ResponseWriter,
	machine Machine,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Client requested logout")

	err := h.ExpireMachine(&machine)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Str("func", "handleMachineLogOutCommon").
			Err(err).
			Msg("Failed to expire machine")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.User = *machine.Namespace.toUser()
	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Bool("noise", machineKey.IsZero()).
			Caller().
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Successfully logged out")
}

func (h *Headscale) handleMachineValidRegistrationCommon(
	writer http.ResponseWriter,
	machine Machine,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *machine.Namespace.toUser()
	resp.Login = *machine.Namespace.toLogin()

	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("update", "web", "error", machine.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("update", "web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Machine successfully authorized")
}

func (h *Headscale) handleMachineRefreshKeyCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	log.Debug().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")
	machine.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)

	if err := h.db.Save(&machine).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to update machine key in the database")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.User = *machine.Namespace.toUser()
	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("old_node_key", registerRequest.OldNodeKey.ShortString()).
		Str("machine", machine.Hostname).
		Msg("Machine successfully refreshed")
}

func (h *Headscale) handleMachineExpiredCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machine Machine,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	// The client has registered before, but has expired
	log.Debug().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Machine registration has expired. Sending a authurl to register")

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKeyCommon(writer, registerRequest, machineKey)

		return
	}

	if h.cfg.OIDC.Issuer != "" {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			NodePublicKeyStripPrefix(registerRequest.NodeKey))
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			NodePublicKeyStripPrefix(registerRequest.NodeKey))
	}

	respBody, err := h.marshalResponse(resp, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("reauth", "web", "error", machine.Namespace.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.Namespace.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", machineKey.IsZero()).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", machineKey.IsZero()).
		Str("machine", machine.Hostname).
		Msg("Auth URL for reauthenticate successfully sent")
}
