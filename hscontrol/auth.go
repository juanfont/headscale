package hscontrol

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/mapper"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

// handleRegister is the common logic for registering a client in the legacy and Noise protocols
//
// When using Noise, the machineKey is Zero.
func (h *Headscale) handleRegister(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	now := time.Now().UTC()
	machine, err := h.db.GetMachineByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the machine has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKey(writer, registerRequest, machineKey, isNoise)

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
			if _, ok := h.registrationCache.Get(util.NodePublicKeyStripPrefix(registerRequest.NodeKey)); ok {
				log.Debug().
					Caller().
					Str("machine", registerRequest.Hostinfo.Hostname).
					Str("machine_key", machineKey.ShortString()).
					Str("node_key", registerRequest.NodeKey.ShortString()).
					Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
					Str("follow_up", registerRequest.Followup).
					Bool("noise", isNoise).
					Msg("Machine is waiting for interactive login")

				select {
				case <-req.Context().Done():
					return
				case <-time.After(registrationHoldoff):
					h.handleNewMachine(writer, registerRequest, machineKey, isNoise)

					return
				}
			}
		}

		log.Info().
			Caller().
			Str("machine", registerRequest.Hostinfo.Hostname).
			Str("machine_key", machineKey.ShortString()).
			Str("node_key", registerRequest.NodeKey.ShortString()).
			Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
			Str("follow_up", registerRequest.Followup).
			Bool("noise", isNoise).
			Msg("New machine not yet in the database")

		givenName, err := h.db.GenerateGivenName(
			machineKey.String(),
			registerRequest.Hostinfo.Hostname,
		)
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
		newMachine := types.Machine{
			MachineKey: util.MachinePublicKeyStripPrefix(machineKey),
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    util.NodePublicKeyStripPrefix(registerRequest.NodeKey),
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			log.Trace().
				Caller().
				Bool("noise", isNoise).
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

		h.handleNewMachine(writer, registerRequest, machineKey, isNoise)

		return
	}

	// The machine is already in the DB. This could mean one of the following:
	// - The machine is authenticated and ready to /map
	// - We are doing a key refresh
	// - The machine is logged out (or expired) and pending to be authorized. TODO(juan): We need to keep alive the connection here
	if machine != nil {
		// (juan): For a while we had a bug where we were not storing the MachineKey for the nodes using the TS2021,
		// due to a misunderstanding of the protocol https://github.com/juanfont/headscale/issues/1054
		// So if we have a not valid MachineKey (but we were able to fetch the machine with the NodeKeys), we update it.
		var storedMachineKey key.MachinePublic
		err = storedMachineKey.UnmarshalText(
			[]byte(util.MachinePublicKeyEnsurePrefix(machine.MachineKey)),
		)
		if err != nil || storedMachineKey.IsZero() {
			if err := h.db.MachineSetMachineKey(machine, machineKey); err != nil {
				log.Error().
					Caller().
					Str("func", "RegistrationHandler").
					Str("machine", machine.Hostname).
					Err(err).
					Msg("Error saving machine key to database")

				return
			}
		}

		// If the NodeKey stored in headscale is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered machine, looking for /map
		// - Expired machine wanting to reauthenticate
		if machine.NodeKey == util.NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(now) {
				h.handleMachineLogOut(writer, *machine, machineKey, isNoise)

				return
			}

			// If machine is not expired, and it is register, we have a already accepted this machine,
			// let it proceed with a valid registration
			if !machine.IsExpired() {
				h.handleMachineWithValidRegistration(writer, *machine, machineKey, isNoise)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if machine.NodeKey == util.NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!machine.IsExpired() {
			h.handleMachineKeyRefresh(
				writer,
				registerRequest,
				*machine,
				machineKey,
				isNoise,
			)

			return
		}

		if registerRequest.Followup != "" {
			select {
			case <-req.Context().Done():
				return
			case <-time.After(registrationHoldoff):
			}
		}

		// The machine has expired or it is logged out
		h.handleMachineExpiredOrLoggedOut(writer, registerRequest, *machine, machineKey, isNoise)

		// TODO(juan): RegisterRequest includes an Expiry time, that we could optionally use
		machine.Expiry = &time.Time{}

		// If we are here it means the client needs to be reauthorized,
		// we need to make sure the NodeKey matches the one in the request
		// TODO(juan): What happens when using fast user switching between two
		// headscale-managed tailnets?
		machine.NodeKey = util.NodePublicKeyStripPrefix(registerRequest.NodeKey)
		h.registrationCache.Set(
			util.NodePublicKeyStripPrefix(registerRequest.NodeKey),
			*machine,
			registerCacheExpiration,
		)

		return
	}
}

// handleAuthKey contains the logic to manage auth key client registration
// It is used both by the legacy and the new Noise protocol.
// When using Noise, the machineKey is Zero.
//
// TODO: check if any locks are needed around IP allocation.
func (h *Headscale) handleAuthKey(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	log.Debug().
		Caller().
		Str("machine", registerRequest.Hostinfo.Hostname).
		Bool("noise", isNoise).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.db.ValidatePreAuthKey(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("machine", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()

			return
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err = writer.Write(respBody)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Err(err).
				Msg("Failed to write response")
		}

		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("machine", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		if pak != nil {
			machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()
		} else {
			machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := util.NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve machine information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new machine and we will move
	// on to registration.
	machine, _ := h.db.GetMachineByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if machine != nil {
		log.Trace().
			Caller().
			Bool("noise", isNoise).
			Str("machine", machine.Hostname).
			Msg("machine was already registered before, refreshing with new auth key")

		machine.NodeKey = nodeKey
		machine.AuthKeyID = uint(pak.ID)
		err := h.db.RefreshMachine(machine, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("machine", machine.Hostname).
				Err(err).
				Msg("Failed to refresh machine")

			return
		}

		aclTags := pak.Proto().AclTags
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour, although SaaS would reset the tags on auth-key login
			err = h.db.SetTags(machine, aclTags)

			if err != nil {
				log.Error().
					Caller().
					Bool("noise", isNoise).
					Str("machine", machine.Hostname).
					Strs("aclTags", aclTags).
					Err(err).
					Msg("Failed to set tags after refreshing machine")

				return
			}
		}
	} else {
		now := time.Now().UTC()

		givenName, err := h.db.GenerateGivenName(util.MachinePublicKeyStripPrefix(machineKey), registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		machineToRegister := types.Machine{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			UserID:         pak.User.ID,
			MachineKey:     util.MachinePublicKeyStripPrefix(machineKey),
			RegisterMethod: util.RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			AuthKeyID:      uint(pak.ID),
			ForcedTags:     pak.Proto().AclTags,
		}

		machine, err = h.db.RegisterMachine(
			machineToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Err(err).
				Msg("could not register machine")
			machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	err = h.db.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to use pre-auth key")
		machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *pak.User.TailscaleUser()
	// Provide LoginName when registering with pre-auth key
	// Otherwise it will need to exec `tailscale up` twice to fetch the *LoginName*
	resp.Login = *pak.User.TailscaleLogin()

	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("machine", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "success", pak.User.Name).
		Inc()
	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Bool("noise", isNoise).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(machine.IPAddresses.StringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewMachine exposes for both legacy and Noise the functionality to get a URL
// for authorizing the machine. This url is then showed to the user by the local Tailscale client.
func (h *Headscale) handleNewMachine(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is new, redirect the client to the registration URL
	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("The node seems to be new, sending auth url")

	if h.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			registerRequest.NodeKey,
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			registerRequest.NodeKey)
	}

	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
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
			Bool("noise", isNoise).
			Caller().
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("AuthURL", resp.AuthURL).
		Str("machine", registerRequest.Hostinfo.Hostname).
		Msg("Successfully sent auth url")
}

func (h *Headscale) handleMachineLogOut(
	writer http.ResponseWriter,
	machine types.Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Client requested logout")

	err := h.db.ExpireMachine(&machine)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to expire machine")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.NodeKeyExpired = true
	resp.User = *machine.User.TailscaleUser()
	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
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
			Bool("noise", isNoise).
			Caller().
			Err(err).
			Msg("Failed to write response")

		return
	}

	// Machine is not need after logout
	err = h.db.HardDeleteMachine(&machine)
	if err != nil {
		log.Error().
			Err(err).
			Str("machine", machine.Hostname).
			Msg("Cannot delete ephemeral machine from the database")
	}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Successfully logged out")
}

func (h *Headscale) handleMachineWithValidRegistration(
	writer http.ResponseWriter,
	machine types.Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	// The machine registration is valid, respond with redirect to /map
	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *machine.User.TailscaleUser()
	resp.Login = *machine.User.TailscaleLogin()

	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("update", "web", "error", machine.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("update", "web", "success", machine.User.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("Machine successfully authorized")
}

func (h *Headscale) handleMachineKeyRefresh(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machine types.Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")

	err := h.db.MachineSetNodeKey(&machine, registerRequest.NodeKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to update machine key in the database")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.User = *machine.User.TailscaleUser()
	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
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
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("old_node_key", registerRequest.OldNodeKey.ShortString()).
		Str("machine", machine.Hostname).
		Msg("Node key successfully refreshed")
}

func (h *Headscale) handleMachineExpiredOrLoggedOut(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machine types.Machine,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKey(writer, registerRequest, machineKey, isNoise)

		return
	}

	// The client has registered before, but has expired or logged out
	log.Trace().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Str("machine_key", machineKey.ShortString()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
		Msg("Machine registration has expired or logged out. Sending a auth url to register")

	if h.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			registerRequest.NodeKey)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			registerRequest.NodeKey)
	}

	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Cannot encode message")
		machineRegistrations.WithLabelValues("reauth", "web", "error", machine.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	machineRegistrations.WithLabelValues("reauth", "web", "success", machine.User.Name).
		Inc()

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to write response")
	}

	log.Trace().
		Caller().
		Bool("noise", isNoise).
		Str("machine_key", machineKey.ShortString()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
		Str("machine", machine.Hostname).
		Msg("Machine logged out. Sent AuthURL for reauthentication")
}
