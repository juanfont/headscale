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
	node, err := h.db.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the node has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKey(writer, registerRequest, machineKey, isNoise)

			return
		}

		// Check if the node is waiting for interactive login.
		//
		// TODO(juan): We could use this field to improve our protocol implementation,
		// and hold the request until the client closes it, or the interactive
		// login is completed (i.e., the user registers the node).
		// This is not implemented yet, as it is no strictly required. The only side-effect
		// is that the client will hammer headscale with requests until it gets a
		// successful RegisterResponse.
		if registerRequest.Followup != "" {
			if _, ok := h.registrationCache.Get(util.NodePublicKeyStripPrefix(registerRequest.NodeKey)); ok {
				log.Debug().
					Caller().
					Str("node", registerRequest.Hostinfo.Hostname).
					Str("machine_key", machineKey.ShortString()).
					Str("node_key", registerRequest.NodeKey.ShortString()).
					Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
					Str("follow_up", registerRequest.Followup).
					Bool("noise", isNoise).
					Msg("Node is waiting for interactive login")

				select {
				case <-req.Context().Done():
					return
				case <-time.After(registrationHoldoff):
					h.handleNewNode(writer, registerRequest, machineKey, isNoise)

					return
				}
			}
		}

		log.Info().
			Caller().
			Str("node", registerRequest.Hostinfo.Hostname).
			Str("machine_key", machineKey.ShortString()).
			Str("node_key", registerRequest.NodeKey.ShortString()).
			Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
			Str("follow_up", registerRequest.Followup).
			Bool("noise", isNoise).
			Msg("New node not yet in the database")

		givenName, err := h.db.GenerateGivenName(
			machineKey.String(),
			registerRequest.Hostinfo.Hostname,
		)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Failed to generate given name for node")

			return
		}

		// The node did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the node and then keep it around until a callback
		// happens
		newNode := types.Node{
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
				Str("node", registerRequest.Hostinfo.Hostname).
				Time("expiry", registerRequest.Expiry).
				Msg("Non-zero expiry time requested")
			newNode.Expiry = &registerRequest.Expiry
		}

		h.registrationCache.Set(
			newNode.NodeKey,
			newNode,
			registerCacheExpiration,
		)

		h.handleNewNode(writer, registerRequest, machineKey, isNoise)

		return
	}

	// The node is already in the DB. This could mean one of the following:
	// - The node is authenticated and ready to /map
	// - We are doing a key refresh
	// - The node is logged out (or expired) and pending to be authorized. TODO(juan): We need to keep alive the connection here
	if node != nil {
		// (juan): For a while we had a bug where we were not storing the MachineKey for the nodes using the TS2021,
		// due to a misunderstanding of the protocol https://github.com/juanfont/headscale/issues/1054
		// So if we have a not valid MachineKey (but we were able to fetch the node with the NodeKeys), we update it.
		var storedMachineKey key.MachinePublic
		err = storedMachineKey.UnmarshalText(
			[]byte(util.MachinePublicKeyEnsurePrefix(node.MachineKey)),
		)
		if err != nil || storedMachineKey.IsZero() {
			if err := h.db.NodeSetMachineKey(node, machineKey); err != nil {
				log.Error().
					Caller().
					Str("func", "RegistrationHandler").
					Str("node", node.Hostname).
					Err(err).
					Msg("Error saving machine key to database")

				return
			}
		}

		// If the NodeKey stored in headscale is the same as the key presented in a registration
		// request, then we have a node that is either:
		// - Trying to log out (sending a expiry in the past)
		// - A valid, registered node, looking for /map
		// - Expired node wanting to reauthenticate
		if node.NodeKey == util.NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(now) {
				h.handleNodeLogOut(writer, *node, machineKey, isNoise)

				return
			}

			// If node is not expired, and it is register, we have a already accepted this node,
			// let it proceed with a valid registration
			if !node.IsExpired() {
				h.handleNodeWithValidRegistration(writer, *node, machineKey, isNoise)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if node.NodeKey == util.NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!node.IsExpired() {
			h.handleNodeKeyRefresh(
				writer,
				registerRequest,
				*node,
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

		// The node has expired or it is logged out
		h.handleNodeExpiredOrLoggedOut(writer, registerRequest, *node, machineKey, isNoise)

		// TODO(juan): RegisterRequest includes an Expiry time, that we could optionally use
		node.Expiry = &time.Time{}

		// If we are here it means the client needs to be reauthorized,
		// we need to make sure the NodeKey matches the one in the request
		// TODO(juan): What happens when using fast user switching between two
		// headscale-managed tailnets?
		node.NodeKey = util.NodePublicKeyStripPrefix(registerRequest.NodeKey)
		h.registrationCache.Set(
			util.NodePublicKeyStripPrefix(registerRequest.NodeKey),
			*node,
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
		Str("node", registerRequest.Hostinfo.Hostname).
		Bool("noise", isNoise).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.db.ValidatePreAuthKey(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("node", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("node", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
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
			Str("node", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		if pak != nil {
			nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()
		} else {
			nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("node", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := util.NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := h.db.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if node != nil {
		log.Trace().
			Caller().
			Bool("noise", isNoise).
			Str("node", node.Hostname).
			Msg("node was already registered before, refreshing with new auth key")

		node.NodeKey = nodeKey
		pakID := uint(pak.ID)
		if pakID != 0 {
			node.AuthKeyID = &pakID
		}

		err := h.db.NodeSetExpiry(node, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("node", node.Hostname).
				Err(err).
				Msg("Failed to refresh node")

			return
		}

		aclTags := pak.Proto().AclTags
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour, although SaaS would reset the tags on auth-key login
			err = h.db.SetTags(node, aclTags)

			if err != nil {
				log.Error().
					Caller().
					Bool("noise", isNoise).
					Str("node", node.Hostname).
					Strs("aclTags", aclTags).
					Err(err).
					Msg("Failed to set tags after refreshing node")

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
				Err(err).
				Msg("Failed to generate given name for node")

			return
		}

		nodeToRegister := types.Node{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			UserID:         pak.User.ID,
			MachineKey:     util.MachinePublicKeyStripPrefix(machineKey),
			RegisterMethod: util.RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			ForcedTags:     pak.Proto().AclTags,
		}

		pakID := uint(pak.ID)
		if pakID != 0 {
			nodeToRegister.AuthKeyID = &pakID
		}
		node, err = h.db.RegisterNode(
			nodeToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Err(err).
				Msg("could not register node")
			nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
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
		nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
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
			Str("node", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")
		nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "error", pak.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	nodeRegistrations.WithLabelValues("new", util.RegisterMethodAuthKey, "success", pak.User.Name).
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
		Str("node", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(node.IPAddresses.StringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewNode exposes for both legacy and Noise the functionality to get a URL
// for authorizing the node. This url is then showed to the user by the local Tailscale client.
func (h *Headscale) handleNewNode(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	// The node registration is new, redirect the client to the registration URL
	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("node", registerRequest.Hostinfo.Hostname).
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
		Str("node", registerRequest.Hostinfo.Hostname).
		Msg("Successfully sent auth url")
}

func (h *Headscale) handleNodeLogOut(
	writer http.ResponseWriter,
	node types.Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("Client requested logout")

	now := time.Now()
	err := h.db.NodeSetExpiry(&node, now)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to expire node")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.NodeKeyExpired = true
	resp.User = *node.User.TailscaleUser()
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

	if node.IsEphemeral() {
		err = h.db.DeleteNode(&node)
		if err != nil {
			log.Error().
				Err(err).
				Str("node", node.Hostname).
				Msg("Cannot delete ephemeral node from the database")
		}

		return
	}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("Successfully logged out")
}

func (h *Headscale) handleNodeWithValidRegistration(
	writer http.ResponseWriter,
	node types.Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	// The node registration is valid, respond with redirect to /map
	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *node.User.TailscaleUser()
	resp.Login = *node.User.TailscaleLogin()

	respBody, err := mapper.MarshalResponse(resp, isNoise, h.privateKey2019, machineKey)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Cannot encode message")
		nodeRegistrations.WithLabelValues("update", "web", "error", node.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	nodeRegistrations.WithLabelValues("update", "web", "success", node.User.Name).
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
		Str("node", node.Hostname).
		Msg("Node successfully authorized")
}

func (h *Headscale) handleNodeKeyRefresh(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	node types.Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")

	err := h.db.NodeSetNodeKey(&node, registerRequest.NodeKey)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to update machine key in the database")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.User = *node.User.TailscaleUser()
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
		Str("node", node.Hostname).
		Msg("Node key successfully refreshed")
}

func (h *Headscale) handleNodeExpiredOrLoggedOut(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	node types.Node,
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
		Str("node", node.Hostname).
		Str("machine_key", machineKey.ShortString()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
		Msg("Node registration has expired or logged out. Sending a auth url to register")

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
		nodeRegistrations.WithLabelValues("reauth", "web", "error", node.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	nodeRegistrations.WithLabelValues("reauth", "web", "success", node.User.Name).
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
		Str("node", node.Hostname).
		Msg("Node logged out. Sent AuthURL for reauthentication")
}
