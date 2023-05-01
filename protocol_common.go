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
	isNoise bool,
) {
	now := time.Now().UTC()
	node, err := h.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the node has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKeyCommon(writer, registerRequest, machineKey, isNoise)

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
			if _, ok := h.registrationCache.Get(NodePublicKeyStripPrefix(registerRequest.NodeKey)); ok {
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
					h.handleNewNodeCommon(writer, registerRequest, machineKey, isNoise)

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

		givenName, err := h.GenerateGivenName(
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

		// The node did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the node and then keep it around until a callback
		// happens
		newNode := Node{
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

		h.handleNewNodeCommon(writer, registerRequest, machineKey, isNoise)

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
			[]byte(MachinePublicKeyEnsurePrefix(node.MachineKey)),
		)
		if err != nil || storedMachineKey.IsZero() {
			node.MachineKey = MachinePublicKeyStripPrefix(machineKey)
			if err := h.db.Save(&node).Error; err != nil {
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
		if node.NodeKey == NodePublicKeyStripPrefix(registerRequest.NodeKey) {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(now) {
				h.handleNodeLogOutCommon(writer, *node, machineKey, isNoise)

				return
			}

			// If node is not expired, and it is register, we have a already accepted this node,
			// let it proceed with a valid registration
			if !node.isExpired() {
				h.handleNodeValidRegistrationCommon(writer, *node, machineKey, isNoise)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if node.NodeKey == NodePublicKeyStripPrefix(registerRequest.OldNodeKey) &&
			!node.isExpired() {
			h.handleNodeRefreshKeyCommon(
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
		h.handleNodeExpiredOrLoggedOutCommon(writer, registerRequest, *node, machineKey, isNoise)

		// TODO(juan): RegisterRequest includes an Expiry time, that we could optionally use
		node.Expiry = &time.Time{}

		// If we are here it means the client needs to be reauthorized,
		// we need to make sure the NodeKey matches the one in the request
		// TODO(juan): What happens when using fast user switching between two
		// headscale-managed tailnets?
		node.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)
		h.registrationCache.Set(
			NodePublicKeyStripPrefix(registerRequest.NodeKey),
			*node,
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
	isNoise bool,
) {
	log.Debug().
		Str("func", "handleAuthKeyCommon").
		Str("node", registerRequest.Hostinfo.Hostname).
		Bool("noise", isNoise).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.checkKeyValidity(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "handleAuthKeyCommon").
			Bool("noise", isNoise).
			Str("node", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		respBody, err := h.marshalResponse(resp, machineKey, isNoise)
		if err != nil {
			log.Error().
				Caller().
				Str("func", "handleAuthKeyCommon").
				Bool("noise", isNoise).
				Str("node", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)
			nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.User.Name).
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
			Str("func", "handleAuthKeyCommon").
			Bool("noise", isNoise).
			Str("node", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		if pak != nil {
			nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()
		} else {
			nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", "unknown").Inc()
		}

		return
	}

	log.Debug().
		Str("func", "handleAuthKeyCommon").
		Bool("noise", isNoise).
		Str("node", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := NodePublicKeyStripPrefix(registerRequest.NodeKey)

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := h.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if node != nil {
		log.Trace().
			Caller().
			Bool("noise", isNoise).
			Str("node", node.Hostname).
			Msg("node was already registered before, refreshing with new auth key")

		node.NodeKey = nodeKey
		node.AuthKeyID = uint(pak.ID)
		err := h.RefreshNode(node, registerRequest.Expiry)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("node", node.Hostname).
				Err(err).
				Msg("Failed to refresh node")

			return
		}

		aclTags := pak.toProto().AclTags
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour, although SaaS would reset the tags on auth-key login
			err = h.SetTags(node, aclTags)

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

		givenName, err := h.GenerateGivenName(MachinePublicKeyStripPrefix(machineKey), registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err)

			return
		}

		nodeToRegister := Node{
			Hostname:       registerRequest.Hostinfo.Hostname,
			GivenName:      givenName,
			UserID:         pak.User.ID,
			MachineKey:     MachinePublicKeyStripPrefix(machineKey),
			RegisterMethod: RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			AuthKeyID:      uint(pak.ID),
			ForcedTags:     pak.toProto().AclTags,
		}

		node, err = h.RegisterNode(
			nodeToRegister,
		)
		if err != nil {
			log.Error().
				Caller().
				Bool("noise", isNoise).
				Err(err).
				Msg("could not register node")
			nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.User.Name).
				Inc()
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	err = h.UsePreAuthKey(pak)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Err(err).
			Msg("Failed to use pre-auth key")
		nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *pak.User.toTailscaleUser()
	// Provide LoginName when registering with pre-auth key
	// Otherwise it will need to exec `tailscale up` twice to fetch the *LoginName*
	resp.Login = *pak.User.toTailscaleLogin()

	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("func", "handleAuthKeyCommon").
			Str("node", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Cannot encode message")
		nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "error", pak.User.Name).
			Inc()
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}
	nodeRegistrations.WithLabelValues("new", RegisterMethodAuthKey, "success", pak.User.Name).
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
		Str("func", "handleAuthKeyCommon").
		Bool("noise", isNoise).
		Str("node", registerRequest.Hostinfo.Hostname).
		Str("ips", strings.Join(node.IPAddresses.ToStringSlice(), ", ")).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewNodeCommon exposes for both legacy and Noise the functionality to get a URL
// for authorizing the node. This url is then showed to the user by the local Tailscale client.
func (h *Headscale) handleNewNodeCommon(
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

	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
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

func (h *Headscale) handleNodeLogOutCommon(
	writer http.ResponseWriter,
	node Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("Client requested logout")

	err := h.ExpireNode(&node)
	if err != nil {
		log.Error().
			Caller().
			Bool("noise", isNoise).
			Str("func", "handleNodeLogOutCommon").
			Err(err).
			Msg("Failed to expire node")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.NodeKeyExpired = true
	resp.User = *node.User.toTailscaleUser()
	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
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

	if node.isEphemeral() {
		err = h.HardDeleteNode(&node)
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

func (h *Headscale) handleNodeValidRegistrationCommon(
	writer http.ResponseWriter,
	node Node,
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
	resp.User = *node.User.toTailscaleUser()
	resp.Login = *node.User.toTailscaleLogin()

	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
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

func (h *Headscale) handleNodeRefreshKeyCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	node Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Caller().
		Bool("noise", isNoise).
		Str("node", node.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")
	node.NodeKey = NodePublicKeyStripPrefix(registerRequest.NodeKey)

	if err := h.db.Save(&node).Error; err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to update node key in the database")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.AuthURL = ""
	resp.User = *node.User.toTailscaleUser()
	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
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

func (h *Headscale) handleNodeExpiredOrLoggedOutCommon(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	node Node,
	machineKey key.MachinePublic,
	isNoise bool,
) {
	resp := tailcfg.RegisterResponse{}

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKeyCommon(writer, registerRequest, machineKey, isNoise)

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

	respBody, err := h.marshalResponse(resp, machineKey, isNoise)
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
