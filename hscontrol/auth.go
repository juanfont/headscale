package hscontrol

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func logAuthFunc(
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (func(string), func(string), func(error, string)) {
	return func(msg string) {
			log.Info().
				Caller().
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Msg(msg)
		},
		func(msg string) {
			log.Trace().
				Caller().
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Msg(msg)
		},
		func(err error, msg string) {
			log.Error().
				Caller().
				Str("machine_key", machineKey.ShortString()).
				Str("node_key", registerRequest.NodeKey.ShortString()).
				Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
				Str("node", registerRequest.Hostinfo.Hostname).
				Str("followup", registerRequest.Followup).
				Time("expiry", registerRequest.Expiry).
				Err(err).
				Msg(msg)
		}
}

// handleRegister is the logic for registering a client.
func (h *Headscale) handleRegister(
	writer http.ResponseWriter,
	req *http.Request,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	logInfo, logTrace, logErr := logAuthFunc(registerRequest, machineKey)
	now := time.Now().UTC()
	logTrace("handleRegister called, looking up machine in DB")
	node, err := h.db.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	logTrace("handleRegister database lookup has returned")
	if errors.Is(err, gorm.ErrRecordNotFound) {
		// If the node has AuthKey set, handle registration via PreAuthKeys
		if registerRequest.Auth.AuthKey != "" {
			h.handleAuthKey(writer, registerRequest, machineKey)

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
			logTrace("register request is a followup")
			if _, ok := h.registrationCache.Get(machineKey.String()); ok {
				logTrace("Node is waiting for interactive login")

				select {
				case <-req.Context().Done():
					return
				case <-time.After(registrationHoldoff):
					h.handleNewNode(writer, registerRequest, machineKey)

					return
				}
			}
		}

		logInfo("Node not found in database, creating new")

		givenName, err := h.db.GenerateGivenName(
			machineKey,
			registerRequest.Hostinfo.Hostname,
		)
		if err != nil {
			logErr(err, "Failed to generate given name for node")

			return
		}

		// The node did not have a key to authenticate, which means
		// that we rely on a method that calls back some how (OpenID or CLI)
		// We create the node and then keep it around until a callback
		// happens
		newNode := types.Node{
			MachineKey: machineKey,
			Hostname:   registerRequest.Hostinfo.Hostname,
			GivenName:  givenName,
			NodeKey:    registerRequest.NodeKey,
			LastSeen:   &now,
			Expiry:     &time.Time{},
		}

		if !registerRequest.Expiry.IsZero() {
			logTrace("Non-zero expiry time requested")
			newNode.Expiry = &registerRequest.Expiry
		}

		h.registrationCache.Set(
			machineKey.String(),
			newNode,
			registerCacheExpiration,
		)

		h.handleNewNode(writer, registerRequest, machineKey)

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
		if err != nil || node.MachineKey.IsZero() {
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
		if node.NodeKey.String() == registerRequest.NodeKey.String() {
			// The client sends an Expiry in the past if the client is requesting to expire the key (aka logout)
			//   https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L648
			if !registerRequest.Expiry.IsZero() &&
				registerRequest.Expiry.UTC().Before(now) {
				h.handleNodeLogOut(writer, *node, machineKey)

				return
			}

			// If node is not expired, and it is register, we have a already accepted this node,
			// let it proceed with a valid registration
			if !node.IsExpired() {
				h.handleNodeWithValidRegistration(writer, *node, machineKey)

				return
			}
		}

		// The NodeKey we have matches OldNodeKey, which means this is a refresh after a key expiration
		if node.NodeKey.String() == registerRequest.OldNodeKey.String() &&
			!node.IsExpired() {
			h.handleNodeKeyRefresh(
				writer,
				registerRequest,
				*node,
				machineKey,
			)

			return
		}

		// When logged out and reauthenticating with OIDC, the OldNodeKey is not passed, but the NodeKey has changed
		if node.NodeKey.String() != registerRequest.NodeKey.String() &&
			registerRequest.OldNodeKey.IsZero() && !node.IsExpired() {
			h.handleNodeKeyRefresh(
				writer,
				registerRequest,
				*node,
				machineKey,
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
		h.handleNodeExpiredOrLoggedOut(writer, registerRequest, *node, machineKey)

		// TODO(juan): RegisterRequest includes an Expiry time, that we could optionally use
		node.Expiry = &time.Time{}

		// If we are here it means the client needs to be reauthorized,
		// we need to make sure the NodeKey matches the one in the request
		// TODO(juan): What happens when using fast user switching between two
		// headscale-managed tailnets?
		node.NodeKey = registerRequest.NodeKey
		h.registrationCache.Set(
			machineKey.String(),
			*node,
			registerCacheExpiration,
		)

		return
	}
}

// handleAuthKey contains the logic to manage auth key client registration
// When using Noise, the machineKey is Zero.
func (h *Headscale) handleAuthKey(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	log.Debug().
		Caller().
		Str("node", registerRequest.Hostinfo.Hostname).
		Msgf("Processing auth key for %s", registerRequest.Hostinfo.Hostname)
	resp := tailcfg.RegisterResponse{}

	pak, err := h.db.ValidatePreAuthKey(registerRequest.Auth.AuthKey)
	if err != nil {
		log.Error().
			Caller().
			Str("node", registerRequest.Hostinfo.Hostname).
			Err(err).
			Msg("Failed authentication via AuthKey")
		resp.MachineAuthorized = false

		respBody, err := json.Marshal(resp)
		if err != nil {
			log.Error().
				Caller().
				Str("node", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("Cannot encode message")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}

		writer.Header().Set("Content-Type", "application/json; charset=utf-8")
		writer.WriteHeader(http.StatusUnauthorized)
		_, err = writer.Write(respBody)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Failed to write response")
		}

		log.Error().
			Caller().
			Str("node", registerRequest.Hostinfo.Hostname).
			Msg("Failed authentication via AuthKey")

		return
	}

	log.Debug().
		Caller().
		Str("node", registerRequest.Hostinfo.Hostname).
		Msg("Authentication key was valid, proceeding to acquire IP addresses")

	nodeKey := registerRequest.NodeKey

	// retrieve node information if it exist
	// The error is not important, because if it does not
	// exist, then this is a new node and we will move
	// on to registration.
	node, _ := h.db.GetNodeByAnyKey(machineKey, registerRequest.NodeKey, registerRequest.OldNodeKey)
	if node != nil {
		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Msg("node was already registered before, refreshing with new auth key")

		node.NodeKey = nodeKey
		pakID := uint(pak.ID)
		if pakID != 0 {
			node.AuthKeyID = &pakID
		}

		node.Expiry = &registerRequest.Expiry
		node.User = pak.User
		node.UserID = pak.UserID
		err := h.db.DB.Save(node).Error
		if err != nil {
			log.Error().
				Caller().
				Str("node", node.Hostname).
				Err(err).
				Msg("failed to save node after logging in with auth key")

			return
		}

		aclTags := pak.Proto().GetAclTags()
		if len(aclTags) > 0 {
			// This conditional preserves the existing behaviour, although SaaS would reset the tags on auth-key login
			err = h.db.SetTags(node.ID, aclTags)

			if err != nil {
				log.Error().
					Caller().
					Str("node", node.Hostname).
					Strs("aclTags", aclTags).
					Err(err).
					Msg("Failed to set tags after refreshing node")

				return
			}
		}

		ctx := types.NotifyCtx(context.Background(), "handle-authkey", "na")
		h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{Type: types.StatePeerChanged, ChangeNodes: []types.NodeID{node.ID}})
	} else {
		now := time.Now().UTC()

		givenName, err := h.db.GenerateGivenName(machineKey, registerRequest.Hostinfo.Hostname)
		if err != nil {
			log.Error().
				Caller().
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
			User:           pak.User,
			MachineKey:     machineKey,
			RegisterMethod: util.RegisterMethodAuthKey,
			Expiry:         &registerRequest.Expiry,
			NodeKey:        nodeKey,
			LastSeen:       &now,
			ForcedTags:     pak.Proto().GetAclTags(),
		}

		ipv4, ipv6, err := h.ipAlloc.Next()
		if err != nil {
			log.Error().
				Caller().
				Str("func", "RegistrationHandler").
				Str("hostinfo.name", registerRequest.Hostinfo.Hostname).
				Err(err).
				Msg("failed to allocate IP	")

			return
		}

		pakID := uint(pak.ID)
		if pakID != 0 {
			nodeToRegister.AuthKeyID = &pakID
		}
		node, err = h.db.RegisterNode(
			nodeToRegister,
			ipv4, ipv6,
		)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("could not register node")
			http.Error(writer, "Internal server error", http.StatusInternalServerError)

			return
		}
	}

	h.db.Write(func(tx *gorm.DB) error {
		return db.UsePreAuthKey(tx, pak)
	})
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to use pre-auth key")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	resp.MachineAuthorized = true
	resp.User = *pak.User.TailscaleUser()
	// Provide LoginName when registering with pre-auth key
	// Otherwise it will need to exec `tailscale up` twice to fetch the *LoginName*
	resp.Login = *pak.User.TailscaleLogin()

	respBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Str("node", registerRequest.Hostinfo.Hostname).
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
			Err(err).
			Msg("Failed to write response")
		return
	}

	log.Info().
		Str("node", registerRequest.Hostinfo.Hostname).
		Msg("Successfully authenticated via AuthKey")
}

// handleNewNode returns the authorisation URL to the client based on what type
// of registration headscale is configured with.
// This url is then showed to the user by the local Tailscale client.
func (h *Headscale) handleNewNode(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) {
	logInfo, logTrace, logErr := logAuthFunc(registerRequest, machineKey)

	resp := tailcfg.RegisterResponse{}

	// The node registration is new, redirect the client to the registration URL
	logTrace("The node seems to be new, sending auth url")

	if h.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf(
			"%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String(),
		)
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String())
	}

	respBody, err := json.Marshal(resp)
	if err != nil {
		logErr(err, "Cannot encode message")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	writer.Header().Set("Content-Type", "application/json; charset=utf-8")
	writer.WriteHeader(http.StatusOK)
	_, err = writer.Write(respBody)
	if err != nil {
		logErr(err, "Failed to write response")
	}

	logInfo(fmt.Sprintf("Successfully sent auth url: %s", resp.AuthURL))
}

func (h *Headscale) handleNodeLogOut(
	writer http.ResponseWriter,
	node types.Node,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Str("node", node.Hostname).
		Msg("Client requested logout")

	now := time.Now()
	err := h.db.NodeSetExpiry(node.ID, now)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Failed to expire node")
		http.Error(writer, "Internal server error", http.StatusInternalServerError)

		return
	}

	ctx := types.NotifyCtx(context.Background(), "logout-expiry", "na")
	h.nodeNotifier.NotifyWithIgnore(ctx, types.StateUpdateExpire(node.ID, now), node.ID)

	resp.AuthURL = ""
	resp.MachineAuthorized = false
	resp.NodeKeyExpired = true
	resp.User = *node.User.TailscaleUser()
	respBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
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
			Err(err).
			Msg("Failed to write response")

		return
	}

	if node.IsEphemeral() {
		changedNodes, err := h.db.DeleteNode(&node, h.nodeNotifier.LikelyConnectedMap())
		if err != nil {
			log.Error().
				Err(err).
				Str("node", node.Hostname).
				Msg("Cannot delete ephemeral node from the database")
		}

		ctx := types.NotifyCtx(context.Background(), "logout-ephemeral", "na")
		h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
			Type:    types.StatePeerRemoved,
			Removed: []types.NodeID{node.ID},
		})
		if changedNodes != nil {
			h.nodeNotifier.NotifyAll(ctx, types.StateUpdate{
				Type:        types.StatePeerChanged,
				ChangeNodes: changedNodes,
			})
		}

		return
	}

	log.Info().
		Caller().
		Str("node", node.Hostname).
		Msg("Successfully logged out")
}

func (h *Headscale) handleNodeWithValidRegistration(
	writer http.ResponseWriter,
	node types.Node,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	// The node registration is valid, respond with redirect to /map
	log.Debug().
		Caller().
		Str("node", node.Hostname).
		Msg("Client is registered and we have the current NodeKey. All clear to /map")

	resp.AuthURL = ""
	resp.MachineAuthorized = true
	resp.User = *node.User.TailscaleUser()
	resp.Login = *node.User.TailscaleLogin()

	respBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
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
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
		Str("node", node.Hostname).
		Msg("Node successfully authorized")
}

func (h *Headscale) handleNodeKeyRefresh(
	writer http.ResponseWriter,
	registerRequest tailcfg.RegisterRequest,
	node types.Node,
	machineKey key.MachinePublic,
) {
	resp := tailcfg.RegisterResponse{}

	log.Info().
		Caller().
		Str("node", node.Hostname).
		Msg("We have the OldNodeKey in the database. This is a key refresh")

	err := h.db.Write(func(tx *gorm.DB) error {
		return db.NodeSetNodeKey(tx, &node, registerRequest.NodeKey)
	})
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
	respBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
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
			Err(err).
			Msg("Failed to write response")
	}

	log.Info().
		Caller().
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
) {
	resp := tailcfg.RegisterResponse{}

	if registerRequest.Auth.AuthKey != "" {
		h.handleAuthKey(writer, registerRequest, machineKey)

		return
	}

	// The client has registered before, but has expired or logged out
	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Str("machine_key", machineKey.ShortString()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
		Msg("Node registration has expired or logged out. Sending a auth url to register")

	if h.oauth2Config != nil {
		resp.AuthURL = fmt.Sprintf("%s/oidc/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String())
	} else {
		resp.AuthURL = fmt.Sprintf("%s/register/%s",
			strings.TrimSuffix(h.cfg.ServerURL, "/"),
			machineKey.String())
	}

	respBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
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
			Err(err).
			Msg("Failed to write response")
	}

	log.Trace().
		Caller().
		Str("machine_key", machineKey.ShortString()).
		Str("node_key", registerRequest.NodeKey.ShortString()).
		Str("node_key_old", registerRequest.OldNodeKey.ShortString()).
		Str("node", node.Hostname).
		Msg("Node logged out. Sent AuthURL for reauthentication")
}
