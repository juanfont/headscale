package hscontrol

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

type AuthProvider interface {
	RegisterHandler(http.ResponseWriter, *http.Request)
	AuthURL(types.RegistrationID) string
}

func (h *Headscale) handleRegister(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Check for logout/expiry FIRST, before checking auth key.
	// Tailscale clients may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry takes precedence - it's a logout regardless of other fields.
	if !req.Expiry.IsZero() && req.Expiry.Before(time.Now()) {
		log.Debug().
			Str("node.key", req.NodeKey.ShortString()).
			Time("expiry", req.Expiry).
			Bool("has_auth", req.Auth != nil).
			Msg("Detected logout attempt with past expiry")

		// This is a logout attempt (expiry in the past)
		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			log.Debug().
				Uint64("node.id", node.ID().Uint64()).
				Str("node.name", node.Hostname()).
				Bool("is_ephemeral", node.IsEphemeral()).
				Bool("has_authkey", node.AuthKey().Valid()).
				Msg("Found existing node for logout, calling handleLogout")

			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling logout: %w", err)
			}
			if resp != nil {
				return resp, nil
			}
		} else {
			log.Warn().
				Str("node.key", req.NodeKey.ShortString()).
				Msg("Logout attempt but node not found in NodeStore")
		}
	}

	// If the register request does not contain a Auth struct, it means we are logging
	// out an existing node (legacy logout path for clients that send Auth=nil).
	if req.Auth == nil {
		// If the register request present a NodeKey that is currently in use, we will
		// check if the node needs to be sent to re-auth, or if the node is logging out.
		// We do not look up nodes by [key.MachinePublic] as it might belong to multiple
		// nodes, separated by users and this path is handling expiring/logout paths.
		if node, ok := h.state.GetNodeByNodeKey(req.NodeKey); ok {
			resp, err := h.handleLogout(node, req, machineKey)
			if err != nil {
				return nil, fmt.Errorf("handling existing node: %w", err)
			}

			// If resp is not nil, we have a response to return to the node.
			// If resp is nil, we should proceed and see if the node is trying to re-auth.
			if resp != nil {
				return resp, nil
			}
		} else {
			// If the register request is not attempting to register a node, and
			// we cannot match it with an existing node, we consider that unexpected
			// as only register nodes should attempt to log out.
			log.Debug().
				Str("node.key", req.NodeKey.ShortString()).
				Str("machine.key", machineKey.ShortString()).
				Bool("unexpected", true).
				Msg("received register request with no auth, and no existing node")
		}
	}

	// If the [tailcfg.RegisterRequest] has a Followup URL, it means that the
	// node has already started the registration process and we should wait for
	// it to finish the original registration.
	if req.Followup != "" {
		return h.waitForFollowup(ctx, req, machineKey)
	}

	// Pre authenticated keys are handled slightly different than interactive
	// logins as they can be done fully sync and we can respond to the node with
	// the result as it is waiting.
	if isAuthKey(req) {
		resp, err := h.handleRegisterWithAuthKey(req, machineKey)
		if err != nil {
			// Preserve HTTPError types so they can be handled properly by the HTTP layer
			var httpErr HTTPError
			if errors.As(err, &httpErr) {
				return nil, httpErr
			}

			return nil, fmt.Errorf("handling register with auth key: %w", err)
		}

		return resp, nil
	}

	resp, err := h.handleRegisterInteractive(req, machineKey)
	if err != nil {
		return nil, fmt.Errorf("handling register interactive: %w", err)
	}

	return resp, nil
}

// handleLogout checks if the [tailcfg.RegisterRequest] is a
// logout attempt from a node. If the node is not attempting to
func (h *Headscale) handleLogout(
	node types.NodeView,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Fail closed if it looks like this is an attempt to modify a node where
	// the node key and the machine key the noise session was started with does
	// not align.
	if node.MachineKey() != machineKey {
		return nil, NewHTTPError(http.StatusUnauthorized, "node exist with different machine key", nil)
	}

	// Note: We do NOT return early if req.Auth is set, because Tailscale clients
	// may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry indicates logout, regardless of whether Auth is present.
	// The expiry check below will handle the logout logic.

	// If the node is expired and this is not a re-authentication attempt,
	// force the client to re-authenticate.
	// TODO(kradalby): I wonder if this is a path we ever hit?
	if node.IsExpired() {
		log.Trace().Str("node.name", node.Hostname()).
			Uint64("node.id", node.ID().Uint64()).
			Interface("reg.req", req).
			Bool("unexpected", true).
			Msg("Node key expired, forcing re-authentication")
		return &tailcfg.RegisterResponse{
			NodeKeyExpired:    true,
			MachineAuthorized: false,
			AuthURL:           "", // Client will need to re-authenticate
		}, nil
	}

	// If we get here, the node is not currently expired, and not trying to
	// do an auth.
	// The node is likely logging out, but before we run that logic, we will validate
	// that the node is not attempting to tamper/extend their expiry.
	// If it is not, we will expire the node or in the case of an ephemeral node, delete it.

	// The client is trying to extend their key, this is not allowed.
	if req.Expiry.After(time.Now()) {
		return nil, NewHTTPError(http.StatusBadRequest, "extending key is not allowed", nil)
	}

	// If the request expiry is in the past, we consider it a logout.
	if req.Expiry.Before(time.Now()) {
		log.Debug().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Bool("is_ephemeral", node.IsEphemeral()).
			Bool("has_authkey", node.AuthKey().Valid()).
			Time("req.expiry", req.Expiry).
			Msg("Processing logout request with past expiry")

		if node.IsEphemeral() {
			log.Info().
				Uint64("node.id", node.ID().Uint64()).
				Str("node.name", node.Hostname()).
				Msg("Deleting ephemeral node during logout")

			c, err := h.state.DeleteNode(node)
			if err != nil {
				return nil, fmt.Errorf("deleting ephemeral node: %w", err)
			}

			h.Change(c)

			return &tailcfg.RegisterResponse{
				NodeKeyExpired:    true,
				MachineAuthorized: false,
			}, nil
		}

		log.Debug().
			Uint64("node.id", node.ID().Uint64()).
			Str("node.name", node.Hostname()).
			Msg("Node is not ephemeral, setting expiry instead of deleting")
	}

	// Update the internal state with the nodes new expiry, meaning it is
	// logged out.
	updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), req.Expiry)
	if err != nil {
		return nil, fmt.Errorf("setting node expiry: %w", err)
	}

	h.Change(c)

	return nodeToRegisterResponse(updatedNode), nil
}

// isAuthKey reports if the register request is a registration request
// using an pre auth key.
func isAuthKey(req tailcfg.RegisterRequest) bool {
	return req.Auth != nil && req.Auth.AuthKey != ""
}

func nodeToRegisterResponse(node types.NodeView) *tailcfg.RegisterResponse {
	return &tailcfg.RegisterResponse{
		// TODO(kradalby): Only send for user-owned nodes
		// and not tagged nodes when tags is working.
		User:           node.UserView().TailscaleUser(),
		Login:          node.UserView().TailscaleLogin(),
		NodeKeyExpired: node.IsExpired(),

		// Headscale does not implement the concept of machine authorization
		// so we always return true here.
		// Revisit this if #2176 gets implemented.
		MachineAuthorized: true,
	}
}

func (h *Headscale) waitForFollowup(
	ctx context.Context,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	fu, err := url.Parse(req.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid followup URL", err)
	}

	followupReg, err := types.RegistrationIDFromString(strings.ReplaceAll(fu.Path, "/register/", ""))
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid registration ID", err)
	}

	if reg, ok := h.state.GetRegistrationCacheEntry(followupReg); ok {
		select {
		case <-ctx.Done():
			return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", err)
		case node := <-reg.Registered:
			if node == nil {
				// registration is expired in the cache, instruct the client to try a new registration
				return h.reqToNewRegisterResponse(req, machineKey)
			}
			return nodeToRegisterResponse(node.View()), nil
		}
	}

	// if the follow-up registration isn't found anymore, instruct the client to try a new registration
	return h.reqToNewRegisterResponse(req, machineKey)
}

// reqToNewRegisterResponse refreshes the registration flow by creating a new
// registration ID and returning the corresponding AuthURL so the client can
// restart the authentication process.
func (h *Headscale) reqToNewRegisterResponse(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	newRegID, err := types.NewRegistrationID()
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate registration ID", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo,
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	hostinfo.Hostname = hostname

	nodeToRegister := types.NewRegisterNode(
		types.Node{
			Hostname:   hostname,
			MachineKey: machineKey,
			NodeKey:    req.NodeKey,
			Hostinfo:   hostinfo,
			LastSeen:   ptr.To(time.Now()),
		},
	)

	if !req.Expiry.IsZero() {
		nodeToRegister.Node.Expiry = &req.Expiry
	}

	log.Info().Msgf("New followup node registration using key: %s", newRegID)
	h.state.SetRegistrationCacheEntry(newRegID, nodeToRegister)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.AuthURL(newRegID),
	}, nil
}

func (h *Headscale) handleRegisterWithAuthKey(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	node, changed, err := h.state.HandleNodeFromPreAuthKey(
		req,
		machineKey,
	)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre auth key", nil)
		}
		var perr types.PAKError
		if errors.As(err, &perr) {
			return nil, NewHTTPError(http.StatusUnauthorized, perr.Error(), nil)
		}

		return nil, err
	}

	// If node is not valid, it means an ephemeral node was deleted during logout
	if !node.Valid() {
		h.Change(changed)
		return nil, nil
	}

	// This is a bit of a back and forth, but we have a bit of a chicken and egg
	// dependency here.
	// Because the way the policy manager works, we need to have the node
	// in the database, then add it to the policy manager and then we can
	// approve the route. This means we get this dance where the node is
	// first added to the database, then we add it to the policy manager via
	// nodesChangedHook and then we can auto approve the routes.
	// As that only approves the struct object, we need to save it again and
	// ensure we send an update.
	// This works, but might be another good candidate for doing some sort of
	// eventbus.
	// TODO(kradalby): This needs to be ran as part of the batcher maybe?
	// now since we dont update the node/pol here anymore
	routeChange := h.state.AutoApproveRoutes(node)

	if _, _, err := h.state.SaveNode(node); err != nil {
		return nil, fmt.Errorf("saving auto approved routes to node: %w", err)
	}

	if routeChange && changed.Empty() {
		changed = change.NodeAdded(node.ID())
	}
	h.Change(changed)

	// TODO(kradalby): I think this is covered above, but we need to validate that.
	// // If policy changed due to node registration, send a separate policy change
	// if policyChanged {
	// 	policyChange := change.PolicyChange()
	// 	h.Change(policyChange)
	// }

	resp := &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		NodeKeyExpired:    node.IsExpired(),
		User:              node.UserView().TailscaleUser(),
		Login:             node.UserView().TailscaleLogin(),
	}

	log.Trace().
		Caller().
		Interface("reg.resp", resp).
		Interface("reg.req", req).
		Str("node.name", node.Hostname()).
		Uint64("node.id", node.ID().Uint64()).
		Msg("RegisterResponse")

	return resp, nil
}

func (h *Headscale) handleRegisterInteractive(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	registrationId, err := types.NewRegistrationID()
	if err != nil {
		return nil, fmt.Errorf("generating registration ID: %w", err)
	}

	// Ensure we have a valid hostname
	hostname := util.EnsureHostname(
		req.Hostinfo,
		machineKey.String(),
		req.NodeKey.String(),
	)

	// Ensure we have valid hostinfo
	hostinfo := cmp.Or(req.Hostinfo, &tailcfg.Hostinfo{})
	if req.Hostinfo == nil {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with nil hostinfo, generated default hostname")
	} else if req.Hostinfo.Hostname == "" {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Str("generated.hostname", hostname).
			Msg("Received registration request with empty hostname, generated default")
	}
	hostinfo.Hostname = hostname

	nodeToRegister := types.NewRegisterNode(
		types.Node{
			Hostname:   hostname,
			MachineKey: machineKey,
			NodeKey:    req.NodeKey,
			Hostinfo:   hostinfo,
			LastSeen:   ptr.To(time.Now()),
		},
	)

	if !req.Expiry.IsZero() {
		nodeToRegister.Node.Expiry = &req.Expiry
	}

	h.state.SetRegistrationCacheEntry(
		registrationId,
		nodeToRegister,
	)

	log.Info().Msgf("Starting node registration using key: %s", registrationId)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.AuthURL(registrationId),
	}, nil
}
