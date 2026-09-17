package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

type AuthProvider interface {
	RegisterHandler(w http.ResponseWriter, r *http.Request)
	AuthHandler(w http.ResponseWriter, r *http.Request)
	RegisterURL(authID types.AuthID) string
	AuthURL(authID types.AuthID) string
}

// machineKeyMismatch fails closed when a node looked up by NodeKey was started
// in a Noise session with a different machine key. Without this anyone holding a
// target's NodeKey could open a session with a throwaway machine key and act on
// the owner's node. Returns a 401 [HTTPError] on mismatch, nil otherwise.
func machineKeyMismatch(node types.NodeView, machineKey key.MachinePublic) error {
	if node.MachineKey() != machineKey {
		return NewHTTPError(http.StatusUnauthorized, "node exists with a different machine key", nil)
	}

	return nil
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
				EmbedObject(node).
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
			// Refuse to act on a node looked up purely by NodeKey unless
			// the Noise session's machine key matches the cached node.
			// Without this check anyone holding a target's NodeKey could
			// open a Noise session with a throwaway machine key and read
			// the owner's User/Login back through [nodeToRegisterResponse].
			// [Headscale.handleLogout] enforces the same check on its own path.
			err := machineKeyMismatch(node, machineKey)
			if err != nil {
				return nil, err
			}

			// When tailscaled restarts, it sends [tailcfg.RegisterRequest] with Auth=nil and Expiry=zero.
			// Return the current node state without modification.
			if req.Expiry.IsZero() && !node.IsExpired() {
				return nodeToRegisterResponse(node), nil
			}

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
			if httpErr, ok := errors.AsType[HTTPError](err); ok {
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
// logout attempt from a node. If the node is not attempting to.
func (h *Headscale) handleLogout(
	node types.NodeView,
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	// Fail closed if it looks like this is an attempt to modify a node where
	// the node key and the machine key the noise session was started with does
	// not align.
	err := machineKeyMismatch(node, machineKey)
	if err != nil {
		return nil, err
	}

	// Note: We do NOT return early if req.Auth is set, because Tailscale clients
	// may send logout requests with BOTH a past expiry AND an auth key.
	// A past expiry indicates logout, regardless of whether Auth is present.
	// The expiry check below will handle the logout logic.

	// If the node is expired and this is not a re-authentication attempt,
	// force the client to re-authenticate.
	// TODO(kradalby): I wonder if this is a path we ever hit?
	if node.IsExpired() {
		log.Trace().
			EmbedObject(node).
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
	// Zero expiry is handled in [Headscale.handleRegister] before calling this function.
	if req.Expiry.Before(time.Now()) {
		log.Debug().
			EmbedObject(node).
			Bool("is_ephemeral", node.IsEphemeral()).
			Bool("has_authkey", node.AuthKey().Valid()).
			Time("req.expiry", req.Expiry).
			Msg("Processing logout request with past expiry")

		if node.IsEphemeral() {
			log.Info().
				EmbedObject(node).
				Msg("Deleting ephemeral node during logout")

			c, err := h.state.DeleteNode(node)
			if !c.IsEmpty() {
				h.Change(c)
			}

			if err != nil {
				return nil, fmt.Errorf("deleting ephemeral node: %w", err)
			}

			return &tailcfg.RegisterResponse{
				NodeKeyExpired:    true,
				MachineAuthorized: false,
			}, nil
		}

		log.Debug().
			EmbedObject(node).
			Msg("Node is not ephemeral, setting expiry instead of deleting")
	}

	// Tagged nodes have key expiry permanently disabled (they are owned by
	// their tags, not a user, and never expire - KB 1068). Logging one out has
	// no expiry semantics, so do not stamp an expiry on it: doing so leaves the
	// node IsExpired() forever and it can never re-authenticate (#3371). The
	// admin path `headscale nodes expire` remains free to set a deliberate
	// expiry via SetNodeExpiry; only the logout path is guarded here.
	if node.IsTagged() {
		log.Debug().
			EmbedObject(node).
			Msg("Tagged node logout: not stamping expiry (tagged nodes never expire)")

		return nodeToRegisterResponse(node), nil
	}

	// Update the internal state with the nodes new expiry, meaning it is
	// logged out.
	//
	// Clamp the client-supplied value to now: Tailscale sends the
	// sentinel time.Unix(123, 0) on logout (controlclient/direct.go),
	// and storing it verbatim propagates a 1970 KeyExpiry to every
	// peer's netmap. Semantically identical (expired as of now), but
	// sane in logs, debug dumps, and peer netmaps.
	expiry := req.Expiry
	if now := time.Now(); expiry.Before(now) {
		expiry = now
	}

	updatedNode, c, err := h.state.SetNodeExpiry(node.ID(), &expiry)
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
	resp := &tailcfg.RegisterResponse{
		NodeKeyExpired: node.IsExpired(),

		// Headscale does not implement the concept of machine authorization
		// so we always return true here.
		// Revisit this if #2176 gets implemented.
		MachineAuthorized: true,
	}

	// For tagged nodes, use the [types.TaggedDevices] special user
	// For user-owned nodes, include User and Login information from the actual user
	if node.IsTagged() {
		resp.User = types.TaggedDevices.View().TailscaleUser()
		resp.Login = types.TaggedDevices.View().TailscaleLogin()
	} else if node.Owner().Valid() {
		resp.User = node.Owner().TailscaleUser()
		resp.Login = node.Owner().TailscaleLogin()
	}

	return resp
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

	followupReg, err := types.AuthIDFromString(strings.ReplaceAll(fu.Path, "/register/", ""))
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid registration ID", err)
	}

	if reg, ok := h.state.GetAuthCacheEntry(followupReg); ok {
		if !reg.IsRegistration() {
			return nil, NewHTTPError(
				http.StatusUnauthorized,
				"auth session is not for registration",
				nil,
			)
		}

		if reg.RegistrationData().MachineKey != machineKey {
			return nil, NewHTTPError(
				http.StatusUnauthorized,
				"registration belongs to a different machine key",
				nil,
			)
		}

		select {
		// Prefer a completed registration even if the context has also
		// expired. When both are ready, a plain select picks at random and
		// would discard a successful registration as a spurious timeout
		// (issue #3385).
		case <-reg.WaitForAuth():
		default:
			select {
			case <-ctx.Done():
				return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", ctx.Err())
			case <-reg.WaitForAuth():
			}
		}

		verdict, ok := reg.AuthResult()
		if !ok {
			return nil, NewHTTPError(
				http.StatusUnauthorized,
				"registration completed without a verdict",
				nil,
			)
		}

		if verdict.Accept() {
			if !verdict.Node.Valid() {
				// registration is expired in the cache, instruct the client to try a new registration
				return h.reqToNewRegisterResponse(req, machineKey)
			}

			// The followup poll is only authenticated by the auth ID in the
			// URL, so fail closed unless the Noise session asking for the
			// result was started with the same machine key that opened the
			// registration. [State.HandleNodeFromAuthPath] resolves the node
			// from the cached [types.RegistrationData.MachineKey], so the two
			// match on the normal path. [Headscale.handleRegister] and
			// [Headscale.handleLogout] apply the same check.
			err := machineKeyMismatch(verdict.Node, machineKey)
			if err != nil {
				return nil, err
			}

			return nodeToRegisterResponse(verdict.Node), nil
		}
	}

	// if the follow-up registration isn't found anymore, instruct the client to try a new registration
	return h.reqToNewRegisterResponse(req, machineKey)
}

// reqToNewRegisterResponse refreshes the registration flow by creating a new
// registration ID and returning the corresponding [tailcfg.RegisterResponse.AuthURL]
// so the client can restart the authentication process.
func (h *Headscale) reqToNewRegisterResponse(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	newAuthID, err := types.NewAuthID()
	if err != nil {
		return nil, NewHTTPError(http.StatusInternalServerError, "failed to generate registration ID", err)
	}

	regData, err := registrationDataFromRequest(req, machineKey)
	if err != nil {
		return nil, NewHTTPError(http.StatusBadRequest, "registration metadata exceeds limits", err)
	}

	authRegReq := types.NewRegisterAuthRequest(regData)

	err = h.state.SetAuthCacheEntry(newAuthID, authRegReq)
	if err != nil {
		return nil, NewHTTPError(
			http.StatusServiceUnavailable,
			"too many pending registrations; try again later",
			err,
		)
	}

	log.Info().Msgf("new followup node registration using auth id: %s", newAuthID)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.RegisterURL(newAuthID),
	}, nil
}

const (
	registrationHostnameMaxBytes  = 255
	registrationOSMaxBytes        = 32
	registrationVersionMaxBytes   = 256
	registrationDeviceMaxBytes    = 256
	registrationTagMaxCount       = 32
	registrationTagMaxBytes       = 256
	registrationTagsTotalMaxBytes = 4 << 10
)

var errRegistrationMetadataTooLarge = errors.New("registration metadata too large")

// registrationDataFromRequest builds the bounded payload stored in the auth
// cache for a pending registration. Network state is restored by the first
// MapRequest, so only fields needed by authentication and its confirmation UI
// are retained here.
func registrationDataFromRequest(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*types.RegistrationData, error) {
	var (
		hostname string
		hostinfo *tailcfg.Hostinfo
	)

	if req.Hostinfo != nil {
		err := validateRegistrationHostinfo(req.Hostinfo)
		if err != nil {
			return nil, err
		}

		hostname = strings.Clone(req.Hostinfo.Hostname)

		hostinfo = &tailcfg.Hostinfo{
			Hostname:    hostname,
			OS:          strings.Clone(req.Hostinfo.OS),
			IPNVersion:  strings.Clone(req.Hostinfo.IPNVersion),
			OSVersion:   strings.Clone(req.Hostinfo.OSVersion),
			DeviceModel: strings.Clone(req.Hostinfo.DeviceModel),
			RequestTags: make([]string, len(req.Hostinfo.RequestTags)),
		}
		for idx, tag := range req.Hostinfo.RequestTags {
			hostinfo.RequestTags[idx] = strings.Clone(tag)
		}
	}

	regData := &types.RegistrationData{
		MachineKey: machineKey,
		NodeKey:    req.NodeKey,
		Hostname:   hostname,
		Hostinfo:   hostinfo,
	}

	if !req.Expiry.IsZero() {
		expiry := req.Expiry
		regData.Expiry = &expiry
	}

	return regData, nil
}

func validateRegistrationHostinfo(hostinfo *tailcfg.Hostinfo) error {
	fields := []struct {
		name  string
		value string
		limit int
	}{
		{name: "hostname", value: hostinfo.Hostname, limit: registrationHostnameMaxBytes},
		{name: "os", value: hostinfo.OS, limit: registrationOSMaxBytes},
		{name: "client version", value: hostinfo.IPNVersion, limit: registrationVersionMaxBytes},
		{name: "os version", value: hostinfo.OSVersion, limit: registrationVersionMaxBytes},
		{name: "device model", value: hostinfo.DeviceModel, limit: registrationDeviceMaxBytes},
	}
	for _, field := range fields {
		if len(field.value) > field.limit {
			return fmt.Errorf(
				"%w: %s exceeds %d bytes",
				errRegistrationMetadataTooLarge,
				field.name,
				field.limit,
			)
		}
	}

	if len(hostinfo.RequestTags) > registrationTagMaxCount {
		return fmt.Errorf(
			"%w: requested tags exceed %d entries",
			errRegistrationMetadataTooLarge,
			registrationTagMaxCount,
		)
	}

	total := 0

	for _, tag := range hostinfo.RequestTags {
		if len(tag) > registrationTagMaxBytes {
			return fmt.Errorf(
				"%w: requested tag exceeds %d bytes",
				errRegistrationMetadataTooLarge,
				registrationTagMaxBytes,
			)
		}

		total += len(tag)
	}

	if total > registrationTagsTotalMaxBytes {
		return fmt.Errorf(
			"%w: requested tags exceed %d bytes",
			errRegistrationMetadataTooLarge,
			registrationTagsTotalMaxBytes,
		)
	}

	return nil
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

		if perr, ok := errors.AsType[types.PAKError](err); ok {
			return nil, NewHTTPError(http.StatusUnauthorized, perr.Error(), nil)
		}

		return nil, err
	}

	// If node is not valid, it means an ephemeral node was deleted during logout
	if !node.Valid() {
		h.Change(changed)
		return nil, nil //nolint:nilnil // intentional: no node to return when ephemeral deleted
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
	routesChange, err := h.state.AutoApproveRoutes(node)
	if err != nil {
		return nil, fmt.Errorf("auto approving routes: %w", err)
	}

	// Send both changes. Empty changes are ignored by Change().
	h.Change(changed, routesChange)

	resp := &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		NodeKeyExpired:    node.IsExpired(),
		User:              node.Owner().TailscaleUser(),
		Login:             node.Owner().TailscaleLogin(),
	}

	log.Trace().
		Caller().
		Interface("reg.resp", resp).
		Interface("reg.req", req).
		EmbedObject(node).
		Msg("RegisterResponse")

	return resp, nil
}

func (h *Headscale) handleRegisterInteractive(
	req tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	authID, err := types.NewAuthID()
	if err != nil {
		return nil, fmt.Errorf("generating registration ID: %w", err)
	}

	if req.Hostinfo == nil {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Msg("Received registration request with nil hostinfo, generated default hostname")
	} else if req.Hostinfo.Hostname == "" {
		log.Warn().
			Str("machine.key", machineKey.ShortString()).
			Str("node.key", req.NodeKey.ShortString()).
			Msg("Received registration request with empty hostname, generated default")
	}

	regData, err := registrationDataFromRequest(req, machineKey)
	if err != nil {
		return nil, NewHTTPError(http.StatusBadRequest, "registration metadata exceeds limits", err)
	}

	authRegReq := types.NewRegisterAuthRequest(regData)

	err = h.state.SetAuthCacheEntry(authID, authRegReq)
	if err != nil {
		return nil, NewHTTPError(
			http.StatusServiceUnavailable,
			"too many pending registrations; try again later",
			err,
		)
	}

	log.Info().Msgf("starting node registration using auth id: %s", authID)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.RegisterURL(authID),
	}, nil
}
