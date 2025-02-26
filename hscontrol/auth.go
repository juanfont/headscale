package hscontrol

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
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
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	node, err := h.db.GetNodeByNodeKey(regReq.NodeKey)
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, fmt.Errorf("looking up node in database: %w", err)
	}

	if node != nil {
		resp, err := h.handleExistingNode(node, regReq, machineKey)
		if err != nil {
			return nil, fmt.Errorf("handling existing node: %w", err)
		}

		return resp, nil
	}

	if regReq.Followup != "" {
		return h.waitForFollowup(ctx, regReq)
	}

	if regReq.Auth != nil && regReq.Auth.AuthKey != "" {
		resp, err := h.handleRegisterWithAuthKey(regReq, machineKey)
		if err != nil {
			return nil, fmt.Errorf("handling register with auth key: %w", err)
		}

		return resp, nil
	}

	resp, err := h.handleRegisterInteractive(regReq, machineKey)
	if err != nil {
		return nil, fmt.Errorf("handling register interactive: %w", err)
	}

	return resp, nil
}

func (h *Headscale) handleExistingNode(
	node *types.Node,
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	if node.MachineKey != machineKey {
		return nil, NewHTTPError(http.StatusUnauthorized, "node exist with different machine key", nil)
	}

	expired := node.IsExpired()
	if !expired && !regReq.Expiry.IsZero() {
		requestExpiry := regReq.Expiry

		// The client is trying to extend their key, this is not allowed.
		if requestExpiry.After(time.Now()) {
			return nil, NewHTTPError(http.StatusBadRequest, "extending key is not allowed", nil)
		}

		// If the request expiry is in the past, we consider it a logout.
		if requestExpiry.Before(time.Now()) {
			if node.IsEphemeral() {
				err := h.db.DeleteNode(node)
				if err != nil {
					return nil, fmt.Errorf("deleting ephemeral node: %w", err)
				}

				ctx := types.NotifyCtx(context.Background(), "logout-ephemeral", "na")
				h.nodeNotifier.NotifyAll(ctx, types.UpdatePeerRemoved(node.ID))
			}

			expired = true
		}

		err := h.db.NodeSetExpiry(node.ID, requestExpiry)
		if err != nil {
			return nil, fmt.Errorf("setting node expiry: %w", err)
		}

		ctx := types.NotifyCtx(context.Background(), "logout-expiry", "na")
		h.nodeNotifier.NotifyWithIgnore(ctx, types.UpdateExpire(node.ID, requestExpiry), node.ID)
	}

	return nodeToRegisterResponse(node), nil
}

func nodeToRegisterResponse(node *types.Node) *tailcfg.RegisterResponse {
	return &tailcfg.RegisterResponse{
		// TODO(kradalby): Only send for user-owned nodes
		// and not tagged nodes when tags is working.
		User:           *node.User.TailscaleUser(),
		Login:          *node.User.TailscaleLogin(),
		NodeKeyExpired: node.IsExpired(),

		// Headscale does not implement the concept of machine authorization
		// so we always return true here.
		// Revisit this if #2176 gets implemented.
		MachineAuthorized: true,
	}
}

func (h *Headscale) waitForFollowup(
	ctx context.Context,
	regReq tailcfg.RegisterRequest,
) (*tailcfg.RegisterResponse, error) {
	fu, err := url.Parse(regReq.Followup)
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid followup URL", err)
	}

	followupReg, err := types.RegistrationIDFromString(strings.ReplaceAll(fu.Path, "/register/", ""))
	if err != nil {
		return nil, NewHTTPError(http.StatusUnauthorized, "invalid registration ID", err)
	}

	if reg, ok := h.registrationCache.Get(followupReg); ok {
		select {
		case <-ctx.Done():
			return nil, NewHTTPError(http.StatusUnauthorized, "registration timed out", err)
		case node := <-reg.Registered:
			if node == nil {
				return nil, NewHTTPError(http.StatusUnauthorized, "node not found", nil)
			}
			return nodeToRegisterResponse(node), nil
		}
	}

	return nil, NewHTTPError(http.StatusNotFound, "followup registration not found", nil)
}

// canUsePreAuthKey checks if a pre auth key can be used.
func canUsePreAuthKey(pak *types.PreAuthKey) error {
	if pak == nil {
		return NewHTTPError(http.StatusUnauthorized, "invalid authkey", nil)
	}
	if pak.Expiration != nil && pak.Expiration.Before(time.Now()) {
		return NewHTTPError(http.StatusUnauthorized, "authkey expired", nil)
	}

	// we don't need to check if has been used before
	if pak.Reusable {
		return nil
	}

	if pak.Used {
		return NewHTTPError(http.StatusUnauthorized, "authkey already used", nil)
	}

	return nil
}

func (h *Headscale) handleRegisterWithAuthKey(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	pak, err := h.db.GetPreAuthKey(regReq.Auth.AuthKey)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, NewHTTPError(http.StatusUnauthorized, "invalid pre auth key", nil)
		}
		return nil, err
	}

	err = canUsePreAuthKey(pak)
	if err != nil {
		return nil, err
	}

	nodeToRegister := types.Node{
		Hostname:       regReq.Hostinfo.Hostname,
		UserID:         pak.User.ID,
		User:           pak.User,
		MachineKey:     machineKey,
		NodeKey:        regReq.NodeKey,
		Hostinfo:       regReq.Hostinfo,
		LastSeen:       ptr.To(time.Now()),
		RegisterMethod: util.RegisterMethodAuthKey,

		// TODO(kradalby): This should not be set on the node,
		// they should be looked up through the key, which is
		// attached to the node.
		ForcedTags: pak.Proto().GetAclTags(),
		AuthKey:    pak,
		AuthKeyID:  &pak.ID,
	}

	if !regReq.Expiry.IsZero() {
		nodeToRegister.Expiry = &regReq.Expiry
	}

	ipv4, ipv6, err := h.ipAlloc.Next()
	if err != nil {
		return nil, fmt.Errorf("allocating IPs: %w", err)
	}

	node, err := db.Write(h.db.DB, func(tx *gorm.DB) (*types.Node, error) {
		node, err := db.RegisterNode(tx,
			nodeToRegister,
			ipv4, ipv6,
		)
		if err != nil {
			return nil, fmt.Errorf("registering node: %w", err)
		}

		if !pak.Reusable {
			err = db.UsePreAuthKey(tx, pak)
			if err != nil {
				return nil, fmt.Errorf("using pre auth key: %w", err)
			}
		}

		return node, nil
	})
	if err != nil {
		return nil, err
	}

	updateSent, err := nodesChangedHook(h.db, h.polMan, h.nodeNotifier)
	if err != nil {
		return nil, fmt.Errorf("nodes changed hook: %w", err)
	}

	if !updateSent {
		ctx := types.NotifyCtx(context.Background(), "node updated", node.Hostname)
		h.nodeNotifier.NotifyAll(ctx, types.UpdatePeerChanged(node.ID))
	}

	return &tailcfg.RegisterResponse{
		MachineAuthorized: true,
		NodeKeyExpired:    node.IsExpired(),
		User:              *pak.User.TailscaleUser(),
		Login:             *pak.User.TailscaleLogin(),
	}, nil
}

func (h *Headscale) handleRegisterInteractive(
	regReq tailcfg.RegisterRequest,
	machineKey key.MachinePublic,
) (*tailcfg.RegisterResponse, error) {
	registrationId, err := types.NewRegistrationID()
	if err != nil {
		return nil, fmt.Errorf("generating registration ID: %w", err)
	}

	newNode := types.RegisterNode{
		Node: types.Node{
			Hostname:   regReq.Hostinfo.Hostname,
			MachineKey: machineKey,
			NodeKey:    regReq.NodeKey,
			Hostinfo:   regReq.Hostinfo,
			LastSeen:   ptr.To(time.Now()),
		},
		Registered: make(chan *types.Node),
	}

	if !regReq.Expiry.IsZero() {
		newNode.Node.Expiry = &regReq.Expiry
	}

	h.registrationCache.Set(
		registrationId,
		newNode,
	)

	return &tailcfg.RegisterResponse{
		AuthURL: h.authProvider.AuthURL(registrationId),
	}, nil
}
