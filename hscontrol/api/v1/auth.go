package apiv1

import (
	"context"
	"errors"
	"net/http"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

var errAuthRejected = errors.New("auth request rejected")

// HandleBearerAuth validates the API key bearer token against the state layer.
// A missing or malformed Authorization header is reported by ogen before this
// is reached. Any validation failure — a malformed/unknown key (which
// [state.State.ValidateAPIKey] reports as an error) or an expired/invalid one —
// is a 401, matching the previous middleware which rejected every such case
// with Unauthorized.
func (s *Server) HandleBearerAuth(
	ctx context.Context,
	_ oas.OperationName,
	t oas.BearerAuth,
) (context.Context, error) {
	valid, err := s.state.ValidateAPIKey(t.Token)
	if err != nil || !valid {
		return ctx, apiError(http.StatusUnauthorized, "invalid API key")
	}

	return ctx, nil
}

// AuthRegister registers a node via an auth id; it is an alias of RegisterNode.
func (s *Server) AuthRegister(
	ctx context.Context,
	req *oas.AuthRegisterReq,
) (*oas.AuthRegisterOK, error) {
	resp, err := s.RegisterNode(ctx, oas.RegisterNodeParams{
		Key:  oas.NewOptString(req.AuthId.Or("")),
		User: oas.NewOptString(req.User.Or("")),
	})
	if err != nil {
		return nil, err
	}

	return &oas.AuthRegisterOK{Node: resp.Node}, nil
}

// AuthApprove approves a pending auth session.
func (s *Server) AuthApprove(_ context.Context, req *oas.AuthApproveReq) error {
	authReq, apiErr := s.pendingAuth(req.AuthId.Or(""))
	if apiErr != nil {
		return apiErr
	}

	authReq.FinishAuth(types.AuthVerdict{})

	return nil
}

// AuthReject rejects a pending auth session.
func (s *Server) AuthReject(_ context.Context, req *oas.AuthRejectReq) error {
	authReq, apiErr := s.pendingAuth(req.AuthId.Or(""))
	if apiErr != nil {
		return apiErr
	}

	authReq.FinishAuth(types.AuthVerdict{Err: errAuthRejected})

	return nil
}

// pendingAuth resolves an auth id to its cached, in-progress auth request.
// An unparseable id is a 400; an unknown one is a 404.
func (s *Server) pendingAuth(authID string) (*types.AuthRequest, *oas.ErrorStatusCode) {
	id, err := types.AuthIDFromString(authID)
	if err != nil {
		return nil, badRequest("invalid auth_id: " + err.Error())
	}

	authReq, ok := s.state.GetAuthCacheEntry(id)
	if !ok {
		return nil, notFound("no pending auth session for auth_id " + id.String())
	}

	return authReq, nil
}
