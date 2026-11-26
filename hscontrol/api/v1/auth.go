package apiv1

import (
	"context"
	"errors"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerAuth)
}

// AuthRegisterRequestBody is the v1.AuthRegisterRequest body.
type AuthRegisterRequestBody struct {
	User   string `json:"user,omitempty"`
	AuthID string `json:"authId,omitempty"`
}

// AuthApproveRequestBody is the v1.AuthApproveRequest body.
type AuthApproveRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

// AuthRejectRequestBody is the v1.AuthRejectRequest body.
type AuthRejectRequestBody struct {
	AuthID string `json:"authId,omitempty"`
}

type (
	authRegisterInput struct {
		Body AuthRegisterRequestBody
	}
	authRegisterOutput struct {
		Body struct {
			Node Node `json:"node"`
		}
	}
)

type (
	authApproveInput struct {
		Body AuthApproveRequestBody
	}
	authApproveOutput struct {
		Body struct{}
	}
)

type (
	authRejectInput struct {
		Body AuthRejectRequestBody
	}
	authRejectOutput struct {
		Body struct{}
	}
)

func registerAuth(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "authRegister",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/register",
		Summary:     "Register node via auth flow",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRegisterInput) (*authRegisterOutput, error) {
		// Malformed auth_id is 400; unknown user and missing pending session are
		// 404 via mapError, matching the Approve/Reject handlers.
		registrationID, err := types.AuthIDFromString(in.Body.AuthID)
		if err != nil {
			return nil, huma.Error400BadRequest("registering node", err)
		}

		user, err := b.State.GetUserByName(in.Body.User)
		if err != nil {
			return nil, mapError("looking up user", err)
		}

		node, nodeChange, err := b.State.HandleNodeFromAuthPath(
			registrationID,
			types.UserID(user.ID),
			nil,
			util.RegisterMethodCLI,
		)
		b.Change(nodeChange)

		if err != nil {
			return nil, mapError("registering node", err)
		}

		out := &authRegisterOutput{}
		out.Body.Node = nodeFromView(node)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authApprove",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/approve",
		Summary:     "Approve a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authApproveInput) (*authApproveOutput, error) {
		err := answerAuthRequest(b, in.Body.AuthID, types.AuthVerdict{})
		if err != nil {
			return nil, err
		}

		return &authApproveOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "authReject",
		Method:      http.MethodPost,
		Path:        "/api/v1/auth/reject",
		Summary:     "Reject a pending auth session",
		Tags:        []string{"Auth"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *authRejectInput) (*authRejectOutput, error) {
		err := answerAuthRequest(b, in.Body.AuthID, types.AuthVerdict{Err: state.ErrAuthRequestRejected})
		if err != nil {
			return nil, err
		}

		return &authRejectOutput{}, nil
	})
}

// answerAuthRequest gives the pending session for auth_id verdict.
// Malformed auth_id is 400; unknown, timed out or answered already is 404.
func answerAuthRequest(b Backend, rawID string, verdict types.AuthVerdict) error {
	authID, err := types.AuthIDFromString(rawID)
	if err != nil {
		return huma.Error400BadRequest("invalid auth_id", err)
	}

	err = b.State.ResolveAuthRequest(authID, verdict)
	if errors.Is(err, db.ErrNodeNotFoundRegistrationCache) {
		return huma.Error404NotFound("no pending auth session for auth_id")
	}

	return err
}
