package apiv1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerPolicy)
}

// PolicyRequestBody carries the HuJSON policy document as a string, for both
// v1.SetPolicyRequest and v1.CheckPolicyRequest.
type PolicyRequestBody struct {
	Policy string `json:"policy,omitempty"`
}

// PolicyResponseBody is the v1.GetPolicyResponse/SetPolicyResponse body. Fields
// carry no omitempty so zero values are emitted (EmitUnpopulated parity).
type PolicyResponseBody struct {
	Policy    string    `json:"policy"`
	UpdatedAt time.Time `json:"updatedAt"`
}

type (
	getPolicyInput  struct{}
	getPolicyOutput struct {
		Body PolicyResponseBody
	}

	setPolicyInput struct {
		Body PolicyRequestBody
	}
	setPolicyOutput struct {
		Body PolicyResponseBody
	}

	checkPolicyInput struct {
		Body PolicyRequestBody
	}
	checkPolicyOutput struct {
		Body struct{}
	}
)

func registerPolicy(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "getPolicy",
		Method:      http.MethodGet,
		Path:        "/api/v1/policy",
		Summary:     "Get policy",
		Tags:        []string{"Policy"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *getPolicyInput) (*getPolicyOutput, error) {
		switch b.Cfg.Policy.Mode {
		case types.PolicyModeDB:
			p, err := b.State.GetPolicy()
			if err != nil {
				return nil, huma.Error500InternalServerError("loading ACL from database", err)
			}

			out := &getPolicyOutput{}
			out.Body.Policy = p.Data
			out.Body.UpdatedAt = p.UpdatedAt

			return out, nil
		case types.PolicyModeFile:
			absPath := util.AbsolutePathFromConfigPath(b.Cfg.Policy.Path)

			f, err := os.Open(absPath)
			if err != nil {
				return nil, huma.Error500InternalServerError(
					fmt.Sprintf("reading policy from path %q", absPath), err,
				)
			}
			defer f.Close()

			data, err := io.ReadAll(f)
			if err != nil {
				return nil, huma.Error500InternalServerError("reading policy from file", err)
			}

			out := &getPolicyOutput{}
			out.Body.Policy = string(data)

			return out, nil
		}

		return nil, huma.Error500InternalServerError(fmt.Sprintf(
			"no supported policy mode found in configuration, policy.mode: %q",
			b.Cfg.Policy.Mode,
		), nil)
	})

	huma.Register(api, huma.Operation{
		OperationID: "setPolicy",
		Method:      http.MethodPut,
		Path:        "/api/v1/policy",
		Summary:     "Set policy",
		Tags:        []string{"Policy"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *setPolicyInput) (*setPolicyOutput, error) {
		if b.Cfg.Policy.Mode != types.PolicyModeDB {
			// Policy updates are only valid in DB mode; otherwise 400.
			return nil, huma.Error400BadRequest(
				types.ErrPolicyUpdateIsDisabled.Error(), types.ErrPolicyUpdateIsDisabled,
			)
		}

		updated, cs, err := b.State.UpdatePolicy([]byte(in.Body.Policy))
		b.Change(cs...)

		if err != nil {
			return nil, mapError("setting policy", err)
		}

		out := &setPolicyOutput{}
		out.Body.Policy = updated.Data
		out.Body.UpdatedAt = updated.UpdatedAt

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "checkPolicy",
		Method:      http.MethodPost,
		Path:        "/api/v1/policy/check",
		Summary:     "Check policy",
		Description: "Validates the given policy against the server's live users and nodes without persisting it.",
		Tags:        []string{"Policy"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *checkPolicyInput) (*checkPolicyOutput, error) {
		err := b.State.ValidatePolicy([]byte(in.Body.Policy))
		if err != nil {
			return nil, mapError(err.Error(), err)
		}

		return &checkPolicyOutput{}, nil
	})
}
