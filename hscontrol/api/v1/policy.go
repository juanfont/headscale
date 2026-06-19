package apiv1

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/danielgtaylor/huma/v2"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
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

		p := in.Body.Policy

		// Reject policy that would fail when building a map response. SSH rule
		// validation needs a node, so a server with no nodes can't catch every
		// case here.
		nodes := b.State.ListNodes()

		_, err := b.State.SetPolicy([]byte(p))
		if err != nil {
			return nil, huma.Error400BadRequest("setting policy", err)
		}

		if nodes.Len() > 0 {
			_, err = b.State.SSHPolicy(nodes.At(0))
			if err != nil {
				return nil, huma.Error400BadRequest("verifying SSH rules", err)
			}
		}

		updated, err := b.State.SetPolicyInDB(p)
		if err != nil {
			return nil, huma.Error500InternalServerError("setting policy", err)
		}

		// Reload even when content is unchanged: routes manually disabled before
		// may now qualify for auto-approval, so they must be re-evaluated.
		cs, err := b.State.ReloadPolicy()
		if err != nil {
			return nil, huma.Error500InternalServerError("reloading policy", err)
		}

		if len(cs) > 0 {
			b.Change(cs...)
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
		polB := []byte(in.Body.Policy)

		users, err := b.State.ListAllUsers()
		if err != nil {
			return nil, huma.Error500InternalServerError("loading users", err)
		}

		nodes := b.State.ListNodes()

		pm, err := policyv2.NewPolicyManager(polB, users, nodes)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error(), err)
		}

		_, err = pm.SetPolicy(polB)
		if err != nil {
			return nil, huma.Error400BadRequest(err.Error(), err)
		}

		return &checkPolicyOutput{}, nil
	})
}
