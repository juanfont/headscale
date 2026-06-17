package apiv1

import (
	"context"
	"os"

	oas "github.com/juanfont/headscale/gen/api/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

// GetPolicy returns the current ACL policy, from the database or the policy
// file depending on the configured policy mode.
func (s *Server) GetPolicy(_ context.Context) (*oas.GetPolicyOK, error) {
	switch s.cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := s.state.GetPolicy()
		if err != nil {
			return nil, internalError("loading ACL from database: " + err.Error())
		}

		return &oas.GetPolicyOK{
			Policy:    oas.NewOptString(p.Data),
			UpdatedAt: oas.NewOptDateTime(p.UpdatedAt),
		}, nil
	case types.PolicyModeFile:
		absPath := util.AbsolutePathFromConfigPath(s.cfg.Policy.Path)

		b, err := os.ReadFile(absPath)
		if err != nil {
			return nil, internalError("reading policy from path " + absPath + ": " + err.Error())
		}

		return &oas.GetPolicyOK{Policy: oas.NewOptString(string(b))}, nil
	}

	return nil, internalError(
		"no supported policy mode found in configuration, policy.mode: " +
			string(s.cfg.Policy.Mode),
	)
}

// SetPolicy stores a new ACL policy (database policy mode only), validating it
// against the live nodes and distributing the resulting changes.
func (s *Server) SetPolicy(_ context.Context, req *oas.SetPolicyReq) (*oas.SetPolicyOK, error) {
	if s.cfg.Policy.Mode != types.PolicyModeDB {
		return nil, badRequest(types.ErrPolicyUpdateIsDisabled.Error())
	}

	p := req.Policy.Or("")

	// Validate against live nodes, where they exist, before storing.
	nodes := s.state.ListNodes()

	_, err := s.state.SetPolicy([]byte(p))
	if err != nil {
		return nil, badRequest("setting policy: " + err.Error())
	}

	if nodes.Len() > 0 {
		_, err = s.state.SSHPolicy(nodes.At(0))
		if err != nil {
			return nil, badRequest("verifying SSH rules: " + err.Error())
		}
	}

	updated, err := s.state.SetPolicyInDB(p)
	if err != nil {
		return nil, mapStateError(err)
	}

	// Always reload so routes are re-evaluated even when the content is unchanged.
	cs, err := s.state.ReloadPolicy()
	if err != nil {
		return nil, internalError("reloading policy: " + err.Error())
	}

	if len(cs) > 0 {
		s.change(cs...)
	}

	return &oas.SetPolicyOK{
		Policy:    oas.NewOptString(updated.Data),
		UpdatedAt: oas.NewOptDateTime(updated.UpdatedAt),
	}, nil
}

// CheckPolicy validates a policy against the live users and nodes without
// storing it. Works regardless of policy mode.
func (s *Server) CheckPolicy(_ context.Context, req *oas.CheckPolicyReq) error {
	polB := []byte(req.Policy.Or(""))

	users, err := s.state.ListAllUsers()
	if err != nil {
		return internalError("loading users: " + err.Error())
	}

	nodes := s.state.ListNodes()

	pm, err := policyv2.NewPolicyManager(polB, users, nodes)
	if err != nil {
		return badRequest(err.Error())
	}

	_, err = pm.SetPolicy(polB)
	if err != nil {
		return badRequest(err.Error())
	}

	return nil
}
