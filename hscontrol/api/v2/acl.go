package apiv2

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"os"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

func init() {
	registrations = append(registrations, registerACL)
}

const (
	contentTypeJSON   = "application/json"
	contentTypeHuJSON = "application/hujson"
)

// defaultPolicy is served by GET when no policy is set, and is what an If-Match
// of "ts-default" matches against. Allow-all, matching the cluster's behaviour
// with no configured policy.
const defaultPolicy = `{
	// Headscale default policy. Allows all communication.
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
}
`

type getACLInput struct {
	Tailnet string `path:"tailnet"`
	Accept  string `header:"Accept"`
	Details bool   `doc:"Accepted for compatibility; ignored." query:"details"`
}

type setACLInput struct {
	Tailnet string `path:"tailnet"`
	IfMatch string `header:"If-Match"`
	Accept  string `header:"Accept"`
	// RawBody captures the raw HuJSON or JSON policy bytes; huma feeds them here
	// regardless of Content-Type. The declared type only shapes the OpenAPI schema.
	RawBody []byte `contentType:"application/json"`
}

func registerACL(api huma.API, b Backend) {
	aclTags := []string{"Policy", "Tailscale compat"}

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getACL",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/acl",
		Summary:     "Get the policy file",
		Tags:        aclTags,
		Security:    security,
		Errors:      []int{http.StatusUnauthorized, http.StatusForbidden, http.StatusNotFound, http.StatusInternalServerError},
	}, scope.PolicyFileRead), func(ctx context.Context, in *getACLInput) (*huma.StreamResponse, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		data, err := currentPolicy(b)
		if err != nil {
			return nil, err
		}

		return streamPolicy(data, aclContentType(in.Accept)), nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "setACL",
		Method:        http.MethodPost,
		Path:          "/api/v2/tailnet/{tailnet}/acl",
		Summary:       "Set the policy file",
		Tags:          aclTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		// The body is an opaque HuJSON document captured raw; skip huma's
		// schema validation (which would expect a base64 string).
		SkipValidateBody: true,
		Errors: []int{
			http.StatusBadRequest, http.StatusUnauthorized, http.StatusForbidden,
			http.StatusNotFound, http.StatusPreconditionFailed, http.StatusInternalServerError,
		},
	}, scope.PolicyFile), func(ctx context.Context, in *setACLInput) (*huma.StreamResponse, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		if b.Cfg.Policy.Mode != types.PolicyModeDB {
			return nil, huma.Error400BadRequest(
				types.ErrPolicyUpdateIsDisabled.Error(), types.ErrPolicyUpdateIsDisabled,
			)
		}

		if in.IfMatch != "" {
			current, err := currentPolicy(b)
			if err != nil {
				return nil, err
			}

			if !etagMatches(in.IfMatch, current) {
				return nil, huma.Error412PreconditionFailed("precondition failed, invalid old hash")
			}
		}

		// Mirror the v1 setPolicy flow: validate, SSH-check, persist, reload.
		nodes := b.State.ListNodes()

		_, err = b.State.SetPolicy(in.RawBody)
		if err != nil {
			return nil, huma.Error400BadRequest("setting policy", err)
		}

		if nodes.Len() > 0 {
			_, err = b.State.SSHPolicy(nodes.At(0))
			if err != nil {
				return nil, huma.Error400BadRequest("verifying SSH rules", err)
			}
		}

		updated, err := b.State.SetPolicyInDB(string(in.RawBody))
		if err != nil {
			return nil, huma.Error500InternalServerError("setting policy", err)
		}

		cs, err := b.State.ReloadPolicy()
		if err != nil {
			return nil, huma.Error500InternalServerError("reloading policy", err)
		}

		if len(cs) > 0 {
			b.Change(cs...)
		}

		return streamPolicy([]byte(updated.Data), aclContentType(in.Accept)), nil
	})
}

// currentPolicy returns the stored policy bytes, or the allow-all default when
// none is set. File mode reads the configured path; DB mode reads the database.
func currentPolicy(b Backend) ([]byte, error) {
	switch b.Cfg.Policy.Mode {
	case types.PolicyModeDB:
		p, err := b.State.GetPolicy()
		if err != nil {
			if errors.Is(err, types.ErrPolicyNotFound) {
				return []byte(defaultPolicy), nil
			}

			return nil, huma.Error500InternalServerError("loading policy", err)
		}

		if p.Data == "" {
			return []byte(defaultPolicy), nil
		}

		return []byte(p.Data), nil

	case types.PolicyModeFile:
		path := util.AbsolutePathFromConfigPath(b.Cfg.Policy.Path)
		if path == "" {
			return []byte(defaultPolicy), nil
		}

		data, err := os.ReadFile(path)
		if err != nil {
			return nil, huma.Error500InternalServerError("reading policy file", err)
		}

		return data, nil
	}

	return nil, huma.Error500InternalServerError("unsupported policy mode", nil)
}

// streamPolicy writes the policy bytes as-is with the chosen content type and
// a content-addressed ETag, bypassing huma's JSON marshaler so HuJSON survives.
func streamPolicy(data []byte, contentType string) *huma.StreamResponse {
	return &huma.StreamResponse{Body: func(ctx huma.Context) {
		ctx.SetHeader("Content-Type", contentType)
		ctx.SetHeader("ETag", policyETag(data))
		ctx.SetStatus(http.StatusOK)
		_, _ = ctx.BodyWriter().Write(data)
	}}
}

// aclContentType serves HuJSON only when explicitly asked; everything else
// (including an empty Accept) gets application/json. The bytes are identical.
func aclContentType(accept string) string {
	if strings.Contains(accept, contentTypeHuJSON) {
		return contentTypeHuJSON
	}

	return contentTypeJSON
}

// policyETag is the quoted hex SHA-256 of the policy bytes: stable across reads,
// changes iff the policy changes.
func policyETag(data []byte) string {
	sum := sha256.Sum256(data)

	return `"` + hex.EncodeToString(sum[:]) + `"`
}

// etagMatches reports whether an If-Match header satisfies the current policy.
// "*" always matches; "ts-default" matches only when no policy is set (an
// approximation of Tailscale's untouched-default semantics).
func etagMatches(ifMatch string, current []byte) bool {
	ifMatch = strings.TrimSpace(ifMatch)

	switch ifMatch {
	case "*":
		return true
	case `"ts-default"`, "ts-default":
		return string(current) == defaultPolicy
	default:
		return ifMatch == policyETag(current)
	}
}
