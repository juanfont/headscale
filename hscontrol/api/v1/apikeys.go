package apiv1

import (
	"cmp"
	"context"
	"slices"
	"time"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/types"
)

// CreateApiKey creates an API key and returns the full secret. This is the only
// time the secret is exposed.
func (s *Server) CreateApiKey(
	_ context.Context,
	req *oas.CreateApiKeyReq,
) (*oas.CreateApiKeyOK, error) {
	var expiration time.Time
	if v, ok := req.Expiration.Get(); ok {
		expiration = v
	}

	key, _, err := s.state.CreateAPIKey(&expiration)
	if err != nil {
		return nil, mapStateError(err)
	}

	return &oas.CreateApiKeyOK{ApiKey: oas.NewOptString(key)}, nil
}

// ListApiKeys lists all API keys (masked), sorted by id.
func (s *Server) ListApiKeys(_ context.Context) (*oas.ListApiKeysOK, error) {
	keys, err := s.state.ListAPIKeys()
	if err != nil {
		return nil, mapStateError(err)
	}

	slices.SortFunc(keys, func(a, b types.APIKey) int { return cmp.Compare(a.ID, b.ID) })

	out := make([]oas.ApiKey, len(keys))
	for i := range keys {
		out[i] = oasAPIKey(&keys[i])
	}

	return &oas.ListApiKeysOK{ApiKeys: out}, nil
}

// ExpireApiKey expires an API key identified by id or prefix.
func (s *Server) ExpireApiKey(_ context.Context, req *oas.ExpireApiKeyReq) error {
	key, apiErr := s.apiKeyByIDOrPrefix(req.ID.Or(0), req.Prefix.Or(""))
	if apiErr != nil {
		return apiErr
	}

	err := s.state.ExpireAPIKey(key)
	if err != nil {
		return mapStateError(err)
	}

	return nil
}

// DeleteApiKey deletes an API key identified by prefix (or id).
func (s *Server) DeleteApiKey(_ context.Context, params oas.DeleteApiKeyParams) error {
	key, apiErr := s.apiKeyByIDOrPrefix(params.ID.Or(0), params.Prefix)
	if apiErr != nil {
		return apiErr
	}

	err := s.state.DestroyAPIKey(*key)
	if err != nil {
		return mapStateError(err)
	}

	return nil
}

// apiKeyByIDOrPrefix looks up an API key by exactly one of id or prefix.
// Providing neither or both is a 400.
func (s *Server) apiKeyByIDOrPrefix(
	id uint64,
	prefix string,
) (*types.APIKey, *oas.ErrorStatusCode) {
	hasID := id != 0
	hasPrefix := prefix != ""

	switch {
	case hasID && hasPrefix:
		return nil, badRequest("provide either id or prefix, not both")
	case hasID:
		key, err := s.state.GetAPIKeyByID(id)
		if err != nil {
			return nil, mapStateError(err)
		}

		return key, nil
	case hasPrefix:
		key, err := s.state.GetAPIKey(prefix)
		if err != nil {
			return nil, mapStateError(err)
		}

		return key, nil
	default:
		return nil, badRequest("must provide id or prefix")
	}
}
