package apiv1

import (
	"cmp"
	"context"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerApiKeys)
}

// ApiKey is the v1 ApiKey message. Timestamps are pointers so a nil source is
// emitted as JSON null, matching protojson's unset Timestamp (e.g. lastSeen on
// a fresh key).
type ApiKey struct {
	ID         string     `format:"uint64"   json:"id"`
	Prefix     string     `json:"prefix"`
	Expiration *time.Time `json:"expiration" nullable:"true"`
	CreatedAt  *time.Time `json:"createdAt"  nullable:"true"`
	LastSeen   *time.Time `json:"lastSeen"   nullable:"true"`
}

// CreateApiKeyRequestBody is the v1.CreateApiKeyRequest body.
type CreateApiKeyRequestBody struct {
	Expiration *time.Time `json:"expiration,omitempty"`
}

// ExpireApiKeyRequestBody is the v1.ExpireApiKeyRequest body.
type ExpireApiKeyRequestBody struct {
	Prefix string `json:"prefix,omitempty"`
	ID     string `format:"uint64"         json:"id,omitempty"`
}

type (
	createApiKeyInput struct {
		Body CreateApiKeyRequestBody
	}
	createApiKeyOutput struct {
		Body struct {
			APIKey string `json:"apiKey"`
		}
	}
)

type (
	expireApiKeyInput struct {
		Body ExpireApiKeyRequestBody
	}
	expireApiKeyOutput struct {
		Body struct{}
	}
)

type (
	listApiKeysOutput struct {
		Body struct {
			APIKeys []ApiKey `json:"apiKeys" nullable:"false"`
		}
	}
)

type (
	deleteApiKeyInput struct {
		Prefix string `path:"prefix"`
		ID     string `format:"uint64" query:"id"`
	}
	deleteApiKeyOutput struct {
		Body struct{}
	}
)

func registerApiKeys(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "createApiKey",
		Method:      http.MethodPost,
		Path:        "/api/v1/apikey",
		Summary:     "Create API key",
		Tags:        []string{"ApiKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *createApiKeyInput) (*createApiKeyOutput, error) {
		// CreateAPIKey requires a non-nil pointer; default a missing expiration
		// to the zero time as the gRPC handler does.
		var expiration time.Time
		if in.Body.Expiration != nil {
			expiration = *in.Body.Expiration
		}

		keyStr, _, err := b.State.CreateAPIKey(&expiration)
		if err != nil {
			return nil, huma.Error500InternalServerError("creating api key", err)
		}

		out := &createApiKeyOutput{}
		out.Body.APIKey = keyStr

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "expireApiKey",
		Method:      http.MethodPost,
		Path:        "/api/v1/apikey/expire",
		Summary:     "Expire API key",
		Tags:        []string{"ApiKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *expireApiKeyInput) (*expireApiKeyOutput, error) {
		key, err := lookupApiKey(b, in.Body.ID, in.Body.Prefix)
		if err != nil {
			return nil, err
		}

		err = b.State.ExpireAPIKey(key)
		if err != nil {
			return nil, huma.Error500InternalServerError("expiring api key", err)
		}

		return &expireApiKeyOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listApiKeys",
		Method:      http.MethodGet,
		Path:        "/api/v1/apikey",
		Summary:     "List API keys",
		Tags:        []string{"ApiKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listApiKeysOutput, error) {
		keys, err := b.State.ListAPIKeys()
		if err != nil {
			return nil, huma.Error500InternalServerError("listing api keys", err)
		}

		// Match the gRPC handler's ascending-ID ordering.
		slices.SortFunc(keys, func(a, b types.APIKey) int {
			return cmp.Compare(a.ID, b.ID)
		})

		out := &listApiKeysOutput{}

		out.Body.APIKeys = make([]ApiKey, len(keys))
		for i := range keys {
			out.Body.APIKeys[i] = apiKeyFromState(&keys[i])
		}

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deleteApiKey",
		Method:      http.MethodDelete,
		Path:        "/api/v1/apikey/{prefix}",
		Summary:     "Delete API key",
		Tags:        []string{"ApiKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *deleteApiKeyInput) (*deleteApiKeyOutput, error) {
		key, err := lookupApiKey(b, in.ID, in.Prefix)
		if err != nil {
			return nil, err
		}

		err = b.State.DestroyAPIKey(*key)
		if err != nil {
			return nil, huma.Error500InternalServerError("deleting api key", err)
		}

		return &deleteApiKeyOutput{}, nil
	})
}

// lookupApiKey resolves an API key by id or prefix; exactly one must be
// supplied. An empty or zero id counts as "no id". Unknown id/prefix maps to
// 404 via mapError.
func lookupApiKey(b Backend, idStr, prefix string) (*types.APIKey, error) {
	id, err := parseApiKeyID(idStr)
	if err != nil {
		return nil, err
	}

	hasID := id != 0
	hasPrefix := prefix != ""

	switch {
	case hasID && hasPrefix:
		return nil, huma.Error400BadRequest("provide either id or prefix, not both")
	case hasID:
		key, err := b.State.GetAPIKeyByID(id)
		if err != nil {
			return nil, mapError("getting api key", err)
		}

		return key, nil
	case hasPrefix:
		key, err := b.State.GetAPIKey(prefix)
		if err != nil {
			return nil, mapError("getting api key", err)
		}

		return key, nil
	default:
		return nil, huma.Error400BadRequest("must provide id or prefix")
	}
}

// parseApiKeyID decodes the optional uint64 id. Empty maps to zero; non-numeric
// is rejected with 400.
func parseApiKeyID(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}

	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest("invalid api key id", err)
	}

	return id, nil
}

// apiKeyFromState converts a domain API key into the v1 response shape, masking
// the prefix so the secret is never returned.
func apiKeyFromState(k *types.APIKey) ApiKey {
	return ApiKey{
		ID:         formatID(k.ID),
		Prefix:     apiKeyMaskedPrefix(k.Prefix),
		Expiration: k.Expiration,
		CreatedAt:  k.CreatedAt,
		LastSeen:   k.LastSeen,
	}
}

// apiKeyMaskedPrefix reproduces the unexported types.APIKey.maskedPrefix.
func apiKeyMaskedPrefix(prefix string) string {
	if len(prefix) == types.NewAPIKeyPrefixLength {
		return "hskey-api-" + prefix + "-***"
	}

	return prefix + "***"
}
