package apiv2

import (
	"context"
	"net/http"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

func init() {
	registrations = append(registrations, registerKeys)
}

// defaultExpiry is the auth-key lifetime when the request omits expirySeconds:
// 90 days, matching Tailscale and the Terraform provider default.
const defaultExpiry = 90 * 24 * time.Hour

// keyTypeAuth is the only key kind Headscale issues; Tailscale's OAuth-client
// and federated-identity kinds are out of scope.
const keyTypeAuth = "auth"

// KeyCapabilities maps a resource to the actions a key permits. Headscale
// populates only devices.create (auth keys); the named types (vs Tailscale's
// anonymous nesting) give Huma stable schema names.
type KeyCapabilities struct {
	Devices KeyDeviceCapabilities `json:"devices"`
}

type KeyDeviceCapabilities struct {
	Create KeyDeviceCreateCapabilities `json:"create"`
}

type KeyDeviceCreateCapabilities struct {
	Reusable      bool `json:"reusable"`
	Ephemeral     bool `json:"ephemeral"`
	Preauthorized bool `json:"preauthorized"`
	// Tags is not nullable:"false": the Tailscale clients send "tags":null for
	// an untagged key, which must be accepted. The response always emits [] via
	// emptyIfNil.
	Tags []string `json:"tags"`
}

// CreateKeyRequest is the POST body. expirySeconds is plain seconds (unlike the
// response, see Key).
type CreateKeyRequest struct {
	Capabilities  KeyCapabilities `json:"capabilities"`
	ExpirySeconds int64           `doc:"Lifetime in seconds; defaults to 90 days." json:"expirySeconds,omitempty"`
	Description   string          `json:"description,omitempty"                    maxLength:"50"`
}

// Key is the Tailscale auth-key response. expirySeconds is emitted in seconds
// to match the Tailscale spec; the secret key is present only at creation.
type Key struct {
	ID            string          `json:"id"`
	KeyType       string          `json:"keyType"`
	Key           string          `json:"key,omitempty"`
	Description   string          `json:"description,omitempty"`
	ExpirySeconds int64           `json:"expirySeconds,omitempty"`
	Created       time.Time       `json:"created"`
	Expires       *time.Time      `json:"expires,omitempty"`
	Revoked       *time.Time      `json:"revoked,omitempty"`
	Invalid       bool            `json:"invalid"`
	Capabilities  KeyCapabilities `json:"capabilities"`
	Tags          []string        `json:"tags,omitempty"`
	UserID        string          `json:"userId,omitempty"`
}

type (
	createKeyInput struct {
		Tailnet string `doc:"Tailnet; must be \"-\" (the single Headscale tailnet)." path:"tailnet"`
		Body    CreateKeyRequest
	}

	listKeysInput struct {
		Tailnet string `path:"tailnet"`
		All     bool   `doc:"Accepted for compatibility; Headscale returns all keys." query:"all"`
	}

	keyByIDInput struct {
		Tailnet string `path:"tailnet"`
		KeyID   string `path:"keyId"`
	}

	keyOutput struct {
		Body Key
	}

	listKeysOutput struct {
		Body struct {
			Keys []Key `json:"keys" nullable:"false"`
		}
	}

	deleteKeyOutput struct {
		Body struct{}
	}
)

func registerKeys(api huma.API, b Backend) {
	keysTags := []string{"Keys", "Tailscale compat"}

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "createKey",
		Method:      http.MethodPost,
		Path:        "/api/v2/tailnet/{tailnet}/keys",
		Summary:     "Create an auth key",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusBadRequest,
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, ScopeAuthKeys), func(ctx context.Context, in *createKeyInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		create := in.Body.Capabilities.Devices.Create

		// Ownership: tags -> tagged key; no tags -> owned by the API key's user;
		// no tags and an ownerless (legacy/admin) key -> 400.
		var userID *types.UserID

		if len(create.Tags) == 0 {
			uid, ok := ownerUser(ctx)
			if !ok {
				return nil, huma.Error400BadRequest(
					"an auth key without tags must be created with a user-owned API key",
				)
			}

			userID = &uid
		}

		expiration := time.Now().Add(expiryDuration(in.Body.ExpirySeconds))

		pak, err := b.State.CreatePreAuthKey(
			userID,
			create.Reusable,
			create.Ephemeral,
			&expiration,
			create.Tags,
		)
		if err != nil {
			return nil, mapError("creating auth key", err)
		}

		if in.Body.Description != "" {
			err := b.State.SetPreAuthKeyDescription(
				pak.ID,
				in.Body.Description,
			)
			if err != nil {
				return nil, huma.Error500InternalServerError(
					"setting auth key description",
					err,
				)
			}
		}

		return &keyOutput{Body: keyFromNew(pak, in.Body)}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "listKeys",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys",
		Summary:     "List auth keys",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, ScopeAuthKeysRead), func(ctx context.Context, in *listKeysInput) (*listKeysOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		keys, err := b.State.ListPreAuthKeys()
		if err != nil {
			return nil, huma.Error500InternalServerError("listing auth keys", err)
		}

		out := &listKeysOutput{}
		out.Body.Keys = make([]Key, 0, len(keys))

		for i := range keys {
			out.Body.Keys = append(out.Body.Keys, keyFromStored(&keys[i]))
		}

		return out, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID: "getKey",
		Method:      http.MethodGet,
		Path:        "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:     "Get an auth key",
		Tags:        keysTags,
		Security:    security,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, ScopeAuthKeysRead), func(ctx context.Context, in *keyByIDInput) (*keyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		key, err := findKeyByID(b, in.KeyID)
		if err != nil {
			return nil, err
		}

		return &keyOutput{Body: keyFromStored(key)}, nil
	})

	huma.Register(api, requireScope(huma.Operation{
		OperationID:   "deleteKey",
		Method:        http.MethodDelete,
		Path:          "/api/v2/tailnet/{tailnet}/keys/{keyId}",
		Summary:       "Delete an auth key",
		Tags:          keysTags,
		Security:      security,
		DefaultStatus: http.StatusOK,
		Errors: []int{
			http.StatusUnauthorized,
			http.StatusForbidden,
			http.StatusNotFound,
		},
	}, ScopeAuthKeys), func(ctx context.Context, in *keyByIDInput) (*deleteKeyOutput, error) {
		err := requireDefaultTailnet(in.Tailnet)
		if err != nil {
			return nil, err
		}

		id, err := parseID(in.KeyID, "auth key")
		if err != nil {
			return nil, err
		}

		// Tailscale's DELETE revokes the key but keeps it retrievable (invalid)
		// rather than destroying it; the collector reaps it after the retention
		// window.
		err = b.State.RevokePreAuthKey(id)
		if err != nil {
			return nil, mapError("revoking auth key", err)
		}

		return &deleteKeyOutput{}, nil
	})
}

// findKeyByID looks up a stored pre-auth key by its (stringified) id with a
// direct by-id query; an unknown id surfaces as gorm.ErrRecordNotFound, which
// mapError turns into a 404.
func findKeyByID(b Backend, rawID string) (*types.PreAuthKey, error) {
	id, err := parseID(rawID, "auth key")
	if err != nil {
		return nil, err
	}

	pak, err := b.State.GetPreAuthKeyByID(id)
	if err != nil {
		return nil, mapError("looking up auth key", err)
	}

	return pak, nil
}

// keyFromNew builds the create response from the freshly created key. The
// plaintext secret is returned only here. preauthorized is reported true to
// match keyFromStored: Headscale always authorizes pre-auth-key nodes, so the
// create and read paths must agree or the Terraform provider sees a diff.
func keyFromNew(pak *types.PreAuthKeyNew, req CreateKeyRequest) Key {
	create := req.Capabilities.Devices.Create

	key := Key{
		ID:          pak.StringID(),
		KeyType:     keyTypeAuth,
		Key:         pak.Key,
		Description: req.Description,
		Created:     timeOrZero(pak.CreatedAt),
		Capabilities: capabilities(
			create.Reusable,
			create.Ephemeral,
			true,
			pak.Tags,
		),
		Tags: pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	// A tagged key presents no owner; a user-owned key reports its user id.
	if len(pak.Tags) == 0 && pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

// keyFromStored builds the get/list response from a stored key. The secret is
// never returned here. preauthorized is reported true: Headscale has no separate
// device-approval step, so every pre-auth key authorizes its nodes. Reporting it
// stably keeps the Terraform provider from seeing a forced-replacement diff.
func keyFromStored(pak *types.PreAuthKey) Key {
	key := Key{
		ID:           pak.StringID(),
		KeyType:      keyTypeAuth,
		Description:  pak.Description,
		Created:      timeOrZero(pak.CreatedAt),
		Invalid:      pak.Validate() != nil,
		Capabilities: capabilities(pak.Reusable, pak.Ephemeral, true, pak.Tags),
		Tags:         pak.Tags,
	}

	if pak.Expiration != nil {
		key.Expires = pak.Expiration
		key.ExpirySeconds = expirySeconds(pak.CreatedAt, pak.Expiration)
	}

	if pak.Revoked != nil {
		key.Revoked = pak.Revoked
	}

	if len(pak.Tags) == 0 && pak.User != nil {
		key.UserID = pak.User.StringID()
	}

	return key
}

func capabilities(
	reusable, ephemeral, preauthorized bool,
	tags []string,
) KeyCapabilities {
	return KeyCapabilities{
		Devices: KeyDeviceCapabilities{Create: KeyDeviceCreateCapabilities{
			Reusable:      reusable,
			Ephemeral:     ephemeral,
			Preauthorized: preauthorized,
			Tags:          emptyIfNil(tags),
		}},
	}
}

func expiryDuration(seconds int64) time.Duration {
	if seconds <= 0 {
		return defaultExpiry
	}

	return time.Duration(seconds) * time.Second
}
