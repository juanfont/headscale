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
	registrations = append(registrations, registerPreAuthKeys)
}

// PreAuthKey is the v1 PreAuthKey message. User is a pointer with no omitempty
// so tagged (system-created) keys emit "user":null. Expiration and CreatedAt
// are always emitted, zero-stamped when unset.
type PreAuthKey struct {
	User       *User     `json:"user"`
	ID         string    `format:"uint64"   json:"id"`
	Key        string    `json:"key"`
	Reusable   bool      `json:"reusable"`
	Ephemeral  bool      `json:"ephemeral"`
	Used       bool      `json:"used"`
	Expiration time.Time `json:"expiration"`
	CreatedAt  time.Time `json:"createdAt"`
	ACLTags    []string  `json:"aclTags"    nullable:"false"`
}

// CreatePreAuthKeyRequestBody is the v1.CreatePreAuthKeyRequest body. Every
// field is optional, hence omitempty throughout.
type CreatePreAuthKeyRequestBody struct {
	User       string     `format:"uint64"             json:"user,omitempty"`
	Reusable   bool       `json:"reusable,omitempty"`
	Ephemeral  bool       `json:"ephemeral,omitempty"`
	Expiration *time.Time `json:"expiration,omitempty"`
	ACLTags    []string   `json:"aclTags,omitempty"`
}

// ExpirePreAuthKeyRequestBody is the v1.ExpirePreAuthKeyRequest body.
type ExpirePreAuthKeyRequestBody struct {
	ID string `format:"uint64" json:"id,omitempty"`
}

type (
	createPreAuthKeyInput struct {
		Body CreatePreAuthKeyRequestBody
	}
	preAuthKeyOutput struct {
		Body struct {
			PreAuthKey PreAuthKey `json:"preAuthKey"`
		}
	}
)

type (
	expirePreAuthKeyInput struct {
		Body ExpirePreAuthKeyRequestBody
	}
	expirePreAuthKeyOutput struct {
		Body struct{}
	}
)

type (
	deletePreAuthKeyInput struct {
		ID string `format:"uint64" query:"id"`
	}
	deletePreAuthKeyOutput struct {
		Body struct{}
	}
)

type listPreAuthKeysOutput struct {
	Body struct {
		PreAuthKeys []PreAuthKey `json:"preAuthKeys" nullable:"false"`
	}
}

func registerPreAuthKeys(api huma.API, b Backend) {
	huma.Register(api, huma.Operation{
		OperationID: "createPreAuthKey",
		Method:      http.MethodPost,
		Path:        "/api/v1/preauthkey",
		Summary:     "Create pre-auth key",
		Tags:        []string{"PreAuthKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *createPreAuthKeyInput) (*preAuthKeyOutput, error) {
		user, err := parsePreAuthKeyUser(in.Body.User)
		if err != nil {
			return nil, err
		}

		for _, tag := range in.Body.ACLTags {
			tagErr := validateTag(tag)
			if tagErr != nil {
				return nil, huma.Error400BadRequest("invalid tag", tagErr)
			}
		}

		// CreatePreAuthKey requires a non-nil pointer; zero-stamp when unset.
		var expiration time.Time
		if in.Body.Expiration != nil {
			expiration = *in.Body.Expiration
		}

		var userID *types.UserID

		if user != 0 {
			u, getErr := b.State.GetUserByID(user)
			if getErr != nil {
				return nil, mapError("creating pre-auth key", getErr)
			}

			userID = u.TypedID()
		}

		preAuthKey, err := b.State.CreatePreAuthKey(
			userID,
			in.Body.Reusable,
			in.Body.Ephemeral,
			&expiration,
			in.Body.ACLTags,
		)
		if err != nil {
			// A key that is neither tagged nor user-owned is invalid input (400).
			return nil, mapError("creating pre-auth key", err)
		}

		out := &preAuthKeyOutput{}
		out.Body.PreAuthKey = preAuthKeyNewToResponse(preAuthKey)

		return out, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "expirePreAuthKey",
		Method:      http.MethodPost,
		Path:        "/api/v1/preauthkey/expire",
		Summary:     "Expire pre-auth key",
		Tags:        []string{"PreAuthKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *expirePreAuthKeyInput) (*expirePreAuthKeyOutput, error) {
		id, err := parsePreAuthKeyID(in.Body.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.ExpirePreAuthKey(id)
		if err != nil {
			// An unknown key id maps to 404.
			return nil, mapError("expiring pre-auth key", err)
		}

		return &expirePreAuthKeyOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "deletePreAuthKey",
		Method:      http.MethodDelete,
		Path:        "/api/v1/preauthkey",
		Summary:     "Delete pre-auth key",
		Tags:        []string{"PreAuthKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, in *deletePreAuthKeyInput) (*deletePreAuthKeyOutput, error) {
		// DELETE has no body: id is bound from the query string.
		id, err := parsePreAuthKeyID(in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.DeletePreAuthKey(id)
		if err != nil {
			// An unknown key id maps to 404.
			return nil, mapError("deleting pre-auth key", err)
		}

		return &deletePreAuthKeyOutput{}, nil
	})

	huma.Register(api, huma.Operation{
		OperationID: "listPreAuthKeys",
		Method:      http.MethodGet,
		Path:        "/api/v1/preauthkey",
		Summary:     "List pre-auth keys",
		Tags:        []string{"PreAuthKeys"},
		Security:    bearerAuth,
	}, func(ctx context.Context, _ *struct{}) (*listPreAuthKeysOutput, error) {
		preAuthKeys, err := b.State.ListPreAuthKeys()
		if err != nil {
			return nil, huma.Error500InternalServerError("listing pre-auth keys", err)
		}

		// Match the gRPC handler's ascending-ID ordering.
		slices.SortFunc(preAuthKeys, func(a, b types.PreAuthKey) int {
			return cmp.Compare(a.ID, b.ID)
		})

		out := &listPreAuthKeysOutput{}

		out.Body.PreAuthKeys = make([]PreAuthKey, len(preAuthKeys))
		for i := range preAuthKeys {
			out.Body.PreAuthKeys[i] = preAuthKeyToResponse(&preAuthKeys[i])
		}

		return out, nil
	})
}

// preAuthKeyNewToResponse builds the v1 response for a freshly created key. The
// plaintext key is returned only here; Used is always false.
func preAuthKeyNewToResponse(key *types.PreAuthKeyNew) PreAuthKey {
	out := PreAuthKey{
		ID:        formatID(key.ID),
		Key:       key.Key,
		Reusable:  key.Reusable,
		Ephemeral: key.Ephemeral,
		ACLTags:   nonNilTags(key.Tags),
	}

	if key.User != nil {
		u := userFromView(key.User.View())
		out.User = &u
	}

	if key.Expiration != nil {
		out.Expiration = *key.Expiration
	}

	if key.CreatedAt != nil {
		out.CreatedAt = *key.CreatedAt
	}

	return out
}

// preAuthKeyToResponse builds the v1 response for a stored key, with its key
// field masked (see maskedPreAuthKey).
func preAuthKeyToResponse(key *types.PreAuthKey) PreAuthKey {
	out := PreAuthKey{
		ID:        formatID(key.ID),
		Key:       maskedPreAuthKey(key.View()),
		Reusable:  key.Reusable,
		Ephemeral: key.Ephemeral,
		Used:      key.Used,
		ACLTags:   nonNilTags(key.Tags),
	}

	if key.User != nil {
		u := userFromView(key.User.View())
		out.User = &u
	}

	if key.Expiration != nil {
		out.Expiration = *key.Expiration
	}

	if key.CreatedAt != nil {
		out.CreatedAt = *key.CreatedAt
	}

	return out
}

// maskedPreAuthKey masks new keys (those with a stored prefix) so the secret is
// never returned; legacy plaintext keys are returned in full for backwards
// compatibility.
func maskedPreAuthKey(key types.PreAuthKeyView) string {
	if key.Prefix() != "" {
		return "hskey-auth-" + key.Prefix() + "-***"
	}

	return key.Key()
}

// nonNilTags ensures aclTags serializes as [] rather than null, matching
// EmitUnpopulated output.
func nonNilTags(tags []string) []string {
	if tags == nil {
		return []string{}
	}

	return tags
}

// parsePreAuthKeyUser parses the optional uint64 user field. Empty means "no
// user" (user 0); non-numeric is rejected with 400.
func parsePreAuthKeyUser(s string) (types.UserID, error) {
	if s == "" {
		return 0, nil
	}

	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest("invalid user id", err)
	}

	return types.UserID(id), nil
}

// parsePreAuthKeyID parses the uint64 key id. Empty means id 0; non-numeric is
// rejected with 400.
func parsePreAuthKeyID(s string) (uint64, error) {
	if s == "" {
		return 0, nil
	}

	id, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, huma.Error400BadRequest("invalid pre-auth key id", err)
	}

	return id, nil
}
