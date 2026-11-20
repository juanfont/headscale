package apiv0

import (
	"context"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
)

// ApiKey is an API key, the same object in a list, a get and, with its
// secret, the answer to a create. No other answer holds the secret. An API
// key may do everything.
type ApiKey struct {
	ID       string      `json:"id"`
	Prefix   string      `doc:"The part of the key that is not secret."                                                                                                       json:"prefix"`
	Owner    *Owner      `doc:"The user recorded on the key; tags is always []. null for a key with no owner. The owner does not limit what the key may do."                  json:"owner"`
	State    ApiKeyState `json:"state"`
	Expiry   *time.Time  `doc:"When the key stops working; null for a key that never expires."                                                                                json:"expiry"`
	Created  *time.Time  `doc:"null for a key that does not record it."                                                                                                       json:"created"`
	LastSeen *time.Time  `doc:"When the key was last used, to the minute: a use within a minute of the last is not written. null for a key never used since it was recorded." json:"lastSeen"`
	Revoked  *time.Time  `doc:"When the key was revoked, or null."                                                                                                            json:"revoked"`
	Removal  *time.Time  `doc:"When the server removes the revoked record; null while it is kept: not revoked, or kept for ever."                                             json:"removal"`
}

// ApiKeyState is what a key can do now, as the server's clock says.
type ApiKeyState string

const (
	ApiKeyValid   ApiKeyState = "valid"
	ApiKeyExpired ApiKeyState = "expired"
	ApiKeyRevoked ApiKeyState = "revoked"
)

// Schema is registered once; see [stateSchema].
func (ApiKeyState) Schema(r huma.Registry) *huma.Schema {
	return stateSchema(r, "ApiKeyState", "revoked wins over expired. A client must accept a value it does not know.",
		string(ApiKeyValid), string(ApiKeyExpired), string(ApiKeyRevoked))
}

// CreatedApiKey is the answer to a create: the key and its secret.
type CreatedApiKey struct {
	ApiKey

	Key string `doc:"The secret. It is in this answer and no other; the server keeps only a hash of it." json:"key"`
}

// ApiKeyList is a page of API keys.
type ApiKeyList struct {
	ApiKeys       []ApiKey `json:"apiKeys"                                                                                nullable:"false"`
	NextPageToken string   `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

// CreateApiKeyBody is the body of POST /api-keys.
type CreateApiKeyBody struct {
	UserID Optional[string]    `doc:"The user recorded on the key as its owner. It does not limit what the key may do." json:"userId,omitzero" maxLength:"20"`
	Expiry Optional[time.Time] `doc:"When the key stops working, in the future. Required; there is no upper limit."     json:"expiry,omitzero" null:"absent"`
}

func (b *CreateApiKeyBody) problem() *Problem {
	switch {
	case !b.Expiry.Set:
		return newProblem(CodeExpiryRequired, "Send an expiry; a key has one.")
	case !b.Expiry.Value.After(time.Now()):
		return newProblem(CodeExpiryInPast, "The expiry must be in the future.")
	}

	return nil
}

func (b *CreateApiKeyBody) fieldErrors() []FieldError {
	var errs []FieldError

	if b.UserID.Set {
		_, err := pathID[types.UserID](b.UserID.Value)
		if err != nil {
			errs = append(errs, FieldError{Location: "body.userId", Message: notUserID})
		}
	}

	if b.Expiry.Set {
		_, err := types.ValidateExpiry(b.Expiry.Value)
		if err != nil {
			errs = append(errs, FieldError{Location: "body.expiry", Message: "is not a time between the years 0 and 9999"})
		}
	}

	return errs
}

// maxApiKeyBody bounds an API key body, which holds two short fields.
const maxApiKeyBody = 4 << 10

// tokenCannotCreateAPIKey keeps a token from escaping its scopes: an API
// key may do everything, so only an API key or the socket makes one.
var tokenCannotCreateAPIKey = tokenRule{
	name:       "token_cannot_create_api_key",
	why:        "An OAuth access token cannot make an API key, whatever its scopes: an API key may do everything. Use an API key or the unix socket.",
	everyToken: true,
}

type (
	listApiKeysInput struct {
		PageQuery

		User string `doc:"Only the keys owned by the user with this ID; an ID no user has matches no key." query:"user"`
	}

	apiKeyIDInput struct {
		ID string `doc:"The ID of the API key." path:"id"`
	}

	createApiKeyInput struct {
		Body CreateApiKeyBody
	}

	createdApiKeyOutput struct {
		Location string `header:"Location"`
		Body     CreatedApiKey
	}
)

var apiKeyNotFound = onError(db.ErrAPIKeyNotFound, CodeNotFound, "No API key has this ID.")

func registerApiKeys(api huma.API, b Backend) {
	tags := []string{"API keys"}

	register(api, huma.Operation{
		OperationID: "listApiKeys",
		Method:      http.MethodGet,
		Path:        Prefix + "/api-keys",
		Summary:     "List API keys",
		Description: "In ID order, expired and revoked keys too, until the server removes them. No answer holds a secret.",
		Tags:        tags,
	}, needs(scope.AllRead), nil, func(ctx context.Context, in *listApiKeysInput) (*struct{ Body ApiKeyList }, error) {
		var owner types.UserID

		if in.User != "" {
			id, err := pathID[types.UserID](in.User)
			if err != nil {
				p := newProblem(CodeInvalidField, "A query parameter is not valid.")
				p.Errors = []FieldError{{Location: "query.user", Message: notUserID}}

				return nil, p
			}

			owner = id
		}

		pg, err := openPage[uint64](in.PageQuery, "apiKeys", in.User)
		if err != nil {
			return nil, err
		}

		rows, err := b.State.ListAPIKeysPage(ctx, pg.after, pg.limit(), owner)
		if err != nil {
			return nil, err
		}

		rows, next := cutPage(pg, rows, func(c types.Credential) uint64 { return c.ID })

		now := time.Now()
		list := ApiKeyList{ApiKeys: make([]ApiKey, 0, len(rows)), NextPageToken: next}

		for i := range rows {
			list.ApiKeys = append(list.ApiKeys, apiKeyFromView(rows[i].View(), now, b.Cfg.Credentials.RevokedRetention))
		}

		return &struct{ Body ApiKeyList }{Body: list}, nil
	})

	register(api, huma.Operation{
		OperationID: "getApiKey",
		Method:      http.MethodGet,
		Path:        Prefix + "/api-keys/{id}",
		Summary:     "Read one API key",
		Description: "Without the secret. A revoked key is read until the server removes it.",
		Tags:        tags,
	}, needs(scope.AllRead), []answer{apiKeyNotFound}, func(_ context.Context, in *apiKeyIDInput) (*struct{ Body ApiKey }, error) {
		id, err := pathID[uint64](in.ID)
		if err != nil {
			return nil, err
		}

		c, err := b.State.GetAPIKeyCredential(id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "apiKey", ID: in.ID})
		}

		return &struct{ Body ApiKey }{Body: apiKeyFromView(c.View(), time.Now(), b.Cfg.Credentials.RevokedRetention)}, nil
	})

	register(api, huma.Operation{
		OperationID:   "createApiKey",
		Method:        http.MethodPost,
		Path:          Prefix + "/api-keys",
		Summary:       "Create an API key",
		Description:   "An API key may do everything, so only an API key or the unix socket can make one; an OAuth access token cannot, whatever its scopes. The answer holds the secret, in key; no other answer does.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxApiKeyBody,
	}, needs(scope.All).withTokenRules(&tokenCannotCreateAPIKey), []answer{
		{code: CodeExpiryRequired}, {code: CodeExpiryInPast},
	}, func(ctx context.Context, in *createApiKeyInput) (*createdApiKeyOutput, error) {
		body := in.Body

		k := db.NewAPIKey{
			Expiration: new(micro(body.Expiry.Value)),
			Created:    micro(time.Now()),
			Maker:      maker(ctx),
		}

		if body.UserID.Set {
			id, _ := pathID[types.UserID](body.UserID.Value) // checked in fieldErrors
			k.Owner = &id
		}

		stored, secret, err := b.State.CreateAPIKeyFrom(k)

		switch {
		case errors.Is(err, db.ErrUserNotFound):
			p := newProblem(CodeInvalidField, "A field is not valid.")
			p.Errors = []FieldError{{Location: "body.userId", Message: "no user has this ID"}}

			return nil, p
		case err != nil:
			return nil, err
		}

		key := apiKeyFromView(stored.View(), time.Now(), b.Cfg.Credentials.RevokedRetention)

		return &createdApiKeyOutput{
			Location: Prefix + "/api-keys/" + key.ID,
			Body:     CreatedApiKey{ApiKey: key, Key: secret},
		}, nil
	})

	register(api, huma.Operation{
		OperationID:   "deleteApiKey",
		Method:        http.MethodDelete,
		Path:          Prefix + "/api-keys/{id}",
		Summary:       "Revoke an API key",
		Description:   "The key is refused from its next request on; a key can revoke itself. Its record stays, revoked, until the server removes it (removal). Repeating the call answers 204 again and changes nothing.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, needs(scope.All), []answer{apiKeyNotFound}, func(_ context.Context, in *apiKeyIDInput) (*struct{}, error) {
		id, err := pathID[uint64](in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.RevokeAPIKey(id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "apiKey", ID: in.ID})
		}

		return nil, nil //nolint:nilnil // 204 has no body
	})
}

// apiKeyFromView is the API key c at now.
func apiKeyFromView(c types.CredentialView, now time.Time, retention time.Duration) ApiKey {
	k := ApiKey{
		ID:       strconv.FormatUint(c.ID(), 10),
		Prefix:   c.Identifier(),
		Expiry:   utcOrNil(c.Expiration()),
		Created:  utcOrNil(c.CreatedAt()),
		LastSeen: utcOrNil(c.LastSeen()),
		Revoked:  utcOrNil(c.Revoked()),
	}

	if c.User().Valid() {
		k.Owner = &Owner{User: ownerUser(c.User()), Tags: []string{}}
	}

	switch {
	case k.Revoked != nil:
		k.State = ApiKeyRevoked
	case k.Expiry != nil && !k.Expiry.After(now):
		k.State = ApiKeyExpired
	default:
		k.State = ApiKeyValid
	}

	k.Removal = removal(k.Revoked, retention, false)

	return k
}
