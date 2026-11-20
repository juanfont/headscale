package apiv0

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	tsset "tailscale.com/util/set"
)

// AuthKey is an auth key, the same object in a list, a get and, with its
// secret, the answer to a create. No other answer holds the secret.
type AuthKey struct {
	ID          string         `json:"id"`
	Prefix      string         `doc:"The part of the key that is not secret."                                                                                                                  json:"prefix"`
	Description string         `doc:"Free text for people, such as what the key is for; \"\" for none."                                                                                        json:"description"`
	Owner       *Owner         `doc:"The user, or the tags, that a node joining with the key gets; for a tagged key user is null."                                                             json:"owner"`
	CreatedBy   *UserReference `doc:"The user who owns the credential that made the key; null for a key older than this field, made over the socket, or whose user is deleted. Not the owner." json:"createdBy"`
	State       AuthKeyState   `json:"state"`
	Used        bool           `doc:"A node has joined with the key."                                                                                                                          json:"used"`
	Reusable    bool           `json:"reusable"`
	Ephemeral   bool           `doc:"A node that joins with the key is removed some time after it disconnects."                                                                                json:"ephemeral"`
	Expiry      *time.Time     `doc:"When the key stops working; null for a key that never expires."                                                                                           json:"expiry"`
	Created     *time.Time     `doc:"null for a key that does not record it."                                                                                                                  json:"created"`
	Revoked     *time.Time     `doc:"When the key was revoked, or null."                                                                                                                       json:"revoked"`
	Removal     *time.Time     `doc:"When the server removes the revoked record; null while it is kept: not revoked, kept for ever, or a node still refers to the key."                        json:"removal"`
}

// AuthKeyState is what a key can do now, as the server's clock says.
type AuthKeyState string

const (
	AuthKeyValid   AuthKeyState = "valid"
	AuthKeyUsed    AuthKeyState = "used"
	AuthKeyExpired AuthKeyState = "expired"
	AuthKeyRevoked AuthKeyState = "revoked"
)

// Schema is registered once and referred to, so a client has one type for
// it, not one for each object that holds it.
func (AuthKeyState) Schema(r huma.Registry) *huma.Schema {
	return stateSchema(r, "AuthKeyState",
		"revoked wins over used, which wins over expired; used is a single-use key that a node took. A client must accept a value it does not know.",
		string(AuthKeyValid), string(AuthKeyUsed), string(AuthKeyExpired), string(AuthKeyRevoked))
}

// CreatedAuthKey is the answer to a create: the key and its secret.
type CreatedAuthKey struct {
	AuthKey

	Key string `doc:"The secret. It is in this answer and no other; the server keeps only a hash of it." json:"key"`
}

// AuthKeyList is a page of auth keys.
type AuthKeyList struct {
	AuthKeys      []AuthKey `json:"authKeys"                                                                               nullable:"false"`
	NextPageToken string    `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

// CreateAuthKeyBody is the body of POST /auth-keys.
type CreateAuthKeyBody struct {
	UserID      Optional[string]    `doc:"The user who owns the nodes that join with the key. Exactly one of userId and tags."                            json:"userId,omitzero"      maxLength:"20"`
	Tags        Optional[[]string]  `doc:"The tags of the nodes that join with the key, each in tagOwners of the policy. Exactly one of userId and tags." json:"tags,omitzero"        maxItems:"256" nullable:"false"`
	Expiry      Optional[time.Time] `doc:"When the key stops working, in the future. Required; there is no upper limit."                                  json:"expiry,omitzero"      null:"absent"`
	Reusable    Optional[bool]      `doc:"More than one node may join with the key."                                                                      json:"reusable,omitzero"`
	Ephemeral   Optional[bool]      `doc:"A node that joins with the key is removed some time after it disconnects."                                      json:"ephemeral,omitzero"`
	Description Optional[string]    `doc:"Free text for people, such as what the key is for."                                                             json:"description,omitzero" maxLength:"50"`
}

func (b *CreateAuthKeyBody) problem() *Problem {
	switch {
	case b.UserID.Set && b.Tags.Set:
		return newProblem(CodeOwnerConflict, "Send userId or tags, not both.")
	case !b.UserID.Set && !b.Tags.Set:
		return newProblem(CodeOwnerConflict, "Send userId, or at least one tag.")
	case b.Tags.Set && len(b.Tags.Value) == 0:
		return newProblem(CodeTagsRequired, "A key for tags needs at least one tag.")
	case !b.Expiry.Set:
		return newProblem(CodeExpiryRequired, "Send an expiry; a key has one.")
	case !b.Expiry.Value.After(time.Now()):
		return newProblem(CodeExpiryInPast, "The expiry must be in the future.")
	}

	return nil
}

func (b *CreateAuthKeyBody) fieldErrors() []FieldError {
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

	if types.ValidateUserText(b.Description.Value) != nil {
		errs = append(errs, FieldError{Location: "body.description", Message: "has a control character or a bidirectional formatting character"})
	}

	return errs
}

// maxAuthKeyBody bounds a key body: a tag list is the longest.
const maxAuthKeyBody = 64 << 10

// tokenCannotCreateKeyForUser keeps a token from minting a way into a
// person's tailnet: a key for a user makes nodes that user owns. A token
// stands for a client, never for a person.
var tokenCannotCreateKeyForUser = tokenRule{
	name: "token_cannot_create_key_for_user",
	why:  "An OAuth access token can make an auth key for tags only, never for a user (userId). Use an API key.",
	refuses: func(_ *caller, in any) bool {
		k, ok := in.(*createAuthKeyInput)

		return ok && k.Body.UserID.Set
	},
}

type (
	listAuthKeysInput struct {
		PageQuery

		User string `doc:"Only the keys owned by the user with this ID; tagged keys never match, and an ID no user has matches no key. With tag, a key must match both." query:"user"`
		Tag  string `doc:"Only the keys with this tag. With user, a key must match both."                                                                                query:"tag"`
	}

	authKeyIDInput struct {
		ID string `doc:"The ID of the auth key." path:"id"`
	}

	createAuthKeyInput struct {
		Body CreateAuthKeyBody
	}

	createdAuthKeyOutput struct {
		Location string `header:"Location"`
		Body     CreatedAuthKey
	}
)

var authKeyNotFound = onError(db.ErrPreAuthKeyNotFound, CodeNotFound, "No auth key has this ID.")

func registerAuthKeys(api huma.API, b Backend) {
	tags := []string{"Auth keys"}

	register(api, huma.Operation{
		OperationID: "listAuthKeys",
		Method:      http.MethodGet,
		Path:        Prefix + "/auth-keys",
		Summary:     "List auth keys",
		Description: "In ID order, revoked keys too, until the server removes them. No answer holds a secret.",
		Tags:        tags,
	}, needs(scope.AuthKeysRead), nil, func(ctx context.Context, in *listAuthKeysInput) (*struct{ Body AuthKeyList }, error) {
		f := db.PreAuthKeyFilter{Tag: in.Tag}

		if in.User != "" {
			id, err := pathID[types.UserID](in.User)
			if err != nil {
				p := newProblem(CodeInvalidField, "A query parameter is not valid.")
				p.Errors = []FieldError{{Location: "query.user", Message: notUserID}}

				return nil, p
			}

			f.User = id
		}

		pg, err := openPage[uint64](in.PageQuery, "authKeys", in.User, in.Tag)
		if err != nil {
			return nil, err
		}

		rows, refs, err := b.State.ListAuthKeysPage(ctx, pg.after, pg.limit(), f)
		if err != nil {
			return nil, err
		}

		rows, next := cutPage(pg, rows, func(k types.PreAuthKey) uint64 { return k.ID })

		keys, err := b.authKeys(rows, refs)
		if err != nil {
			return nil, err
		}

		return &struct{ Body AuthKeyList }{Body: AuthKeyList{AuthKeys: keys, NextPageToken: next}}, nil
	})

	register(api, huma.Operation{
		OperationID: "getAuthKey",
		Method:      http.MethodGet,
		Path:        Prefix + "/auth-keys/{id}",
		Summary:     "Read one auth key",
		Description: "Without the secret. A revoked key is read until the server removes it.",
		Tags:        tags,
	}, needs(scope.AuthKeysRead), []answer{authKeyNotFound}, func(_ context.Context, in *authKeyIDInput) (*struct{ Body AuthKey }, error) {
		id, err := pathID[uint64](in.ID)
		if err != nil {
			return nil, err
		}

		k, referenced, err := b.State.GetAuthKey(id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "authKey", ID: in.ID})
		}

		refs := tsset.Set[uint64]{}
		if referenced {
			refs.Add(id)
		}

		keys, err := b.authKeys([]types.PreAuthKey{*k}, refs)
		if err != nil {
			return nil, err
		}

		return &struct{ Body AuthKey }{Body: keys[0]}, nil
	})

	register(api, huma.Operation{
		OperationID:   "createAuthKey",
		Method:        http.MethodPost,
		Path:          Prefix + "/auth-keys",
		Summary:       "Create an auth key",
		Description:   "For one user or for tags. The answer holds the secret, in key; no other answer does. An OAuth access token makes keys for tags only, and only for tags it holds or that they own in the policy.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxAuthKeyBody,
	}, needs(scope.AuthKeys).withTokenRules(&tokenCannotCreateKeyForUser, &tokenMustOwnTags), []answer{
		{code: CodeOwnerConflict}, {code: CodeTagsRequired}, {code: CodeExpiryRequired}, {code: CodeExpiryInPast}, {code: CodeTagsNotPermitted},
	}, func(ctx context.Context, in *createAuthKeyInput) (*createdAuthKeyOutput, error) {
		return b.createAuthKey(ctx, in.Body)
	})

	register(api, huma.Operation{
		OperationID:   "deleteAuthKey",
		Method:        http.MethodDelete,
		Path:          Prefix + "/auth-keys/{id}",
		Summary:       "Revoke an auth key",
		Description:   "The key stops working at once; nodes that joined with it stay. Its record stays, revoked, until the server removes it (removal). Repeating the call answers 204 again and changes nothing.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, needs(scope.AuthKeys), []answer{authKeyNotFound}, func(_ context.Context, in *authKeyIDInput) (*struct{}, error) {
		id, err := pathID[uint64](in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.RevokePreAuthKey(id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "authKey", ID: in.ID})
		}

		return nil, nil //nolint:nilnil // 204 has no body
	})
}

// createAuthKey makes the key of a body that is right in itself
// ([CreateAuthKeyBody.problem]), with the checks that read the policy and the user under the lock of
// every policy write, so the key is made under the policy that allowed it.
func (b Backend) createAuthKey(ctx context.Context, body CreateAuthKeyBody) (*createdAuthKeyOutput, error) {
	c := callerFrom(ctx)
	token := isToken(ctx)
	want := slices.Compact(slices.Sorted(slices.Values(body.Tags.Value)))

	k := db.NewPreAuthKey{
		Tags:        want,
		Reusable:    body.Reusable.Value,
		Ephemeral:   body.Ephemeral.Value,
		Expiration:  new(micro(body.Expiry.Value)),
		Description: body.Description.Value,
		ByToken:     token,
		Created:     micro(time.Now()),
		Maker:       maker(ctx),
	}

	if c.credential != nil && c.credential.owner != nil {
		k.CreatedBy = new(types.UserID(*c.credential.owner))
	}

	if body.UserID.Set {
		id, _ := pathID[types.UserID](body.UserID.Value) // checked in fieldErrors
		k.User = &id
	}

	stored, made, err := b.State.CreateAuthKeyIf(k, func(pol state.TagPolicy) error {
		p := b.tokenMayGive(ctx, pol, want)
		if p != nil {
			return p
		}

		p = tagsNotPermitted(pol, want)
		if p != nil {
			return p
		}

		return nil
	})

	switch {
	case errors.Is(err, db.ErrUserNotFound):
		p := newProblem(CodeInvalidField, "A field is not valid.")
		p.Errors = []FieldError{{Location: "body.userId", Message: "no user has this ID"}}

		return nil, p
	case err != nil:
		return nil, err
	}

	keys, err := b.authKeys([]types.PreAuthKey{*stored}, nil)
	if err != nil {
		return nil, err
	}

	return &createdAuthKeyOutput{
		Location: Prefix + "/auth-keys/" + keys[0].ID,
		Body:     CreatedAuthKey{Key: made.Key, AuthKey: keys[0]},
	}, nil
}

// authKeys is ks as the API shows them; refs are the IDs a node refers to.
// The creators a page names are read in one query.
func (b Backend) authKeys(ks []types.PreAuthKey, refs tsset.Set[uint64]) ([]AuthKey, error) {
	var ids []types.UserID

	for i := range ks {
		if id, ok := keyCreator(&ks[i]); ok {
			ids = append(ids, id)
		}
	}

	slices.Sort(ids)

	users, err := b.State.GetUsersByIDs(slices.Compact(ids))
	if err != nil {
		return nil, err
	}

	now := time.Now()
	out := make([]AuthKey, 0, len(ks))

	for i := range ks {
		k := ks[i].View()
		a := authKeyFromView(k, refs.Contains(k.ID()), now, b.Cfg.Credentials.RevokedRetention)

		if id, ok := keyCreator(&ks[i]); ok {
			if u, ok := users[id]; ok {
				a.CreatedBy = &UserReference{ID: strconv.FormatUint(uint64(id), 10), LoginName: u.Username()}
			}
		}

		out = append(out, a)
	}

	return out, nil
}

// keyCreator is who made k, when it records it. Older code put the maker of
// a tagged key in the owner's column, or the user a request named, so that
// column says nothing of who made it.
func keyCreator(k *types.PreAuthKey) (types.UserID, bool) {
	if k.CreatedByUserID == nil {
		return 0, false
	}

	return types.UserID(*k.CreatedByUserID), true
}

// authKeyFromView is k's own fields at now. referenced is whether a node
// refers to k, which keeps a revoked record and marks a reusable key used.
func authKeyFromView(k types.PreAuthKeyView, referenced bool, now time.Time, retention time.Duration) AuthKey {
	a := AuthKey{
		ID:          strconv.FormatUint(k.ID(), 10),
		Prefix:      k.Prefix(),
		Description: k.Description(),
		Used:        k.Used() || referenced,
		Reusable:    k.Reusable(),
		Ephemeral:   k.Ephemeral(),
		Expiry:      utcOrNil(k.Expiration()),
		Created:     utcOrNil(k.CreatedAt()),
		Revoked:     utcOrNil(k.Revoked()),
	}

	switch {
	case k.Tags().Len() > 0:
		a.Owner = &Owner{Tags: k.Tags().AsSlice()}
	case k.User().Valid():
		a.Owner = &Owner{User: ownerUser(k.User()), Tags: []string{}}
	}

	switch {
	case a.Revoked != nil:
		a.State = AuthKeyRevoked
	case k.Used() && !k.Reusable():
		a.State = AuthKeyUsed
	case a.Expiry != nil && !a.Expiry.After(now):
		a.State = AuthKeyExpired
	default:
		a.State = AuthKeyValid
	}

	a.Removal = removal(a.Revoked, retention, referenced)

	return a
}

// utcOrNil is the time p holds in UTC, or nil.
func utcOrNil(p interface{ GetOk() (time.Time, bool) }) *time.Time {
	t, ok := p.GetOk()
	if !ok {
		return nil
	}

	return new(micro(t))
}
