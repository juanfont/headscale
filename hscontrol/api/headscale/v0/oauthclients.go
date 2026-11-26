package apiv0

import (
	"context"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
)

// OAuthClient is an OAuth client, the same object in a list, a get and,
// with its secret, the answer to a create. No other answer holds the secret.
// Its scopes and tags are the most any token it mints can have.
type OAuthClient struct {
	ID          string           `doc:"The client ID; it is also the middle of the secret."                                                                    json:"id"`
	Description string           `doc:"Free text for people, such as what the client is for; \"\" for none."                                                   json:"description"`
	Scopes      []string         `doc:"The scopes the client may give its tokens."                                                                             json:"scopes"      nullable:"false"`
	Tags        []string         `doc:"The tags the client may give its tokens, and they to keys and nodes; not an owner."                                     json:"tags"        nullable:"false"`
	CreatedBy   *UserReference   `doc:"The user who owns the credential that made the client; null when it was a token or the socket, or the user is deleted." json:"createdBy"`
	Created     *time.Time       `doc:"null for a client that does not record it."                                                                             json:"created"`
	State       OAuthClientState `json:"state"`
	Revoked     *time.Time       `doc:"When the client was revoked, or null."                                                                                  json:"revoked"`
	Removal     *time.Time       `doc:"When the server removes the revoked record; null while it is kept: not revoked, or kept for ever."                      json:"removal"`
}

// OAuthClientState is whether a client can mint tokens, and its tokens work.
type OAuthClientState string

const (
	OAuthClientValid   OAuthClientState = "valid"
	OAuthClientRevoked OAuthClientState = "revoked"
)

// Schema is registered once; see [stateSchema].
func (OAuthClientState) Schema(r huma.Registry) *huma.Schema {
	return stateSchema(
		r,
		"OAuthClientState",
		"A client must accept a value it does not know.",
		string(OAuthClientValid),
		string(OAuthClientRevoked),
	)
}

// CreatedOAuthClient is the answer to a create: the client and its secret.
type CreatedOAuthClient struct {
	OAuthClient

	Key string `doc:"The client secret. It is in this answer and no other; the server keeps only a hash of it. Trade it for a token at POST /api/v2/oauth/token." json:"key"`
}

// OAuthClientList is a page of OAuth clients.
type OAuthClientList struct {
	OAuthClients  []OAuthClient `json:"oauthClients"                                                                           nullable:"false"`
	NextPageToken string        `doc:"Present when more rows can follow; send it back as pageToken. Missing on the last page." json:"nextPageToken,omitempty"`
}

// CreateOAuthClientBody is the body of POST /oauth-clients.
type CreateOAuthClientBody struct {
	Scopes      []string           `doc:"The scopes the client may give its tokens; at least one. devices:core and auth_keys need tags." json:"scopes"               maxItems:"64"  minItems:"1"     nullable:"false"`
	Tags        Optional[[]string] `doc:"The tags the client may give its tokens, each in tagOwners of the policy."                      json:"tags,omitzero"        maxItems:"256" nullable:"false"`
	Description Optional[string]   `doc:"Free text for people, such as what the client is for."                                          json:"description,omitzero" maxLength:"50"`
}

// TransformSchema lists the scopes in the document. A scope it does not
// list still passes the schema: the server answers invalid_scope with every
// unknown one, which says more than a refusal of the schema would.
func (*CreateOAuthClientBody) TransformSchema(
	r huma.Registry,
	s *huma.Schema,
) *huma.Schema {
	known := make([]any, 0, len(scope.Known()))
	for _, sc := range scope.Known() {
		known = append(known, string(sc))
	}

	listed := &huma.Schema{
		Type:        huma.TypeString,
		Enum:        known,
		Description: "A scope this release knows.",
	}
	listed.PrecomputeMessages()
	r.Map()["Scope"] = listed

	items := &huma.Schema{
		AnyOf: []*huma.Schema{
			{Ref: schemaRefPrefix + "Scope"},
			{Type: huma.TypeString},
		},
		Extensions: map[string]any{"x-go-type": "string"},
	}
	items.PrecomputeMessages()
	s.Properties["scopes"].Items = items

	return s
}

// problem is invalid_scope, then scope_requires_tags: what the body alone
// shows, so they come before a token rule.
func (b *CreateOAuthClientBody) problem() *Problem {
	var unknown, needTags []string

	for _, s := range slices.Compact(slices.Sorted(slices.Values(b.Scopes))) {
		switch {
		case !scope.Scope(s).Valid():
			unknown = append(unknown, s)
		case scope.RequiresTags([]scope.Scope{scope.Scope(s)}):
			needTags = append(needTags, s)
		}
	}

	if len(unknown) > 0 {
		p := newProblem(
			CodeInvalidScope,
			"Every scope must be one the server knows; details.scopes names the others.",
		)
		p.Details["scopes"] = unknown

		return p
	}

	if len(needTags) > 0 && len(b.Tags.Value) == 0 {
		p := newProblem(
			CodeScopeRequiresTags,
			"These scopes make tagged keys and nodes, so the client needs tags; details.scopes names them.",
		)
		p.Details["scopes"] = needTags

		return p
	}

	return nil
}

func (b *CreateOAuthClientBody) fieldErrors() []FieldError {
	if types.ValidateUserText(b.Description.Value) != nil {
		return []FieldError{
			{
				Location: "body.description",
				Message:  "has a control character or a bidirectional formatting character",
			},
		}
	}

	return nil
}

// maxOAuthClientBody bounds a client body: a tag list is the longest.
const maxOAuthClientBody = 64 << 10

// tokenMustHoldScopes keeps a token from making a client that mints tokens
// with more than it has: every scope of the client must be one the token's
// scopes grant.
var tokenMustHoldScopes = tokenRule{
	name: "token_must_hold_scopes",
	why:  "An OAuth access token can give a new OAuth client only scopes that its own scopes grant. GET /me lists them as authorization.scopes.",
	refuses: func(c *caller, in any) bool {
		o, ok := in.(*createOAuthClientInput)

		return ok &&
			slices.ContainsFunc(
				o.Body.Scopes,
				func(s string) bool { return !scope.Grants(c.scopes, scope.Scope(s)) },
			)
	},
}

type (
	listOAuthClientsInput struct {
		PageQuery
	}

	oauthClientIDInput struct {
		ID string `doc:"The client ID of the OAuth client." path:"id"`
	}

	createOAuthClientInput struct {
		Body CreateOAuthClientBody
	}

	createdOAuthClientOutput struct {
		Location string `header:"Location"`
		Body     CreatedOAuthClient
	}
)

var oauthClientNotFound = onError(
	db.ErrOAuthClientNotFound,
	CodeNotFound,
	"No OAuth client has this ID.",
)

func registerOAuthClients(api huma.API, b Backend) {
	tags := []string{"OAuth clients"}

	register(api, huma.Operation{
		OperationID: "listOAuthClients",
		Method:      http.MethodGet,
		Path:        Prefix + "/oauth-clients",
		Summary:     "List OAuth clients",
		Description: "In the order they were made, revoked clients too, until the server removes them. No answer holds a secret.",
		Tags:        tags,
	}, needs(scope.OAuthKeysRead), nil, func(ctx context.Context, in *listOAuthClientsInput) (*struct{ Body OAuthClientList }, error) {
		pg, err := openPage[uint64](in.PageQuery, "oauthClients")
		if err != nil {
			return nil, err
		}

		rows, err := b.State.ListOAuthClientsPage(ctx, pg.after, pg.limit())
		if err != nil {
			return nil, err
		}

		// The walk is by the row's ID, the order of creation; the client ID
		// is random.
		rows, next := cutPage(pg, rows, func(c types.Credential) uint64 { return c.ID })

		list := OAuthClientList{
			OAuthClients:  make([]OAuthClient, 0, len(rows)),
			NextPageToken: next,
		}
		for i := range rows {
			list.OAuthClients = append(
				list.OAuthClients,
				oauthClientFromView(rows[i].View(), b.Cfg.Credentials.RevokedRetention),
			)
		}

		return &struct{ Body OAuthClientList }{Body: list}, nil
	})

	register(api, huma.Operation{
		OperationID: "getOAuthClient",
		Method:      http.MethodGet,
		Path:        Prefix + "/oauth-clients/{id}",
		Summary:     "Read one OAuth client",
		Description: "Without the secret. A revoked client is read until the server removes it.",
		Tags:        tags,
	}, needs(scope.OAuthKeysRead), []answer{oauthClientNotFound}, func(ctx context.Context, in *oauthClientIDInput) (*struct{ Body OAuthClient }, error) {
		id, err := clientID(in.ID)
		if err != nil {
			return nil, err
		}

		c, err := b.State.GetOAuthClientCredentialContext(ctx, id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "oauthClient", ID: in.ID})
		}

		return &struct{ Body OAuthClient }{
			Body: oauthClientFromView(c.View(), b.Cfg.Credentials.RevokedRetention),
		}, nil
	})

	register(api, huma.Operation{
		OperationID:   "createOAuthClient",
		Method:        http.MethodPost,
		Path:          Prefix + "/oauth-clients",
		Summary:       "Create an OAuth client",
		Description:   "The answer holds the secret, in key; no other answer does. An OAuth access token gives the client only scopes its own scopes grant, and only tags it holds or that they own in the policy; a token with all and tags may make a client with all and no tags, as on Tailscale.",
		Tags:          tags,
		DefaultStatus: http.StatusCreated,
		MaxBodyBytes:  maxOAuthClientBody,
	}, needs(scope.OAuthKeys).withTokenRules(&tokenMustHoldScopes, &tokenMustOwnTags), []answer{
		{
			code: CodeInvalidScope,
		},
		{code: CodeScopeRequiresTags},
		{code: CodeTagsNotPermitted},
	}, func(ctx context.Context, in *createOAuthClientInput) (*createdOAuthClientOutput, error) {
		return b.createOAuthClient(ctx, in.Body)
	})

	register(api, huma.Operation{
		OperationID:   "deleteOAuthClient",
		Method:        http.MethodDelete,
		Path:          Prefix + "/oauth-clients/{id}",
		Summary:       "Revoke an OAuth client",
		Description:   "The client mints no token from now on, and every token it minted is refused from its next request on; a token can revoke its own client. The record stays, revoked, until the server removes it (removal). Repeating the call answers 204 again and changes nothing.",
		Tags:          tags,
		DefaultStatus: http.StatusNoContent,
	}, needs(scope.OAuthKeys), []answer{oauthClientNotFound}, func(_ context.Context, in *oauthClientIDInput) (*struct{}, error) {
		id, err := clientID(in.ID)
		if err != nil {
			return nil, err
		}

		err = b.State.RevokeOAuthClient(id)
		if err != nil {
			return nil, about(err, ProblemObject{Kind: "oauthClient", ID: in.ID})
		}

		return nil, nil //nolint:nilnil // 204 has no body
	})
}

// clientIDLength is the length of a client ID, which the server makes as
// lowercase hex.
const clientIDLength = 12

// clientID reads the ID of an OAuth client in a path. Only the form the
// server makes names a client; anything else is not_found with no object,
// which would copy the request back.
func clientID(s string) (string, error) {
	if len(s) != clientIDLength || strings.Trim(s, "0123456789abcdef") != "" {
		return "", newProblem(
			CodeNotFound,
			"Nothing has this ID. A path takes the client ID.",
		)
	}

	return s, nil
}

// createOAuthClient makes the client of a body that is right in itself
// ([CreateOAuthClientBody.problem]), with the checks that read the policy
// under the lock of every policy write, so the client is made under the
// policy that allowed it.
func (b Backend) createOAuthClient(
	ctx context.Context,
	body CreateOAuthClientBody,
) (*createdOAuthClientOutput, error) {
	scopes := slices.Compact(slices.Sorted(slices.Values(body.Scopes)))
	want := slices.Compact(slices.Sorted(slices.Values(body.Tags.Value)))

	c := db.NewOAuthClient{
		Scopes:      scopes,
		Tags:        want,
		Description: body.Description.Value,
		Created:     micro(time.Now()),
		Maker:       maker(ctx),
	}

	if cr := callerFrom(ctx); cr.credential != nil && cr.credential.owner != nil {
		c.CreatedBy = new(types.UserID(*cr.credential.owner))
	}

	stored, secret, err := b.State.CreateOAuthClientIf(
		c,
		func(pol state.TagPolicy) error {
			p := b.tokenMayGive(ctx, pol, want)
			if p != nil {
				return p
			}

			p = tagsNotPermitted(pol, want)
			if p != nil {
				return p
			}

			return nil
		},
	)
	if err != nil {
		return nil, err
	}

	client := oauthClientFromView(stored.View(), b.Cfg.Credentials.RevokedRetention)

	return &createdOAuthClientOutput{
		Location: Prefix + "/oauth-clients/" + client.ID,
		Body:     CreatedOAuthClient{OAuthClient: client, Key: secret},
	}, nil
}

// oauthClientFromView is the OAuth client c.
func oauthClientFromView(c types.CredentialView, retention time.Duration) OAuthClient {
	o := OAuthClient{
		ID:          c.Identifier(),
		Description: c.Description(),
		Scopes:      c.Scopes().AsSlice(),
		Tags:        c.Tags().AsSlice(),
		Created:     utcOrNil(c.CreatedAt()),
		State:       OAuthClientValid,
		Revoked:     utcOrNil(c.Revoked()),
	}

	if o.Scopes == nil {
		o.Scopes = []string{}
	}

	if o.Tags == nil {
		o.Tags = []string{}
	}

	// The user column of a client records who made it; it has no owner.
	if u := c.User(); u.Valid() {
		o.CreatedBy = &UserReference{
			ID:        strconv.FormatUint(uint64(u.ID()), 10),
			LoginName: u.Username(),
		}
	}

	if o.Revoked != nil {
		o.State = OAuthClientRevoked
	}

	o.Removal = removal(o.Revoked, retention, false)

	return o
}
