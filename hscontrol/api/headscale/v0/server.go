package apiv0

import (
	"context"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
)

// Me answers GET /me: who makes the request, how it is authenticated and
// what it may do.
type Me struct {
	Principal     Principal     `json:"principal"`
	Credential    *Credential   `json:"credential"`
	Authorization Authorization `json:"authorization"`
}

type Principal struct {
	Kind     PrincipalKind  `doc:"Who or what is authenticated. human and workload are reserved."      enum:"apiKey,oauthClient,local,human,workload" json:"kind"`
	Identity *Identity      `doc:"The identity at an outside identity provider. Reserved: null today." json:"identity"`
	User     *UserReference `doc:"The Headscale user that has identity. Reserved: null today."         json:"user"`
}

type Identity struct {
	_       struct{} `nullable:"true"`
	Issuer  string   `json:"issuer"`
	Subject string   `json:"subject"`
}

// UserReference names a user by ID and loginName: a stored name can be empty.
type UserReference struct {
	_         struct{} `nullable:"true"`
	ID        string   `json:"id"`
	LoginName string   `json:"loginName"`
}

// Credential is how a request was authenticated; null for the unix socket.
type Credential struct {
	_      struct{}         `nullable:"true"`
	Kind   CredentialKind   `enum:"apiKey,oauthToken"                                                              json:"kind"`
	ID     string           `doc:"The ID of the stored credential; for an API key, the ID in /api-keys/{id}."      json:"id"`
	Prefix string           `doc:"The part of the secret that is not secret."                                      json:"prefix"`
	Expiry *time.Time       `json:"expiry"`
	Owner  *Owner           `doc:"For an API key, the user recorded on it. It does not say who makes the request." json:"owner"`
	Client *ClientReference `doc:"For a token, the OAuth client it was issued to."                                 json:"client"`
}

// Owner is who a resource belongs to: one user, or tags, never both.
type Owner struct {
	_    struct{}   `nullable:"true"`
	User *OwnerUser `json:"user"`
	Tags []string   `json:"tags"     nullable:"false"`
}

type OwnerUser struct {
	_           struct{} `nullable:"true"`
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	LoginName   string   `json:"loginName"`
	DisplayName string   `json:"displayName"`
	Email       string   `json:"email"`
}

type ClientReference struct {
	_           struct{} `nullable:"true"`
	ID          string   `json:"id"`
	Description string   `json:"description"`
}

type Authorization struct {
	Scopes    []string  `doc:"The scopes the request has. An API key and the unix socket have all."                                         json:"scopes"  nullable:"false"`
	Tags      []string  `doc:"The tags the caller may give, with those they own in the policy. null: tags do not limit the caller."         json:"tags"    nullable:"true"`
	Resources Resources `doc:"The resources the scopes apply to. own is reserved; a client that does not know a value must act as limited." enum:"all,own" json:"resources"`
}

// Health answers GET /health when the server is healthy.
type Health struct {
	Healthy              bool      `json:"healthy"`
	DatabaseConnectivity bool      `json:"databaseConnectivity"`
	Warnings             []Message `doc:"What an admin should know; a warning never makes the server unhealthy. New codes may appear." json:"warnings" nullable:"false"`
}

// nodeWarnings is the sentence of each node check, after the node count.
var nodeWarnings = map[string]string{
	"node_name_invalid":   "a name that is not valid",
	"node_expiry_invalid": "a key expiry that is not valid",
}

// nodeWarning is the message of one failing node check. It names no node:
// any credential reads /health, and not every credential may read nodes. The
// node object says which checks it fails.
func nodeWarning(p state.NodeHealthProblem) string {
	noun := "nodes have"
	if len(p.Nodes) == 1 {
		noun = "node has"
	}

	return fmt.Sprintf("%d %s %s.", len(p.Nodes), noun, nodeWarnings[p.Code])
}

func registerServer(api huma.API, b Backend) {
	register(api, huma.Operation{
		OperationID: "getVersion",
		Method:      http.MethodGet,
		Path:        Prefix + "/version",
		Summary:     "The version of the server",
		Tags:        []string{"Server"},
	}, public, nil, func(context.Context, *struct{}) (*struct{ Body *types.VersionInfo }, error) {
		return &struct{ Body *types.VersionInfo }{Body: types.GetVersionInfo()}, nil
	})

	register(api, huma.Operation{
		OperationID: "getMe",
		Method:      http.MethodGet,
		Path:        Prefix + "/me",
		Summary:     "Who makes this request, how it is authenticated, and what it may do",
		Tags:        []string{"Server"},
	}, anyCredential, nil, func(ctx context.Context, _ *struct{}) (*struct{ Body Me }, error) {
		me, err := whoAmI(b, callerFrom(ctx))
		if err != nil {
			return nil, err
		}

		return &struct{ Body Me }{Body: me}, nil
	})

	register(api, huma.Operation{
		OperationID: "getHealth",
		Method:      http.MethodGet,
		Path:        Prefix + "/health",
		Summary:     "The health of the server",
		Tags:        []string{"Server"},
	}, anyCredential, []answer{{code: CodeUnhealthy}}, func(ctx context.Context, _ *struct{}) (*struct{ Body Health }, error) {
		err := b.State.PingDB(ctx)
		if err != nil {
			log.Error().Err(err).Str(zf.RequestID, middleware.GetReqID(ctx)).Msg("api v0: database ping")

			return nil, databaseUnreachable()
		}

		return &struct{ Body Health }{Body: Health{
			Healthy:              true,
			DatabaseConnectivity: true,
			Warnings:             healthWarnings(b),
		}}, nil
	})
}

func whoAmI(b Backend, c *caller) (Me, error) {
	scopes := make([]string, len(c.scopes))
	for i, s := range c.scopes {
		scopes[i] = string(s)
	}

	me := Me{
		Principal:     Principal{Kind: c.principal.kind, Identity: c.principal.identity, User: c.principal.user},
		Authorization: Authorization{Scopes: scopes, Resources: c.resources},
	}

	if c.tags != nil {
		me.Authorization.Tags = b.State.TagsOwnedByTags(c.tags)
		if me.Authorization.Tags == nil {
			me.Authorization.Tags = []string{}
		}
	}

	cred := c.credential
	if cred == nil {
		return me, nil
	}

	me.Credential = &Credential{
		Kind:   cred.kind,
		ID:     strconv.FormatUint(cred.id, 10),
		Prefix: cred.prefix,
	}

	if cred.expiry != nil {
		me.Credential.Expiry = new(micro(*cred.expiry))
	}

	if cred.owner != nil {
		u, err := b.State.GetUserByID(types.UserID(*cred.owner))
		if err != nil {
			return Me{}, fmt.Errorf("reading the owner of API key %d: %w", cred.id, err)
		}

		uv := u.View()
		me.Credential.Owner = &Owner{User: ownerUser(uv), Tags: []string{}}
	}

	if cred.clientID != "" {
		client, err := b.State.GetOAuthClientByClientID(cred.clientID)
		if err != nil {
			return Me{}, fmt.Errorf("reading the client of token %d: %w", cred.id, err)
		}

		me.Credential.Client = &ClientReference{ID: client.ClientID, Description: client.Description}
	}

	return me, nil
}

// healthWarnings is one warning per failing node check. The scan reads the
// NodeStore snapshot in memory, so it is cheap enough for every call.
func healthWarnings(b Backend) []Message {
	problems := b.State.NodeHealthProblems()
	warnings := make([]Message, 0, len(problems))

	for _, p := range problems {
		warnings = append(warnings, Message{
			Code:    HealthCode(p.Code),
			Message: nodeWarning(p),
			Details: map[string]any{"count": len(p.Nodes)},
		})
	}

	return warnings
}

// databaseUnreachable is the answer of every call while the database fails.
func databaseUnreachable() *Problem {
	return unhealthy("The server cannot reach its database.", ReasonDatabaseUnreachable)
}

// credentialCheckBusy is the answer while legacy hash checks are all busy:
// the credential was not checked, so it is neither good nor bad.
func credentialCheckBusy() *Problem {
	return unhealthy("The server is too busy to check the credential; try again.", ReasonCredentialCheckBusy)
}

func unhealthy(detail string, reason HealthCode) *Problem {
	p := newProblem(CodeUnhealthy, detail)
	p.Details["reasons"] = []Message{{Code: reason, Message: healthReasons[reason], Details: map[string]any{}}}

	return p
}
