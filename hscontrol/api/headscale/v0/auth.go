package apiv0

import (
	"context"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

// PrincipalKind is who or what is authenticated in a request.
type PrincipalKind string

const (
	PrincipalAPIKey      PrincipalKind = "apiKey"
	PrincipalOAuthClient PrincipalKind = "oauthClient"
	PrincipalLocal       PrincipalKind = "local"
)

// CredentialKind is how a request was authenticated.
type CredentialKind string

const (
	CredentialAPIKey     CredentialKind = "apiKey"
	CredentialOAuthToken CredentialKind = "oauthToken"
)

// Resources is what the scopes of a caller apply to.
type Resources string

const ResourcesAll Resources = "all"

// caller is the one value the auth middleware puts in a request's context.
// Handlers read it; GET /me prints it.
type caller struct {
	principal principal
	// credential is nil for the socket.
	credential *credential
	scopes     []scope.Scope
	// tags a token holds; nil means tags do not limit the caller.
	tags      []string
	resources Resources
}

type principal struct {
	kind PrincipalKind
	// identity is the issuer and subject of the caller at an identity
	// provider outside Headscale.
	// TODO(kradalby): set it with the logins of people and workloads
	// (#3303, #3585); no caller has one today.
	identity *Identity
	// user is the Headscale user that has identity.
	// TODO(kradalby): set it with the logins of people and workloads
	// (#3303, #3585); no caller has one today.
	user *UserReference
}

type credential struct {
	kind   CredentialKind
	id     uint64
	prefix string
	expiry *time.Time
	// owner is the user recorded on an API key.
	owner *uint
	// clientID is the OAuth client a token was issued to.
	clientID string
}

// allAccess is the rule for an API key and the socket: every scope, no tag
// limit, every resource. Neither has stored scopes.
func allAccess(p principal, c *credential) *caller {
	return &caller{
		principal:  p,
		credential: c,
		scopes:     []scope.Scope{scope.All},
		resources:  ResourcesAll,
	}
}

type contextKey int

const (
	localTrustKey contextKey = iota
	callerKey
	queryErrorsKey
)

// WithLocalTrust marks requests as coming over the unix socket, whose access
// is the credential.
func WithLocalTrust(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		next.ServeHTTP(
			w,
			r.WithContext(context.WithValue(r.Context(), localTrustKey, struct{}{})),
		)
	})
}

// callerFrom returns the caller of an authenticated operation.
func callerFrom(ctx context.Context) *caller {
	c, _ := ctx.Value(callerKey).(*caller)

	return c
}

// authMiddleware authenticates the Bearer credential, checks the scopes the
// operation needs and puts the caller in the context. An operation that
// declares no access is refused for every caller, the socket too.
func authMiddleware(b Backend) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		a, _ := ctx.Operation().Metadata[accessMetaKey].(access)
		if a.kind() == undeclared {
			log.Error().Str(zf.RequestID, middleware.GetReqID(ctx.Context())).
				Str("operation", ctx.Operation().OperationID).
				Msg("api v0: operation declares no access")
			writeHumaProblem(ctx, newProblem(CodeInternal, ""))

			return
		}

		if ctx.Context().Value(localTrustKey) != nil {
			next(
				huma.WithValue(
					ctx,
					callerKey,
					allAccess(principal{kind: PrincipalLocal}, nil),
				),
			)

			return
		}

		if a.kind() == publicAccess {
			next(ctx)

			return
		}

		c, p := authenticate(ctx.Context(), b, ctx.Header("Authorization"))
		if p != nil {
			writeHumaProblem(ctx, p)

			return
		}

		p = everyTokenRefusal(c, a)
		if p != nil {
			writeHumaProblem(ctx, p)

			return
		}

		var missing []string

		u := ctx.URL()
		for _, want := range a.wants(u.Query()) {
			if !scope.Grants(c.scopes, want) {
				missing = append(missing, string(want))
			}
		}

		if len(missing) > 0 {
			writeHumaProblem(ctx, forbidden(missing))

			return
		}

		next(huma.WithValue(ctx, callerKey, c))
	}
}

// tokenRule refuses an OAuth access token a call that its scopes allow. An
// operation states its rules with [access.withTokenRules]; they run once
// the body is right in itself, and before the handler. An API key and the socket may do
// everything, so no rule holds them.
type tokenRule struct {
	// name is stable: details.rule of forbidden, and a heading of the page
	// of codes.
	name string
	// why is the detail of the problem and the text on the page.
	why string
	// refuses reports whether the rule refuses the caller c the input of
	// the call. A rule that reads the resource or the policy leaves it nil,
	// and its handler checks it there.
	refuses func(c *caller, in any) bool
	// everyToken refuses every token, before its scopes are read: no scope
	// is enough, so a lacking scope would send the client the wrong way.
	everyToken bool
}

// tokenRules is every rule. The page of codes lists them, and register
// refuses a rule that is not here.
var tokenRules = []*tokenRule{
	&tokenCannotChangeUserNameOrEmail, &tokenMustOwnTags, &tokenCannotCreateKeyForUser,
	&tokenCannotCreateAPIKey, &tokenMustHoldScopes,
}

// ruleRefusal is the problem of the first rule of a that refuses in, when
// the caller is an OAuth access token.
func ruleRefusal(ctx context.Context, a access, in any) *Problem {
	c := callerFrom(ctx)
	if c == nil || c.credential == nil || c.credential.kind != CredentialOAuthToken {
		return nil
	}

	for _, r := range a.rules {
		if r.refuses != nil && r.refuses(c, in) {
			return ruleForbidden(r)
		}
	}

	return nil
}

// everyTokenRefusal is the problem of a rule of a that refuses every token,
// when c is one.
func everyTokenRefusal(c *caller, a access) *Problem {
	if c.credential == nil || c.credential.kind != CredentialOAuthToken {
		return nil
	}

	for _, r := range a.rules {
		if r.everyToken {
			return ruleForbidden(r)
		}
	}

	return nil
}

// refused are the errors of a credential that is not valid, which need no
// log line.
var refused = []error{
	gorm.ErrRecordNotFound,
	db.ErrAPIKeyFailedToParse,
	db.ErrAPIKeyExpired,
	db.ErrAPIKeyRevoked,
	db.ErrAccessTokenFailedToParse,
	db.ErrAccessTokenExpired,
	db.ErrAccessTokenClientRevoked,
}

// authenticate reads an API key or an OAuth access token, told apart by
// prefix so a token is never taken for an all-access key. The db layer says
// which errors left the credential unchecked: a failing store is
// unhealthy, as GET /health says it, and so is a busy legacy hash check.
// Every other error is unauthorized; one that is not a plain refusal, such
// as a stored hash that cannot be read, is logged for the admin.
func authenticate(ctx context.Context, b Backend, header string) (*caller, *Problem) {
	scheme, token, _ := strings.Cut(header, " ")
	// RFC 6750 puts 1*SP after the scheme.
	token = strings.TrimLeft(token, " ")
	if !strings.EqualFold(scheme, "Bearer") || token == "" {
		return nil, unauthorized()
	}

	if strings.HasPrefix(token, types.AccessTokenPrefix) {
		at, err := b.State.AuthenticateAccessTokenContext(ctx, token)
		if err != nil {
			return nil, credentialProblem(ctx, err)
		}

		tags := at.Tags
		if tags == nil {
			tags = []string{}
		}

		return &caller{
			principal: principal{kind: PrincipalOAuthClient},
			credential: &credential{
				kind:     CredentialOAuthToken,
				id:       at.ID,
				prefix:   at.Prefix,
				expiry:   at.Expiration,
				clientID: at.ClientID,
			},
			scopes:    scope.Parse(at.Scopes),
			tags:      tags,
			resources: ResourcesAll,
		}, nil
	}

	key, err := b.State.AuthenticateAPIKeyContext(ctx, token)
	if err != nil {
		return nil, credentialProblem(ctx, err)
	}

	return allAccess(principal{kind: PrincipalAPIKey}, &credential{
		kind:   CredentialAPIKey,
		id:     key.ID,
		prefix: key.Prefix,
		expiry: key.Expiration,
		owner:  key.UserID,
	}), nil
}

func unauthorized() *Problem {
	return newProblem(
		CodeUnauthorized,
		"Send a valid API key or access token as Authorization: Bearer.",
	)
}

// credentialProblem is the answer to a credential check that failed with
// err.
func credentialProblem(ctx context.Context, err error) *Problem {
	reqID := middleware.GetReqID(ctx)

	switch {
	case ctx.Err() != nil:
		// The caller left and the check stopped: answered as a handler's read
		// that stopped is, and not logged as a failing store.
		return newProblem(CodeInternal, "")
	case errors.Is(err, db.ErrCredentialStore):
		log.Error().
			Err(err).
			Str(zf.RequestID, reqID).
			Msg("api v0: database failed while checking a credential")

		return databaseUnreachable()
	case errors.Is(err, db.ErrLegacyHashBusy):
		log.Warn().
			Err(err).
			Str(zf.RequestID, reqID).
			Msg("api v0: legacy hash check busy")

		return credentialCheckBusy()
	case slices.ContainsFunc(refused, func(r error) bool { return errors.Is(err, r) }):
		return unauthorized()
	default:
		log.Error().
			Err(err).
			Str(zf.RequestID, reqID).
			Msg("api v0: credential could not be checked")

		return unauthorized()
	}
}
