// Package apiv2 is Headscale's v2 HTTP API, served at /api/v2.
//
// Where the v1 API (hscontrol/api/v1) is the headscale-native admin surface, v2
// additionally ports selected endpoints from Tailscale's API, reusing
// Tailscale's wire shapes (paths, request/response JSON, error body), so the
// existing Tailscale ecosystem (the Terraform/OpenTofu provider, tscli, and
// tailscale.com/client/tailscale/v2) can drive Headscale unchanged. Ported
// operations carry the "Tailscale compat" tag; a headscale-native v2 operation
// may use headscale's own conventions instead. See README.md for the porting
// guide.
//
// It depends only on the domain layer (hscontrol/state, hscontrol/types, and
// the db error sentinels), never on the hscontrol server package, so it sits
// beside the v1 API without either importing the other.
package apiv2

import (
	"context"
	"encoding/base64"
	"maps"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
)

// Backend is the dependency surface the v2 API needs from the control plane:
// the state layer, the change-notification sink that distributes node/policy
// updates to connected clients, and the config (Policy.Mode/Path, Node.Expiry,
// and TLS are read by the ACL and settings handlers).
type Backend struct {
	State  *state.State
	Change func(...change.Change)
	Cfg    *types.Config
}

// security is the requirement applied to authenticated operations: an API key
// presented as HTTP Basic (the key as username, what the Tailscale SDK sends)
// or as a Bearer token.
var security = []map[string][]string{{"basicAuth": {}}, {"bearerAuth": {}}}

// registrations is populated by each resource file's init(), so adding a
// resource means adding a file rather than editing a shared list.
var registrations []func(huma.API, Backend)

// Register wires up every operation contributed by the resource files. Exported
// so tests can register the v2 operations onto a humatest API.
func Register(api huma.API, b Backend) {
	for _, fn := range registrations {
		fn(api, b)
	}
}

// Config returns the Huma configuration shared by the production API and tests:
// the v2 OpenAPI/docs paths, the basic+bearer security schemes, and the
// Tailscale error transform. Suppressing SchemasPath/CreateHooks keeps "$schema"
// out of the emitted bodies, matching the Tailscale wire contract.
func Config() huma.Config {
	config := huma.DefaultConfig("Headscale API", "v2")
	config.Info.Description = "Headscale v2 API. Some endpoints are ported from / compatible with the Tailscale API (tagged \"Tailscale compat\")."

	config.OpenAPIPath = "/api/v2/openapi"
	config.DocsPath = "/api/v2/docs"
	config.SchemasPath = ""
	config.CreateHooks = nil

	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"basicAuth":  {Type: "http", Scheme: "basic"},
		"bearerAuth": {Type: "http", Scheme: "bearer"},
	}

	config.Transformers = append(config.Transformers, tailscaleErrorTransformer)

	// Accept application/hujson request bodies (the Tailscale SDK sends the
	// policy file that way). The bytes are captured raw by the ACL handler, so
	// reusing the JSON format is only to satisfy huma's content-type check.
	// Clone first: config.Formats aliases huma's shared DefaultFormats map.
	formats := maps.Clone(config.Formats)
	formats["application/hujson"] = formats["application/json"]
	config.Formats = formats

	return config
}

// NewAPI builds the v2 Huma API on router, installs the auth+scope middleware,
// and registers every operation.
func NewAPI(router chi.Router, backend Backend) huma.API {
	api := humachi.New(router, Config())

	// Must run before Register: Huma snapshots the middleware chain at operation
	// registration, so a middleware added afterwards would silently never run.
	api.UseMiddleware(authMiddleware(api, backend))

	Register(api, backend)

	// The OAuth token endpoint is a plain route, not a Huma operation (see
	// oauth.go); register it on the same router.
	registerOAuthToken(router, backend)

	return api
}

// Handler builds the v2 API on a fresh mux and returns both, for mounting.
func Handler(backend Backend) (*chi.Mux, huma.API) {
	mux := chi.NewMux()
	api := NewAPI(mux, backend)

	return mux, api
}

// Spec emits the OpenAPI 3.1 document. The zero Backend is safe because
// handlers are registered but never invoked during emission.
func Spec() ([]byte, error) {
	api := NewAPI(chi.NewMux(), Backend{})

	return api.OpenAPI().YAML()
}

// Spec30 emits the document downgraded to OpenAPI 3.0.3, needed because
// oapi-codegen cannot yet read 3.1; the typed client is generated from this.
func Spec30() ([]byte, error) {
	api := NewAPI(chi.NewMux(), Backend{})

	return api.OpenAPI().DowngradeYAML()
}

type contextKey int

const (
	localTrustKey contextKey = iota
	ownerUserKey
	principalScopesKey
	principalTagsKey
)

// WithLocalTrust marks a request as arriving over a locally-trusted transport
// (the unix socket), bypassing API-key authentication. Reserved for a future
// v2 socket mount; the network listener always authenticates.
func WithLocalTrust(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req.WithContext(
			context.WithValue(req.Context(), localTrustKey, struct{}{}),
		))
	})
}

// authMiddleware authenticates the API key (HTTP Basic with the key as the
// username, what the Tailscale SDK sends, or Bearer), records the key's owning
// user for handlers, and enforces the operation's required scope.
func authMiddleware(api huma.API, b Backend) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if ctx.Context().Value(localTrustKey) != nil {
			next(ctx)

			return
		}

		if len(ctx.Operation().Security) == 0 {
			next(ctx)

			return
		}

		token, ok := bearerOrBasicToken(ctx.Header("Authorization"))
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")

			return
		}

		// An OAuth access token is scope-limited; an admin API key is all-access.
		// They are told apart by prefix so a scoped token can never be mistaken
		// for an all-access key.
		if strings.HasPrefix(token, types.AccessTokenPrefix) {
			at, err := b.State.AuthenticateAccessToken(token)
			if err != nil {
				_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")

				return
			}

			if want, ok := requiredScope(ctx.Operation()); ok && !scope.Grants(scope.Parse(at.Scopes), want) {
				_ = huma.WriteErr(api, ctx, http.StatusForbidden,
					"token is missing the required scope "+string(want))

				return
			}

			// The keys handler multiplexes on keyType, so its required scope and
			// permitted tags depend on the body; carry the token's scopes and tags
			// for it to finish the check the static middleware cannot.
			ctx = huma.WithValue(ctx, principalScopesKey, at.Scopes)
			ctx = huma.WithValue(ctx, principalTagsKey, at.Tags)

			next(ctx)

			return
		}

		key, err := b.State.AuthenticateAPIKey(token)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")

			return
		}

		// An admin API key is all-access: its operations are not scope-checked.
		// Record its owning user (may be unset) so handlers can create user-owned
		// keys on its behalf.
		if key.UserID != nil {
			ctx = huma.WithValue(ctx, ownerUserKey, types.UserID(*key.UserID))
		}

		next(ctx)
	}
}

// bearerOrBasicToken extracts the API key from an Authorization header. The
// Tailscale SDK sends the key as the Basic-auth username with an empty
// password; curl and humans may use Bearer.
func bearerOrBasicToken(header string) (string, bool) {
	if token, ok := strings.CutPrefix(header, "Bearer "); ok {
		return token, token != ""
	}

	if encoded, ok := strings.CutPrefix(header, "Basic "); ok {
		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return "", false
		}

		username, _, _ := strings.Cut(string(raw), ":")

		return username, username != ""
	}

	return "", false
}

// ownerUser returns the user the request's API key belongs to, if any.
func ownerUser(ctx context.Context) (types.UserID, bool) {
	uid, ok := ctx.Value(ownerUserKey).(types.UserID)

	return uid, ok
}

// principalScopes returns the scopes granted to the request's OAuth access
// token, and whether the request authenticated with one. ok is false for an
// admin API key, which is all-access and not scope-checked.
func principalScopes(ctx context.Context) ([]string, bool) {
	scopes, ok := ctx.Value(principalScopesKey).([]string)

	return scopes, ok
}

// principalTags returns the tags granted to the request's OAuth access token,
// and whether the request authenticated with one. An admin API key is not an
// OAuth token, so ok is false and its key creation is unrestricted by tags.
func principalTags(ctx context.Context) ([]string, bool) {
	tags, ok := ctx.Value(principalTagsKey).([]string)

	return tags, ok
}

// requireDefaultTailnet rejects any tailnet other than "-". Headscale is
// single-tailnet; the Tailscale SDK sends "-" (its default tailnet). A non-"-"
// value is "no such tailnet", a 404, which lets the SDK's IsNotFound behave.
func requireDefaultTailnet(tailnet string) error {
	if tailnet != "-" {
		return huma.Error404NotFound("tailnet not found")
	}

	return nil
}

// The scope vocabulary and the grant predicate live in the hscontrol/scope
// package; this file only wires a required scope onto each huma operation and
// reads it back in the middleware.

// scopeMetaKey keys the per-operation required scope in huma.Operation.Metadata.
const scopeMetaKey = "headscale.scope"

// requireScope records op's required scope, both in its Metadata (where the auth
// middleware reads it back) and in the generated OpenAPI document: an
// x-required-scope extension for machine consumers and a Description line so the
// rendered docs state what each operation needs.
func requireScope(op huma.Operation, s scope.Scope) huma.Operation {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}

	op.Metadata[scopeMetaKey] = s

	if op.Extensions == nil {
		op.Extensions = map[string]any{}
	}

	op.Extensions["x-required-scope"] = string(s)

	note := "Requires the `" + string(s) + "` OAuth scope (an admin API key is all-access)."
	if op.Description == "" {
		op.Description = note
	} else {
		op.Description += "\n\n" + note
	}

	return op
}

// requiredScope returns the scope an operation declared via requireScope, if any.
func requiredScope(op *huma.Operation) (scope.Scope, bool) {
	if op == nil || op.Metadata == nil {
		return "", false
	}

	s, ok := op.Metadata[scopeMetaKey].(scope.Scope)

	return s, ok
}
