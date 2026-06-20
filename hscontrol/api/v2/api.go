// Package apiv2 is Headscale's v2 HTTP API, served at /api/v2.
//
// Where the v1 API (hscontrol/api/v1) is the headscale-native admin surface, v2
// additionally ports selected endpoints from Tailscale's API — reusing
// Tailscale's wire shapes (paths, request/response JSON, error body) — so the
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
// presented as HTTP Basic (the key as username — what the Tailscale SDK sends)
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
	// Clone first — config.Formats aliases huma's shared DefaultFormats map.
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

type contextKey int

const (
	localTrustKey contextKey = iota
	ownerUserKey
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
// username — what the Tailscale SDK sends — or Bearer), records the key's
// owning user for handlers, and enforces the operation's required scope.
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

		key, err := b.State.AuthenticateAPIKey(token)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "unauthorized")

			return
		}

		// TODO(scopes): every valid key is all-access today. Operations still
		// declare their required scope (requireScope) so that once OAuth tokens
		// arrive, the granted set can be derived from the token and checked
		// against the operation's scope here. Until then, accept everything.

		// Record the key's owning user (may be unset) so handlers can create
		// user-owned keys on its behalf.
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

// requireDefaultTailnet rejects any tailnet other than "-". Headscale is
// single-tailnet; the Tailscale SDK sends "-" (its default tailnet). A non-"-"
// value is "no such tailnet", a 404, which lets the SDK's IsNotFound behave.
func requireDefaultTailnet(tailnet string) error {
	if tailnet != "-" {
		return huma.Error404NotFound("tailnet not found")
	}

	return nil
}

// Scope is an OAuth capability an operation requires and a token grants. The
// names mirror Tailscale's API scopes (see the OAuth scope descriptions in the
// Tailscale OpenAPI spec); a ...Read scope is the read-only subset of its
// write scope. Nothing is enforced yet — every key is all-access — but every
// operation declares the scope it would require, so OAuth tokens can later be
// checked against it without reworking the operations.
type Scope string

const (
	ScopeAuthKeys     Scope = "auth_keys"
	ScopeAuthKeysRead Scope = "auth_keys:read"

	ScopeDevicesCore     Scope = "devices:core"
	ScopeDevicesCoreRead Scope = "devices:core:read"

	ScopeDevicesRoutes     Scope = "devices:routes"
	ScopeDevicesRoutesRead Scope = "devices:routes:read"

	ScopePolicyFile     Scope = "policy_file"
	ScopePolicyFileRead Scope = "policy_file:read"

	ScopeFeatureSettings     Scope = "feature_settings"
	ScopeFeatureSettingsRead Scope = "feature_settings:read"
)

// scopeMetaKey keys the per-operation required Scope in huma.Operation.Metadata.
const scopeMetaKey = "headscale.scope"

// requireScope records op's required scope in its Metadata, where the auth
// middleware can read it back. It keeps the requirement next to the operation
// definition.
func requireScope(op huma.Operation, s Scope) huma.Operation {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}

	op.Metadata[scopeMetaKey] = s

	return op
}
