// Package apiv1 is the code-first Huma implementation of the Headscale v1 API.
// Handlers are a thin adapter over hscontrol/state; Huma emits the OpenAPI 3.1
// spec from the Go definitions (see Spec), and that spec drives the client.
//
// It depends only on the domain layer (hscontrol/state, hscontrol/types) via
// Backend, never on the hscontrol server package, so a future hscontrol/api/v2
// can sit beside it without either importing the other.
package apiv1

import (
	"context"
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
)

// Backend is the dependency surface the v1 API needs from the control plane:
// the state layer, the change-notification sink that distributes updates to
// connected nodes, and the config (only Policy.Mode and Policy.Path are read).
type Backend struct {
	State  *state.State
	Change func(...change.Change)
	Cfg    *types.Config
}

// NewAPI builds the v1 Huma API on the given chi router and registers every
// operation. Auth is enforced by a Huma middleware driven by each operation's
// declared bearer security (see authMiddleware); locally-trusted requests
// bypass it via WithLocalTrust.
func NewAPI(router chi.Router, backend Backend) huma.API {
	config := huma.DefaultConfig("Headscale API", "v1")
	config.Info.Description = "Headscale control server API."

	// Version the OpenAPI/docs routes under /api/v1 so a future v2 owns its own.
	// These register as plain mux routes, not operations, so they never appear
	// in the emitted spec or client.
	config.OpenAPIPath = "/api/v1/openapi"
	config.DocsPath = "/api/v1/docs"

	// The v1 API does not emit "$schema".
	config.SchemasPath = ""

	// Drop the default schema-link create hook: it injects a "$schema" property
	// and Link header into every response, which the v1 contract omits.
	config.CreateHooks = nil

	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {
			Type:   "http",
			Scheme: "bearer",
		},
	}

	api := humachi.New(router, config)

	// Must run before register: Huma snapshots the middleware chain at operation
	// registration, so a middleware added afterwards would silently never run.
	api.UseMiddleware(authMiddleware(api, backend))

	register(api, backend)

	return api
}

// bearerAuth is the security requirement applied to every operation: all
// /api/v1 routes require an API key.
var bearerAuth = []map[string][]string{{"bearer": {}}}

// registrations is populated by each resource file's init(), so adding a
// resource group means adding a file rather than editing a shared point. Huma
// sorts the emitted spec, so init order does not affect output.
var registrations []func(huma.API, Backend)

// register wires up every operation contributed by the resource files.
func register(api huma.API, b Backend) {
	for _, fn := range registrations {
		fn(api, b)
	}
}

// Spec emits the OpenAPI 3.1 document. The zero Backend is safe because
// handlers are registered but never invoked during emission.
func Spec() ([]byte, error) {
	api := NewAPI(chi.NewMux(), Backend{})
	return api.OpenAPI().YAML()
}

// Spec30 emits the document downgraded to OpenAPI 3.0.3, needed because the
// client generator (oapi-codegen v2) cannot yet read the 3.1 spec.
func Spec30() ([]byte, error) {
	api := NewAPI(chi.NewMux(), Backend{})
	return api.OpenAPI().DowngradeYAML()
}

// Handler builds the v1 API on a fresh mux and returns both. Callers mount the
// mux and may use mux.Match to detect which paths this API serves.
func Handler(backend Backend) (*chi.Mux, huma.API) {
	mux := chi.NewMux()
	api := NewAPI(mux, backend)

	return mux, api
}

// localTrustKey marks a request as arriving over a locally-trusted transport;
// the auth middleware skips authentication for such requests.
type localTrustKey struct{}

// WithLocalTrust wraps a handler so its requests bypass API-key authentication.
// The unix socket uses this — access to the socket is the trust boundary — as
// do in-process tests that exercise the mux directly.
func WithLocalTrust(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		next.ServeHTTP(w, req.WithContext(
			context.WithValue(req.Context(), localTrustKey{}, struct{}{}),
		))
	})
}

// authMiddleware is a pure gate enforcing the bearer API key for any operation
// that declares security; the v1 handlers do not read caller identity.
// Locally-trusted requests and operations without declared security pass
// through. b.State is nil only during spec emission, where no request is
// served, so it is never dereferenced there.
func authMiddleware(api huma.API, b Backend) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		if ctx.Context().Value(localTrustKey{}) != nil {
			next(ctx)

			return
		}

		if len(ctx.Operation().Security) == 0 {
			next(ctx)

			return
		}

		token, ok := strings.CutPrefix(ctx.Header("Authorization"), "Bearer ")
		if !ok {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")

			return
		}

		valid, err := b.State.ValidateAPIKey(token)
		if err != nil || !valid {
			_ = huma.WriteErr(api, ctx, http.StatusUnauthorized, "Unauthorized")

			return
		}

		next(ctx)
	}
}
