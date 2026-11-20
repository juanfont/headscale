// Package apiv0 is Headscale's own API, served at /api/headscale/v0. It may
// change in any minor release until it becomes v1; every change is in the
// changelog.
//
// Every operation is registered through [register], which records who may
// call it and the problem codes it answers, in the OpenAPI document and in
// the operation's metadata, where the auth middleware reads them. Package
// settings of huma are never changed: three APIs share the process.
package apiv0

import (
	"context"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Prefix is the path every v0 operation is under.
const Prefix = "/api/headscale/v0"

// Backend is what v0 needs from the control plane.
type Backend struct {
	State *state.State
	Cfg   *types.Config
}

// specVersion is info.version of the document in the tree, which no server
// made; a served document carries the server's version.
const specVersion = "v0"

// Config returns the huma configuration of v0, for the server and tests.
func Config(version string) huma.Config {
	config := huma.DefaultConfig("Headscale API", version)
	config.Info.Description = "Headscale's own API. It may change in any minor release; every change is in the changelog under \"API v0\"."

	config.OpenAPIPath = Prefix + "/openapi"
	config.DocsPath = Prefix + "/docs"
	config.SchemasPath = ""
	config.CreateHooks = nil
	config.RejectUnknownQueryParameters = true

	config.Components.SecuritySchemes = map[string]*huma.SecurityScheme{
		"bearer": {Type: "http", Scheme: "bearer"},
	}

	config.Transformers = append(config.Transformers, problemTransformer)

	return config
}

// NewAPI builds v0 on router: the auth middleware, then every operation.
func NewAPI(router chi.Router, b Backend, version string) huma.API {
	return newAPI(router, b, Config(version))
}

func newAPI(router chi.Router, b Backend, config huma.Config) huma.API {
	api := humachi.New(router, config)

	// Before registering: huma snapshots the middleware chain per operation.
	api.UseMiddleware(authMiddleware(b))

	registerServer(api, b)

	return api
}

// versionInfo is the version the headers and the served document carry.
// Tests give it a commit, which a test binary does not know.
var versionInfo = types.GetVersionInfo

// Handler builds v0 for mounting at [Prefix]. Every response, the router's
// own problems included, carries the version headers.
func Handler(b Backend) http.Handler {
	mux := chi.NewMux()

	NewAPI(mux, b, versionInfo().Version)

	mux.NotFound(func(w http.ResponseWriter, r *http.Request) {
		writeProblem(w, r, newProblem(CodeNotFound, "No operation has this path."))
	})
	mux.MethodNotAllowed(func(w http.ResponseWriter, r *http.Request) {
		// RFC 9110 asks a 405 for the methods the path takes.
		var allow []string

		for _, m := range []string{http.MethodGet, http.MethodHead, http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
			if mux.Match(chi.NewRouteContext(), m, r.URL.Path) {
				allow = append(allow, m)
			}
		}

		w.Header().Set("Allow", strings.Join(allow, ", "))
		writeProblem(w, r, newProblem(CodeMethodNotAllowed, "This path does not take "+r.Method+"."))
	})

	return VersionHeaders(mux)
}

// VersionHeaders puts Headscale-Version, and Headscale-Commit when the build
// knows it, on every answer of next. The CLI reads them before any body, so
// an answer made in front of v0, such as a CORS preflight, carries them too.
func VersionHeaders(next http.Handler) http.Handler {
	info := versionInfo()

	commit := info.Commit
	if commit == "unknown" {
		commit = ""
	}

	commit = commit[:min(len(commit), 7)]

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", info.Version)

		if commit != "" {
			w.Header().Set("Headscale-Commit", commit)
		}

		next.ServeHTTP(w, r)
	})
}

// Spec emits the OpenAPI 3.1 document that is in the tree. The zero Backend
// is safe: no handler runs.
func Spec() ([]byte, error) {
	return NewAPI(chi.NewMux(), Backend{}, specVersion).OpenAPI().YAML()
}

// accessKind is who may call an operation. The zero value is no
// declaration, which every caller is refused.
type accessKind int

const (
	undeclared accessKind = iota
	// publicAccess needs no credential.
	publicAccess
	// anyCredentialAccess needs a valid credential and no scope.
	anyCredentialAccess
	// scopedAccess needs a credential with every scope in access.scopes.
	scopedAccess
)

// access is who may call an operation. Its kind comes from its fields, so
// that no literal can make a scoped access without scopes: such a value, like
// the zero value, is undeclared, and every caller is refused.
type access struct {
	// open is publicAccess or anyCredentialAccess; zero when scopes are set.
	open   accessKind
	scopes []scope.Scope
}

func (a access) kind() accessKind {
	switch {
	case a.open == undeclared && len(a.scopes) > 0:
		return scopedAccess
	case len(a.scopes) == 0 && (a.open == publicAccess || a.open == anyCredentialAccess):
		return a.open
	default:
		return undeclared
	}
}

var (
	public        = access{open: publicAccess}
	anyCredential = access{open: anyCredentialAccess}
)

// needs is the access of an operation that a token reaches only with every
// scope in s.
func needs(s ...scope.Scope) access {
	if len(s) == 0 {
		panic("apiv0: needs() without a scope; use anyCredential")
	}

	return access{scopes: s}
}

const (
	accessMetaKey = "headscale.v0.access"
	codesMetaKey  = "headscale.v0.codes"
)

// versionHeaders are on every v0 answer; see [Handler].
var versionHeaders = map[string]*huma.Header{
	"Headscale-Version": {Description: "The version of the server.", Required: true, Schema: &huma.Schema{Type: huma.TypeString}},
	"Headscale-Commit":  {Description: "The short commit of the server, when the build knows it.", Schema: &huma.Schema{Type: huma.TypeString}},
}

// register adds op to api with its access and the problem codes of its own.
// The codes every operation of its kind can answer are added here, so a
// handler lists only what is particular to it. A handler that returns a code
// the operation did not declare answers internal.
func register[I, O any](
	api huma.API,
	op huma.Operation,
	a access,
	own []Code,
	handler func(context.Context, *I) (*O, error),
) {
	if a.kind() == undeclared {
		panic("apiv0: " + op.OperationID + " declares no access")
	}

	all := slices.Clone(own)
	all = append(all, CodeInvalidField, CodeInternal)

	if a.kind() != publicAccess {
		scopes := make([]string, len(a.scopes))
		for i, s := range a.scopes {
			scopes[i] = string(s)
		}

		op.Security = []map[string][]string{{"bearer": scopes}}

		// A database that fails while the credential is checked.
		all = append(all, CodeUnauthorized, CodeUnhealthy)
	}

	if a.kind() == scopedAccess {
		all = append(all, CodeForbidden)
	}

	if _, ok := reflect.TypeFor[I]().FieldByName("Body"); ok {
		all = append(all, CodeInvalidRequest, CodeTooLarge, CodeUnsupportedMediaType, CodeRequestTimeout)
	}

	if strings.Contains(op.Path, "{") {
		all = append(all, CodeNotFound)
	}

	slices.Sort(all)
	all = slices.Compact(all)

	for _, c := range all {
		if _, ok := codes[c]; !ok {
			panic("apiv0: " + op.OperationID + " declares unknown code " + string(c))
		}
	}

	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}

	op.Metadata[accessMetaKey] = a
	op.Metadata[codesMetaKey] = all

	if op.Extensions == nil {
		op.Extensions = map[string]any{}
	}

	op.Extensions["x-problem-codes"] = all

	problem := api.OpenAPI().Components.Schemas.Schema(reflect.TypeFor[Problem](), true, "Problem")

	byStatus := map[int][]string{}
	for _, c := range all {
		byStatus[codes[c].status] = append(byStatus[codes[c].status], string(c))
	}

	if op.Responses == nil {
		op.Responses = map[string]*huma.Response{}
	}

	for status, cs := range byStatus {
		op.Responses[strconv.Itoa(status)] = &huma.Response{
			Description: http.StatusText(status) + ": " + strings.Join(cs, ", "),
			Content:     map[string]*huma.MediaType{problemContentType: {Schema: problem}},
			// A copy: the loop below adds to each response's map.
			Headers: maps.Clone(versionHeaders),
		}
	}

	huma.Register(api, op, func(ctx context.Context, in *I) (*O, error) {
		out, err := handler(ctx, in)
		if err != nil {
			return nil, mapError(ctx, err, all)
		}

		return out, nil
	})

	// The success answer exists only now; it carries the headers too.
	for _, r := range operations(api.OpenAPI().Paths[op.Path])[op.Method].Responses {
		if r.Headers == nil {
			r.Headers = map[string]*huma.Header{}
		}

		maps.Copy(r.Headers, versionHeaders)
	}
}

// operations is every operation of a path, by method.
func operations(item *huma.PathItem) map[string]*huma.Operation {
	all := map[string]*huma.Operation{
		http.MethodGet: item.Get, http.MethodHead: item.Head, http.MethodPost: item.Post,
		http.MethodPut: item.Put, http.MethodPatch: item.Patch, http.MethodDelete: item.Delete,
		http.MethodOptions: item.Options, http.MethodTrace: item.Trace,
	}
	maps.DeleteFunc(all, func(_ string, op *huma.Operation) bool { return op == nil })

	return all
}
