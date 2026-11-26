// Package apiv0 is Headscale's own API, served at /api/headscale/v0. It may
// change in any minor release until it becomes v1; every change is in the
// changelog.
//
// Every operation is registered through [register], which records who may
// call it and the problem codes it answers, in the OpenAPI document and in
// the operation's metadata, where the auth middleware reads them. Package
// settings of huma are never changed: three APIs share the process.
//
// The skeleton is v1's and v2's: a Backend, NewAPI, Handler and Spec, one
// registerX per resource on a humachi mux, an xInput struct with path and
// query tags. What differs is on purpose:
//   - [register], not huma.Register: an operation declares who may call it,
//     and one it does not declare is refused, never open.
//   - Errors are [Problem]s (RFC 9457 with a code), made by newProblem, not
//     huma.ErrorNNN; each operation names the codes it answers and maps its
//     own errors, so a code the document does not list cannot leave.
//   - A field a PATCH may clear is an [Optional]. A delete with nothing to
//     tell answers 204; the delete of a user answers 200 with what went.
//   - Bodies are read by their exact member names, an unknown query
//     parameter is refused, and a write may carry If-Match.
//   - newAPI calls each registerX itself; there is no registration slice
//     at the level of the package, which v1 and v2 fill from init.
//   - An output is named when it carries a header or two operations share
//     it, and is an anonymous struct{ Body T } otherwise.
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

	// Once every operation is registered.
	defer openResponses(api.OpenAPI())

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
		writeProblem(
			w,
			r,
			newProblem(CodeMethodNotAllowed, "This path does not take "+r.Method+"."),
		)
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
	"Headscale-Version": {
		Description: "The version of the server.",
		Required:    true,
		Schema:      &huma.Schema{Type: huma.TypeString},
	},
	"Headscale-Commit": {
		Description: "The short commit of the server, when the build knows it.",
		Schema:      &huma.Schema{Type: huma.TypeString},
	},
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
		all = append(
			all,
			CodeInvalidRequest,
			CodeTooLarge,
			CodeUnsupportedMediaType,
			CodeRequestTimeout,
		)
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

	problem := api.OpenAPI().Components.Schemas.Schema(
		reflect.TypeFor[Problem](),
		true,
		"Problem",
	)

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
			Content: map[string]*huma.MediaType{
				problemContentType: {Schema: problem},
			},
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

		// Every handler that declares them sends them.
		for _, name := range []string{"Location", "ETag"} {
			if h, ok := r.Headers[name]; ok {
				h.Required = true
			}
		}
	}
}

// operations is every operation of a path, by method.
func operations(item *huma.PathItem) map[string]*huma.Operation {
	all := map[string]*huma.Operation{
		http.MethodGet:     item.Get,
		http.MethodHead:    item.Head,
		http.MethodPost:    item.Post,
		http.MethodPut:     item.Put,
		http.MethodPatch:   item.Patch,
		http.MethodDelete:  item.Delete,
		http.MethodOptions: item.Options,
		http.MethodTrace:   item.Trace,
	}
	maps.DeleteFunc(all, func(_ string, op *huma.Operation) bool { return op == nil })

	return all
}

// openResponses lets every schema that only an answer reaches take a field
// it does not list, and each of its enums a value it does not list: 002
// lets a release add both to an answer, and a client that validates answers
// against the document must not break on one. A request stays strict, and
// no schema may serve both.
func openResponses(oapi *huma.OpenAPI) {
	reg := oapi.Components.Schemas
	requests, responses := documentRoots(oapi)
	strict := reachedSchemas(reg, requests)

	for _, name := range slices.Sorted(maps.Keys(reachedSchemas(reg, responses))) {
		if strict[name] {
			panic(
				"apiv0: schema " + name + " is in a request and in an answer; give each its own type",
			)
		}

		s := reg.Map()[name]
		s.AdditionalProperties = nil

		for prop, ps := range s.Properties {
			s.Properties[prop] = openEnum(
				reg,
				name+strings.ToUpper(prop[:1])+prop[1:],
				ps,
			)
		}
	}
}

// openEnum is ps, a field of an answer, taking any text. The values this
// release knows stay a schema of their own, named as the Go client names
// the type of the field, and x-go-type keeps that type on the field.
func openEnum(reg huma.Registry, name string, ps *huma.Schema) *huma.Schema {
	switch {
	case ps.Ref != "" && len(reg.SchemaFromRef(ps.Ref).Enum) > 0:
		name = strings.TrimPrefix(ps.Ref, schemaRefPrefix)
	case len(ps.Enum) > 0 && ps.Type == huma.TypeString && !ps.Nullable:
		if _, ok := reg.Map()[name]; ok {
			panic("apiv0: the enum " + name + " has the name of a schema")
		}

		reg.Map()[name] = &huma.Schema{
			Type:        huma.TypeString,
			Enum:        ps.Enum,
			Description: ps.Description,
		}
	case len(ps.Enum) > 0:
		panic("apiv0: the enum " + name + " is not a text that is never null")
	default:
		return ps
	}

	return &huma.Schema{
		Description: ps.Description,
		AnyOf: []*huma.Schema{
			{Ref: schemaRefPrefix + name},
			{Type: huma.TypeString},
		},
		Extensions: map[string]any{"x-go-type": name},
	}
}

// documentRoots are the schemas of every request (body and parameters) and
// of every answer of oapi.
func documentRoots(oapi *huma.OpenAPI) ([]*huma.Schema, []*huma.Schema) {
	var requests, responses []*huma.Schema

	for _, item := range oapi.Paths {
		for _, op := range operations(item) {
			for _, p := range op.Parameters {
				requests = append(requests, p.Schema)
			}

			if op.RequestBody != nil {
				for _, mt := range op.RequestBody.Content {
					requests = append(requests, mt.Schema)
				}
			}

			for _, r := range op.Responses {
				for _, mt := range r.Content {
					responses = append(responses, mt.Schema)
				}
			}
		}
	}

	return requests, responses
}

// reachedSchemas is the name of every component schema that roots refer
// to, directly or through another.
func reachedSchemas(reg huma.Registry, roots []*huma.Schema) map[string]bool {
	seen := map[string]bool{}

	var walk func(s *huma.Schema)

	walk = func(s *huma.Schema) {
		if s == nil {
			return
		}

		if s.Ref != "" {
			name := strings.TrimPrefix(s.Ref, schemaRefPrefix)
			if !seen[name] {
				seen[name] = true
				walk(reg.Map()[name])
			}
		}

		walk(s.Items)

		if ap, ok := s.AdditionalProperties.(*huma.Schema); ok {
			walk(ap)
		}

		for _, p := range s.Properties {
			walk(p)
		}

		for _, list := range [][]*huma.Schema{s.AnyOf, s.OneOf, s.AllOf} {
			for _, c := range list {
				walk(c)
			}
		}
	}

	for _, s := range roots {
		walk(s)
	}

	return seen
}

const schemaRefPrefix = "#/components/schemas/"
