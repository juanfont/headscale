// Package apiv1 is the code-first Huma implementation of the Headscale v1 API.
// Handlers are a thin adapter over hscontrol/state; Huma emits the OpenAPI 3.1
// spec from the Go definitions (see Spec), and that spec drives the client.
//
// It depends only on the domain layer (hscontrol/state, hscontrol/types) via
// Backend, never on the hscontrol server package, so a future hscontrol/api/v2
// can sit beside it without either importing the other.
package apiv1

import (
	"bytes"
	"context"
	"encoding/json/jsontext"
	jsonv2 "encoding/json/v2"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/wrapperspb"
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

	// Errors keep the 0.29 body; see Status.
	config.Transformers = append(config.Transformers, grpcStatusTransformer)

	// JSON only, whatever else imports register in huma.DefaultFormats: every
	// body Huma decodes is then one bodyMiddleware reads (see huma.API
	// Unmarshal there).
	config.Formats = map[string]huma.Format{
		"application/json": huma.DefaultJSONFormat,
		"json":             huma.DefaultJSONFormat,
	}
	config.OnAddOperation = append(config.OnAddOperation, documentStatus, documentOpenBodies)

	router.NotFound(routingError(backend, http.StatusNotFound, http.StatusNotFound, codeNotFound))
	router.MethodNotAllowed(routingError(backend, http.StatusMethodNotAllowed, http.StatusNotImplemented, codeUnimplemented))

	api := humachi.New(router, config)
	api.UseMiddleware(statusMiddleware)

	// Must run before register: Huma snapshots the middleware chain at operation
	// registration, so a middleware added afterwards would silently never run.
	api.UseMiddleware(authMiddleware(backend))
	api.UseMiddleware(queryMiddleware(api))
	api.UseMiddleware(bodyMiddleware(api))

	register(api, backend)

	// Status replaced Huma's error model in every operation.
	schemas := api.OpenAPI().Components.Schemas.Map()
	delete(schemas, "ErrorModel")
	delete(schemas, "ErrorDetail")

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
func authMiddleware(b Backend) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		local := ctx.Context().Value(localTrustKey{}) != nil
		if len(ctx.Operation().Security) == 0 || authorized(local, ctx.Header("Authorization"), b) {
			next(ctx)

			return
		}

		writeUnauthorized(ctx)
	}
}

// queryMiddleware refuses the query keys and values 0.29's grpc-gateway
// refused (runtime/query.go, v2.29.0), which Huma reads as something else or
// not at all, so a write cannot act on what the caller did not ask for:
//   - a parameter given twice, where Huma takes the first (query.go:159-161);
//   - an empty value of a typed parameter, which Huma treats as absent
//     (query.go:166-170);
//   - a dotted key into a scalar, name.child (query.go:144-146), and a
//     bracketed one, name[x], which adds a second value (query.go:50-53);
//   - a dotted key into a path parameter named by its JSON name where that
//     differs from the proto name, nodeId.x; node_id.x and nodeId were
//     filtered out as the path's (query.go:57) and stay ignored;
//   - a query the gateway's ParseForm could not parse.
//
// A date-time parameter is a google.protobuf.Timestamp, a message: its
// operation reads the dotted fields itself. Keys naming nothing are ignored,
// as the gateway did. An operation without query parameters had no query
// parsed at all (the generated headscale.pb.gw.go at v0.29.7 calls
// PopulateQueryParameters only for those), so its query is left alone.
func queryMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		op := ctx.Operation()
		if !takesQuery(op) {
			next(ctx)

			return
		}

		u := ctx.URL()

		// url.Values.Query drops a pair it cannot read, such as one with a
		// semicolon; the gateway's ParseForm refused the request.
		query, err := url.ParseQuery(u.RawQuery)
		if err != nil {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, err.Error())

			return
		}

		for _, key := range slices.Sorted(maps.Keys(query)) {
			msg := gatewayQueryError(op, key, query[key])
			if msg != "" {
				_ = huma.WriteErr(api, ctx, http.StatusBadRequest, msg)

				return
			}
		}

		next(queryContext{ctx, query})
	}
}

// queryContext answers Huma's query reads from the values queryMiddleware
// checked. Huma's own reader takes a bare key, ?name, as "true"; the gateway
// read it as "", as url.ParseQuery does.
type queryContext struct {
	humaContext

	query url.Values
}

// humaContext names the embedded field, since huma.Context has a Context
// method.
type humaContext = huma.Context

func (c queryContext) Query(name string) string { return c.query.Get(name) }

var bracketKey = regexp.MustCompile(`^(.*)\[(.*)\]$`)

// gatewayQueryKey parses a query key by the gateway's grammar
// (runtime/query.go:50-56): a whole key of the form base[v] adds v as a
// value before the key's own, and base is a dotted path of field names.
// Anything else, an unclosed bracket included, is one field name.
func gatewayQueryKey(key string, values []string) ([]string, []string) {
	if m := bracketKey.FindStringSubmatch(key); m != nil {
		key = m[1]
		values = append([]string{m[2]}, values...)
	}

	return strings.Split(key, "."), values
}

// gatewayQueryError is the gateway's refusal of key=values on op, or "".
func gatewayQueryError(op *huma.Operation, key string, values []string) string {
	path, values := gatewayQueryKey(key, values)

	for _, p := range op.Parameters {
		switch {
		case p.In == "query" && p.Name == path[0]:
			if p.Schema != nil && p.Schema.Format == "date-time" {
				return ""
			}

			if len(path) > 1 {
				return fmt.Sprintf("invalid path: %q is not a message", p.Name)
			}

			if len(values) > 1 {
				return fmt.Sprintf("too many values for field %q: %s", p.Name, strings.Join(values, ", "))
			}

			plainString := p.Schema != nil && p.Schema.Type == huma.TypeString && p.Schema.Format == ""
			if values[0] == "" && !plainString {
				return fmt.Sprintf("parsing field %q: empty value", p.Name)
			}

			return ""
		case p.In == "path" && p.Name == path[0] && len(path) > 1 && protoName(p.Name) != p.Name:
			return fmt.Sprintf("invalid path: %q is not a message", p.Name)
		}
	}

	return ""
}

// protoName is the proto field name protoc derived the JSON name from:
// nodeId from node_id.
func protoName(jsonName string) string {
	var b strings.Builder

	for _, r := range jsonName {
		if unicode.IsUpper(r) {
			b.WriteByte('_')

			r = unicode.ToLower(r)
		}

		b.WriteRune(r)
	}

	return b.String()
}

func takesQuery(op *huma.Operation) bool {
	return slices.ContainsFunc(op.Parameters, func(p *huma.Param) bool { return p.In == "query" })
}

// authorized reports whether a request may reach the API: it arrived over a
// locally-trusted transport, or carries a valid bearer API key.
func authorized(local bool, authHeader string, b Backend) bool {
	if local {
		return true
	}

	token, ok := strings.CutPrefix(authHeader, "Bearer ")
	if !ok {
		return false
	}

	valid, err := b.State.ValidateAPIKey(token)

	return err == nil && valid
}

// bodyMiddleware reads a JSON request body as 0.29's grpc-gateway did
// (protojson with DiscardUnknown, grpc-gateway v2.29.0): a member by its JSON
// or its proto name, a member it does not know dropped, the same field twice
// refused, every ID read by protojson's uint64 rules (protoUint64), null as
// not given and "" too for a declared ID member, and the
// path's own field in the body checked against the path, then dropped, since
// the path overwrote it. Without it, a proto name such as acl_tags would be
// dropped as unknown and the write would go ahead without it.
//
// It runs for exactly the bodies Huma decodes (decodesBody). The body is read
// as Huma reads it, under the operation's read deadline and size limit, and
// handed on with any read error as it came. encoding/json/v2 alone decides
// whether it is JSON: syntax, trailing data, duplicate names.
//
// shortcut: top-level members only; every v1 request body is flat. Walk the
// schema if one ever nests an object.
func bodyMiddleware(api huma.API) func(huma.Context, func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		op := ctx.Operation()

		members := bodyMembers(api, op)
		if members == nil || !decodesBody(api, ctx.Header("Content-Type")) {
			next(ctx)

			return
		}

		// As Huma does before it reads the body (huma.go, Register).
		if op.BodyReadTimeout > 0 {
			_ = ctx.SetReadDeadline(time.Now().Add(op.BodyReadTimeout))
		} else if op.BodyReadTimeout < 0 {
			_ = ctx.SetReadDeadline(time.Time{})
		}

		raw, err := io.ReadAll(io.LimitReader(ctx.BodyReader(), op.MaxBodyBytes+1))
		if err != nil {
			next(bodyContext{ctx, io.MultiReader(bytes.NewReader(raw), errReader{err})})

			return
		}

		if int64(len(raw)) > op.MaxBodyBytes {
			// Huma's own limit refuses it.
			next(bodyContext{ctx, io.MultiReader(bytes.NewReader(raw), ctx.BodyReader())})

			return
		}

		body, msg := gatewayBody(raw, members, ctx.Param)
		if msg != "" {
			_ = huma.WriteErr(api, ctx, http.StatusBadRequest, msg)

			return
		}

		next(bodyContext{ctx, bytes.NewReader(body)})
	}
}

// decodesBody reports whether Huma will decode a body of this Content-Type,
// asked of Huma's own format lookup with the fallback Huma uses for a request
// without one (every v1 body is application/json). v1 registers JSON only, so
// that is a JSON body; for any other type Huma answers 415 itself.
func decodesBody(api huma.API, contentType string) bool {
	if contentType == "" {
		contentType = "application/json"
	}

	return api.Unmarshal(contentType, []byte("null"), new(any)) == nil
}

// errReader hands on a read error after the bytes read before it.
type errReader struct{ err error }

func (r errReader) Read([]byte) (int, error) { return 0, r.err }

// bodyContext serves a body the middleware already read.
type bodyContext struct {
	humaContext

	body io.Reader
}

func (c bodyContext) BodyReader() io.Reader { return c.body }

// bodyMember is what a member name of a body stands for: a declared member,
// by its JSON name, or the path's own field.
type bodyMember struct {
	name string
	path bool
	id   bool
}

// bodyMembers maps each name a member of op's JSON body may have, the JSON
// or the proto name of a declared member or of a path field, to what it
// stands for; nil when op takes no JSON body.
func bodyMembers(api huma.API, op *huma.Operation) map[string]bodyMember {
	if op.RequestBody == nil {
		return nil
	}

	mt := op.RequestBody.Content["application/json"]
	if mt == nil || mt.Schema == nil || mt.Schema.Ref == "" {
		return nil
	}

	schema := api.OpenAPI().Components.Schemas.SchemaFromRef(mt.Schema.Ref)
	if schema == nil {
		return nil
	}

	members := make(map[string]bodyMember, 2*len(schema.Properties))

	for name, prop := range schema.Properties {
		m := bodyMember{name: name, id: prop.Format == "uint64"}
		members[name] = m
		members[protoName(name)] = m
	}

	for _, p := range op.Parameters {
		if p.In == "path" {
			members[p.Name] = bodyMember{name: p.Name, path: true}
			members[protoName(p.Name)] = bodyMember{name: p.Name, path: true}
		}
	}

	return members
}

// gatewayBody rewrites a JSON object to the declared members under their JSON
// names, or returns why the gateway would have refused it. A body that is
// empty or null is left for Huma: it was no request message.
func gatewayBody(raw []byte, members map[string]bodyMember, param func(string) string) ([]byte, string) {
	if len(bytes.TrimSpace(raw)) == 0 {
		return raw, ""
	}

	var object map[string]jsontext.Value

	err := jsonv2.Unmarshal(raw, &object)
	if err != nil {
		return nil, err.Error()
	}

	if object == nil {
		return raw, ""
	}

	seen := map[string]string{}
	out := map[string]jsontext.Value{}

	for _, key := range slices.Sorted(maps.Keys(object)) {
		m, known := members[key]
		if !known {
			continue
		}

		if other, dup := seen[m.name]; dup {
			return nil, fmt.Sprintf("duplicate field %q and %q", other, key)
		}

		seen[m.name] = key

		value := object[key]

		switch {
		case value.Kind() == jsontext.KindNull:
			// protojson read null as not given.
			if m.path {
				continue
			}
		case m.id && string(value) == `""`:
			// Not given either, as main reads it: the CLI's tags-only
			// pre-auth key sends user "" (the 0.29 CLI spoke gRPC), and the
			// two expire selectors keep main's reading of an empty id. No ID
			// is "", though protojson refused it. The path's own field keeps
			// protojson's refusal, as main did too.
			continue
		case m.path:
			id, err := protoUint64(value)
			if err != nil {
				return nil, fmt.Sprintf("parsing field %q: %v", key, err)
			}

			if strconv.FormatUint(id, 10) != param(m.name) {
				return nil, fmt.Sprintf("field %q is %d, the path names %s", key, id, param(m.name))
			}

			continue
		case m.id:
			id, err := protoUint64(value)
			if err != nil {
				return nil, fmt.Sprintf("parsing field %q: %v", key, err)
			}

			value = jsontext.Value(strconv.Quote(strconv.FormatUint(id, 10)))
		}

		out[m.name] = value
	}

	body, err := jsonv2.Marshal(out)
	if err != nil {
		return nil, err.Error()
	}

	return body, ""
}

// protoUint64 reads an ID member as 0.29 decoded it, with protojson's own
// uint64 rules: a JSON number or string, integral, 1.0 and "1e0" as 1, "01",
// " 1" and "" refused.
func protoUint64(value jsontext.Value) (uint64, error) {
	var v wrapperspb.UInt64Value

	err := protojson.Unmarshal(value, &v)
	if err != nil {
		return 0, err
	}

	return v.GetValue(), nil
}

// documentOpenBodies says in the OpenAPI document that a request body may
// carry members v1 does not declare, as bodyMiddleware accepts them.
func documentOpenBodies(oapi *huma.OpenAPI, op *huma.Operation) {
	if op.RequestBody == nil {
		return
	}

	for _, mt := range op.RequestBody.Content {
		if mt.Schema == nil || mt.Schema.Ref == "" {
			continue
		}

		if s := oapi.Components.Schemas.SchemaFromRef(mt.Schema.Ref); s != nil {
			s.AdditionalProperties = true
		}
	}
}
