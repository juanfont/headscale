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
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"mime"
	"net/http"
	"net/url"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	jsonv2 "github.com/go-json-experiment/json"
	"github.com/go-json-experiment/json/jsontext"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
)

// Prefix is the path every v0 operation is under.
const Prefix = "/api/headscale/v0"

// Backend is what v0 needs from the control plane.
type Backend struct {
	State *state.State
	// Change sends the change of a write to the connected nodes.
	Change func(...change.Change)
	Cfg    *types.Config
	// Connected reports whether a node has a live map stream, which alone
	// can carry a request to the node.
	Connected func(types.NodeID) bool
	// ConnectedSeen is the last seen v0 reports for a connected node, which
	// is "now"; nil is the wall clock. Nothing else reads it: a test sets it
	// so the minute it expects is the minute the server prints.
	ConnectedSeen func() time.Time
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

	// A map of v0's own: DefaultConfig hands out huma's package map.
	// application/hujson is the policy file as a body; requestChecks lets it
	// through only to an operation that lists it.
	config.Formats = map[string]huma.Format{
		"application/json": bodyFormat,
		"json":             bodyFormat,
		hujsonContentType:  hujsonBodyFormat,
	}

	return config
}

// NewAPI builds v0 on router: the auth middleware, then every operation.
func NewAPI(router chi.Router, b Backend, version string) huma.API {
	return newAPI(router, b, Config(version))
}

func newAPI(router chi.Router, b Backend, config huma.Config) huma.API {
	router.Use(strictQuery, joinIfMatch)

	api := hujsonNotAnswered{humachi.New(router, config), config}

	// Once every operation is registered.
	defer openResponses(api.OpenAPI())

	// Before registering: huma snapshots the middleware chain per operation.
	api.UseMiddleware(authMiddleware(b), requestChecks)

	registerServer(api, b)
	registerUsers(api, b)
	registerNodes(api, b)
	registerTags(api, b)
	registerAuthKeys(api, b)
	registerAPIKeys(api, b)
	registerOAuthClients(api, b)
	registerAuthRequests(api, b)
	registerPolicy(api, b)

	return api
}

// hujsonNotAnswered is an API whose answers are never HuJSON: it is a
// format of one request body, and an Accept of it is any type the server
// does not have.
type hujsonNotAnswered struct {
	huma.API

	config huma.Config
}

// Config is what huma reads of the API it wraps, such as the rule on
// unknown query parameters.
func (a hujsonNotAnswered) Config() huma.Config { return a.config }

func (a hujsonNotAnswered) Negotiate(accept string) (string, error) {
	ct, err := a.API.Negotiate(accept)
	if ct == hujsonContentType {
		return a.API.Negotiate("")
	}

	return ct, err
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
	// rules refuse an OAuth access token what scopes allow.
	rules []*tokenRule
	// paramScopes are the scopes a boolean query parameter needs as well
	// when it is true, by the parameter's name.
	paramScopes map[string][]scope.Scope
}

// withTokenRules is a with rules that refuse an OAuth access token.
func (a access) withTokenRules(r ...*tokenRule) access {
	a.rules = append(slices.Clone(a.rules), r...)

	return a
}

// withParamScopes is a that also needs s when the boolean query parameter
// param is true. The scopes are checked with the others, before the request
// is read, so a forbidden answer lists every scope the call lacks.
func (a access) withParamScopes(param string, s ...scope.Scope) access {
	a.paramScopes = maps.Clone(a.paramScopes)
	if a.paramScopes == nil {
		a.paramScopes = map[string][]scope.Scope{}
	}

	a.paramScopes[param] = s

	return a
}

// wants is every scope a needs for a request with query.
func (a access) wants(query url.Values) []scope.Scope {
	want := slices.Clone(a.scopes)

	for _, param := range slices.Sorted(maps.Keys(a.paramScopes)) {
		// Only the form requestChecks lets through is true.
		if query.Get(param) == "true" {
			for _, s := range a.paramScopes[param] {
				if !slices.Contains(want, s) {
					want = append(want, s)
				}
			}
		}
	}

	return want
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
	accessMetaKey  = "headscale.v0.access"
	codesMetaKey   = "headscale.v0.codes"
	maxBodyMetaKey = "headscale.v0.maxBody"

	tokenRulesExtension  = "x-token-rules"
	paramScopesExtension = "x-parameter-scopes"

	mergePatchContentType = "application/merge-patch+json"

	// maxBodyCeiling bounds the limit an operation may set for its body.
	maxBodyCeiling = 1 << 20
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

// register adds op to api with its access and the answers of its own. The
// codes every operation of its kind can answer are added here, so a handler
// lists only what is particular to it. A handler error that the operation
// does not answer is internal.
//
// Before the handler runs, register answers what the request alone shows,
// in this order: a null or a PATCH with no field, a body that checks its own
// fields ([fieldChecker]) and its own codes ([problemChecker]), then a token
// rule. A rule is checked on a body that is right in itself, so a request
// answers the same error for a token as for an API key. The handler then
// looks up the resource of the path, so a bad field is never hidden by
// not_found.
func register[I, O any](
	api huma.API,
	op huma.Operation,
	a access,
	own []answer,
	handler func(context.Context, *I) (*O, error),
) {
	if a.kind() == undeclared {
		panic("apiv0: " + op.OperationID + " declares no access")
	}

	all := make([]Code, 0, len(own)+8)
	for _, o := range own {
		all = append(all, o.code)
	}

	all = append(all, CodeInvalidField, CodeInternal)
	all = append(all, accessCodes(&op, a)...)

	reqCodes, hasBody := requestCodes[I](&op)
	all = append(all, reqCodes...)
	isPatch := op.Method == http.MethodPatch

	all = knownCodes(op.OperationID, all)
	describeCodes(api, &op, a, all)

	huma.Register(api, op, func(ctx context.Context, in *I) (*O, error) {
		var p *Problem
		if hasBody {
			p = bodyProblem(in, isPatch)
		}

		if p == nil {
			p = ruleRefusal(ctx, a, in)
		}

		if p != nil {
			return nil, p
		}

		out, err := handler(ctx, in)
		if err != nil {
			return nil, mapError(ctx, err, all, own)
		}

		return out, nil
	})

	describeRegistered(api, &op, isPatch)

	registered := operations(api.OpenAPI().Paths[op.Path])[op.Method]
	for param := range a.paramScopes {
		if !booleanQuery(registered, param) {
			panic(
				"apiv0: " + op.OperationID + " has scopes for " + param + ", which is not a boolean query parameter",
			)
		}
	}
}

// accessCodes sets the security and token rules of op from a, and returns
// the codes its credential check can answer.
func accessCodes(op *huma.Operation, a access) []Code {
	var all []Code

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

	if len(a.rules) > 0 {
		if a.kind() != scopedAccess {
			panic("apiv0: " + op.OperationID + " has token rules but no scopes")
		}

		names := make([]string, len(a.rules))
		for i, r := range a.rules {
			if !slices.Contains(tokenRules, r) {
				panic(
					"apiv0: " + op.OperationID + " has token rule " + r.name + ", which tokenRules does not list",
				)
			}

			names[i] = r.name
		}

		if op.Extensions == nil {
			op.Extensions = map[string]any{}
		}

		op.Extensions[tokenRulesExtension] = names
	}

	if len(a.paramScopes) > 0 {
		if a.kind() != scopedAccess {
			panic("apiv0: " + op.OperationID + " has parameter scopes but no scopes")
		}

		byParam := map[string][]string{}

		for param, ss := range a.paramScopes {
			for _, s := range ss {
				if !s.Valid() {
					panic(
						"apiv0: " + op.OperationID + " has unknown scope " + string(s),
					)
				}

				byParam[param] = append(byParam[param], string(s))
			}
		}

		if op.Extensions == nil {
			op.Extensions = map[string]any{}
		}

		op.Extensions[paramScopesExtension] = byParam
	}

	return all
}

// requestCodes checks the body of op against I and returns the codes the
// request of I can answer: its body, its page, a PATCH and a path parameter.
func requestCodes[I any](op *huma.Operation) ([]Code, bool) {
	var all []Code

	body, hasBody := reflect.TypeFor[I]().FieldByName("Body")
	if hasBody {
		// huma's default is 1 MiB; each operation states its own.
		if op.MaxBodyBytes <= 0 || op.MaxBodyBytes > maxBodyCeiling {
			panic(
				"apiv0: " + op.OperationID + " takes a body and sets no MaxBodyBytes between 1 and " + strconv.Itoa(
					maxBodyCeiling,
				),
			)
		}

		checkBody(op.OperationID, body.Type, op.Method == http.MethodPatch)

		all = append(
			all,
			CodeInvalidRequest,
			CodeTooLarge,
			CodeUnsupportedMediaType,
			CodeRequestTimeout,
		)
	}

	if f, ok := reflect.TypeFor[I]().FieldByName("PageQuery"); ok && f.Anonymous &&
		f.Type == reflect.TypeFor[PageQuery]() {
		all = append(all, CodeInvalidPageToken)
	}

	if op.Method == http.MethodPatch {
		if !hasBody {
			panic("apiv0: " + op.OperationID + " is a PATCH without a body")
		}

		all = append(all, CodeEmptyPatch)
	}

	if strings.Contains(op.Path, "{") {
		all = append(all, CodeNotFound)
	}

	return all, hasBody
}

// knownCodes is all sorted with no repeat; a code codes does not list panics.
func knownCodes(operationID string, all []Code) []Code {
	slices.Sort(all)
	all = slices.Compact(all)

	for _, c := range all {
		if _, ok := codes[c]; !ok {
			panic("apiv0: " + operationID + " declares unknown code " + string(c))
		}
	}

	return all
}

// describeCodes records a and all on op for the credential check and the
// guard, and documents a problem answer for each status in all.
func describeCodes(api huma.API, op *huma.Operation, a access, all []Code) {
	if op.Metadata == nil {
		op.Metadata = map[string]any{}
	}

	op.Metadata[accessMetaKey] = a
	op.Metadata[maxBodyMetaKey] = op.MaxBodyBytes
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
}

// describeRegistered documents what exists only once huma registered op:
// the merge patch media type and the headers of the success answer.
func describeRegistered(api huma.API, op *huma.Operation, isPatch bool) {
	registered := operations(api.OpenAPI().Paths[op.Path])[op.Method]

	// RFC 7396's media type; huma reads any +json body as JSON.
	if isPatch {
		registered.RequestBody.Content[mergePatchContentType] = registered.RequestBody.Content["application/json"]
	}

	// The success answer exists only now; it carries the headers too.
	for _, r := range registered.Responses {
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

// notUserID is the message of a userId, or a user query, that is not an ID.
const notUserID = "is not a user ID"

// userIDField is where a body names a user.
const userIDField = "body.userId"

// hasControlCharacter is the message of a text that [types.ValidateUserText]
// refuses.
const hasControlCharacter = "has a control character or a bidirectional formatting character"

// pathID reads the ID of a resource in a path. Only the form a server
// writes names a resource: decimal digits with no sign and no leading zero,
// from 1 to the largest int64, which is what the database stores. Anything
// else names nothing, a name included: not_found, with no object, which
// would copy the request back.
func pathID[T ~uint64](s string) (T, error) {
	id, err := strconv.ParseUint(s, 10, 63)
	if err != nil || id == 0 || strconv.FormatUint(id, 10) != s {
		return 0, newProblem(
			CodeNotFound,
			"Nothing has this ID. A path takes the ID, never the name.",
		)
	}

	return T(id), nil
}

// requestChecks refuses, after the credential is checked, what the request
// alone shows and huma lets through. A query parameter given twice or with
// an empty value is invalid_field: either would make a filter fall away and
// a list return every row. A boolean is true or false: huma would also take
// 1, t or TRUE, which a later version could not refuse. A body not sent as
// JSON is unsupported_media_type: huma reads a body with no media type, and
// any +json one, as JSON.
func requestChecks(ctx huma.Context, next func(huma.Context)) {
	if errs, _ := ctx.Context().Value(queryErrorsKey).([]FieldError); len(errs) > 0 {
		p := newProblem(CodeInvalidField, "The query is not valid percent-encoding.")
		p.Errors = errs
		writeHumaProblem(ctx, p)

		return
	}

	u := ctx.URL()
	query := u.Query()
	op := ctx.Operation()
	p := newProblem(CodeInvalidField, "A query parameter is not valid.")

	for _, name := range slices.Sorted(maps.Keys(query)) {
		switch {
		case len(query[name]) > 1:
			p.Errors = append(
				p.Errors,
				FieldError{
					Location: fieldLocation("query." + name),
					Message:  "is given more than once",
				},
			)
		case query[name][0] == "":
			p.Errors = append(
				p.Errors,
				FieldError{
					Location: fieldLocation("query." + name),
					Message:  "is empty; leave the parameter out",
				},
			)
		case booleanQuery(op, name) && query[name][0] != "true" && query[name][0] != "false":
			p.Errors = append(
				p.Errors,
				FieldError{
					Location: fieldLocation("query." + name),
					Message:  "is not true or false",
				},
			)
		}
	}

	if len(p.Errors) > 0 {
		writeHumaProblem(ctx, p)

		return
	}

	if op.RequestBody != nil && !jsonMediaType(ctx.Header("Content-Type"), op) {
		writeHumaProblem(
			ctx,
			newProblem(
				CodeUnsupportedMediaType,
				"Send the body as application/json, a PATCH as application/merge-patch+json, or another media type the operation lists.",
			),
		)

		return
	}

	next(ctx)
}

// booleanQuery reports whether op takes the query parameter name as a
// boolean.
func booleanQuery(op *huma.Operation, name string) bool {
	return slices.ContainsFunc(op.Parameters, func(p *huma.Param) bool {
		return p.In == "query" && p.Name == name && p.Schema != nil &&
			p.Schema.Type == huma.TypeBoolean
	})
}

// jsonMediaType reports whether a body sent as contentType is v0's JSON:
// application/json, or for a PATCH also RFC 7396's media type, or another
// media type op lists for its body, with no parameter but charset=utf-8.
func jsonMediaType(contentType string, op *huma.Operation) bool {
	mt, params, err := mime.ParseMediaType(contentType)
	if err != nil {
		return false
	}

	for k, v := range params {
		if k != "charset" || !strings.EqualFold(v, "utf-8") {
			return false
		}
	}

	_, listed := op.RequestBody.Content[mt]

	return mt == "application/json" ||
		(op.Method == http.MethodPatch && mt == mergePatchContentType) ||
		listed
}

// unknownMember starts the error of a member that the strict decode of a
// body does not know; fromHumaError reads the location after it.
const unknownMember = "unknown member at "

var errUnknownMember = errors.New(unknownMember)

// bodyFormat decodes v0's bodies with JSON v2. huma's validator matches a
// member name without regard to case, and keeps another duplicate than
// encoding/json does; ValidateStrictCasing would change all three APIs in
// the process. Here a name given twice, and text that is not UTF-8, cannot
// be read (invalid_request). The typed decode matches names exactly and
// refuses a member the type does not have, so a name in another case, which
// the validator let through, is invalid_field and never reaches a handler.
var bodyFormat = huma.Format{
	Marshal: huma.DefaultJSONFormat.Marshal,
	Unmarshal: func(data []byte, v any) error {
		err := jsonv2.Unmarshal(data, v, jsonv2.RejectUnknownMembers(true))

		se, ok := errors.AsType[*jsonv2.SemanticError](err)
		if ok && errors.Is(se.Err, jsonv2.ErrUnknownName) {
			return fmt.Errorf("%w%s", errUnknownMember, bodyLocation(se.JSONPointer))
		}

		return err
	},
}

// bodyLocation is a JSON pointer into a body as a location: body.a.b[2].
func bodyLocation(ptr jsontext.Pointer) string {
	var b strings.Builder

	b.WriteString("body")

	for tok := range ptr.Tokens() {
		if tok != "" && strings.Trim(tok, "0123456789") == "" {
			b.WriteString("[" + tok + "]")
		} else {
			b.WriteString("." + tok)
		}
	}

	return b.String()
}

// fieldChecker is a body that checks its own fields beyond its schema.
// register runs it before the handler, so a bad field is answered before
// the resource of the path is looked up.
type fieldChecker interface {
	fieldErrors() []FieldError
}

// checkBody refuses a body that could take null for a value, at any depth.
// huma's validation lets null through for a field that is not required, and
// the decoder makes it the zero value, so null would pass as "" or as
// "clear". A field is therefore required, or an [Optional] left out when
// zero, which sees the null; a pointer is never a field. In a PATCH every
// field is an Optional, so that a field left out and a field cleared differ.
func checkBody(id string, t reflect.Type, patch bool) {
	for f := range t.Fields() {
		if f.Anonymous && f.Type.Kind() == reflect.Struct {
			checkBody(id, f.Type, patch)

			continue
		}

		where := "apiv0: " + id + ": body field " + t.Name() + "." + f.Name
		optional := f.Type.Implements(optionalFieldType)

		switch {
		case f.Tag.Get("null") == "absent" && (patch || !optional || f.Tag.Get("nullable") == "true"):
			// In a PATCH null clears a value; reading it as left out would
			// keep the value, and a body of one null would change nothing.
			panic(
				where + ` reads null as left out, which only an Optional that refuses null, outside a PATCH, may`,
			)
		case optional && !strings.Contains(f.Tag.Get("json"), ",omitzero"):
			panic(where + " is an Optional without omitzero")
		case patch && !optional:
			panic(where + " must be an Optional tagged omitzero in a PATCH")
		case optional:
		case !requiredField(f):
			panic(where + " is not required, so it must be an Optional")
		case f.Tag.Get("nullable") == "true":
			panic(where + " takes null, so it must be an Optional")
		}

		inner := f.Type
		if optional {
			v, _ := f.Type.FieldByName("Value")
			inner = v.Type
		}

		for inner.Kind() == reflect.Slice || inner.Kind() == reflect.Array || inner.Kind() == reflect.Map {
			inner = inner.Elem()
		}

		switch {
		case inner.Kind() == reflect.Pointer || inner.Kind() == reflect.Interface:
			panic(where + " holds a pointer or an interface; use Optional")
		case inner.Kind() == reflect.Struct && !decodesItself(inner):
			checkBody(id, inner, false)
		}
	}
}

// requiredField is huma's rule: a field is required unless its JSON tag has
// omitempty or omitzero, and a required tag overrides both.
func requiredField(f reflect.StructField) bool {
	if v, ok := f.Tag.Lookup("required"); ok {
		return v == "true"
	}

	json := f.Tag.Get("json")

	return !strings.Contains(json, ",omitempty") && !strings.Contains(json, ",omitzero")
}

// decodesItself is a type with its own JSON or text decoding, such as
// time.Time, whose fields the body does not hold.
func decodesItself(t reflect.Type) bool {
	p := reflect.PointerTo(t)

	return p.Implements(reflect.TypeFor[json.Unmarshaler]()) ||
		p.Implements(reflect.TypeFor[encoding.TextUnmarshaler]()) ||
		p.Implements(reflect.TypeFor[jsonv2.UnmarshalerFrom]())
}

// problemChecker is a body that the body alone shows wrong with a code of
// its operation, such as owner_conflict. register runs it after
// [fieldChecker], before a token rule.
type problemChecker interface {
	problem() *Problem
}

// bodyProblem refuses null for a field not tagged nullable:"true", at any
// depth, and reads it as left out for one tagged null:"absent"; then a
// PATCH body that sends no field; then the fields that the body checks
// itself; and then its own codes.
func bodyProblem(in any, patch bool) *Problem {
	body := reflect.ValueOf(in).Elem().FieldByName("Body")
	p := newProblem(CodeInvalidField, "A field cannot be null.")
	nulls(body, "body", patch, &p.Errors)

	if len(p.Errors) > 0 {
		return p
	}

	if patch && !anySet(body) {
		return newProblem(
			CodeEmptyPatch,
			"The body changes no field; send at least one.",
		)
	}

	if c, ok := reflect.TypeAssert[fieldChecker](body.Addr()); ok {
		p = newProblem(CodeInvalidField, "A field is not valid.")
		p.Errors = c.fieldErrors()

		if len(p.Errors) > 0 {
			return p
		}
	}

	if c, ok := reflect.TypeAssert[problemChecker](body.Addr()); ok {
		return c.problem()
	}

	return nil
}

// anySet reports whether a PATCH body sends a field.
func anySet(body reflect.Value) bool {
	for _, field := range body.Fields() {
		if f, ok := reflect.TypeAssert[optionalField](field); ok && f.isSet() {
			return true
		}
	}

	return false
}

// nulls adds an error for each null in v, at loc, that its field does not
// allow.
func nulls(v reflect.Value, loc string, patch bool, errs *[]FieldError) {
	switch v.Kind() { //nolint:exhaustive // only containers hold a null
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			nulls(v.Index(i), loc+"["+strconv.Itoa(i)+"]", patch, errs)
		}
	case reflect.Map:
		for _, k := range v.MapKeys() {
			nulls(v.MapIndex(k), loc+"."+fmt.Sprint(k.Interface()), patch, errs)
		}
	case reflect.Struct:
		if decodesItself(v.Type()) {
			return
		}

		for i := range v.NumField() {
			sf := v.Type().Field(i)
			if sf.Anonymous {
				nulls(v.Field(i), loc, patch, errs)

				continue
			}

			name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")
			at := loc + "." + name

			f, ok := reflect.TypeAssert[optionalField](v.Field(i))
			if !ok {
				nulls(v.Field(i), at, patch, errs)

				continue
			}

			switch {
			case f.isNull() && sf.Tag.Get("null") == "absent":
				// The operation answers a missing field with its own code;
				// telling the client to leave the field out would send it in
				// a circle.
				v.Field(i).SetZero()
			case f.isNull() && sf.Tag.Get("nullable") != "true":
				*errs = append(
					*errs,
					FieldError{Location: at, Message: nullMessage(sf.Type, patch)},
				)
			case f.isSet() && !f.isNull():
				nulls(v.Field(i).FieldByName("Value"), at, patch, errs)
			}
		}
	}
}

// nullMessage tells the client what to send in place of a null.
func nullMessage(optional reflect.Type, patch bool) string {
	v, _ := optional.FieldByName("Value")

	switch {
	case !patch:
		return "cannot be null; leave the field out"
	case v.Type.Kind() == reflect.String:
		return "cannot be null; send \"\" to clear it"
	default:
		return "cannot be null"
	}
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
