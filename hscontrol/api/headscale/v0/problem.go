package apiv0

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog/log"
)

// Code is the stable, machine-readable kind of a [Problem]. Changing one is a
// breaking change.
type Code string

const (
	CodeUnauthorized         Code = "unauthorized"
	CodeForbidden            Code = "forbidden"
	CodeNotFound             Code = "not_found"
	CodeInvalidRequest       Code = "invalid_request"
	CodeMethodNotAllowed     Code = "method_not_allowed"
	CodeRequestTimeout       Code = "request_timeout"
	CodeTooLarge             Code = "too_large"
	CodeUnsupportedMediaType Code = "unsupported_media_type"
	CodeInvalidField         Code = "invalid_field"
	CodeInvalidPageToken     Code = "invalid_page_token"
	CodeEmptyPatch           Code = "empty_patch"
	CodeNameTaken            Code = "name_taken"
	CodeEmailTaken           Code = "email_taken"
	CodeUserManagedByOIDC    Code = "user_managed_by_oidc"
	CodeUnhealthy            Code = "unhealthy"
	CodeInternal             Code = "internal"
)

// codeInfo is what a code means. when and details are for the page of codes,
// docs/ref/api/problems.md, which is made from this table.
type codeInfo struct {
	status  int
	title   string
	when    string
	details []string
}

// codes is every code v0 answers.
var codes = map[Code]codeInfo{
	CodeUnauthorized: {
		http.StatusUnauthorized, "The request has no valid credential",
		"No credential, or it is unknown, expired or revoked.", nil,
	},
	CodeForbidden: {
		http.StatusForbidden,
		"The credential may not do this",
		"The token lacks a scope the operation needs, or breaks a token rule.",
		[]string{
			"`scopes`: every scope the token lacks; `[]` when a rule refused it",
			"`rule`: a short word naming the token rule that refused it; `null` when a scope is missing",
		},
	},
	CodeNotFound: {
		http.StatusNotFound,
		"The resource does not exist",
		"The resource does not exist, or no longer exists; also a path that no operation has.",
		nil,
	},
	CodeInvalidRequest: {
		http.StatusBadRequest,
		"The request cannot be read",
		"The body is not valid JSON.",
		nil,
	},
	CodeMethodNotAllowed: {
		http.StatusMethodNotAllowed,
		"The method is not allowed on this path",
		"The path exists, the method does not. The `Allow` header lists the methods it takes.",
		nil,
	},
	CodeRequestTimeout: {
		http.StatusRequestTimeout, "The body did not arrive in time",
		"The request did not arrive in time.", nil,
	},
	CodeTooLarge: {
		http.StatusRequestEntityTooLarge,
		"The body is too large",
		"The body is over the limit of the operation.",
		nil,
	},
	CodeUnsupportedMediaType: {
		http.StatusUnsupportedMediaType,
		"The body is not JSON",
		"The body is not JSON.",
		nil,
	},
	CodeInvalidField: {
		http.StatusUnprocessableEntity,
		"A field or parameter is not valid",
		"A field or parameter is unknown, or has a value that is not allowed. `errors` names each one.",
		nil,
	},
	CodeInvalidPageToken: {
		http.StatusUnprocessableEntity,
		"The page token is not valid",
		"The page token was not made by this server, is for another list or other filters, or is from before a restart. Start again from the first page.",
		nil,
	},
	CodeEmptyPatch: {
		http.StatusUnprocessableEntity,
		"The patch changes nothing",
		"A `PATCH` with no fields.",
		nil,
	},
	CodeNameTaken: {
		http.StatusConflict,
		"The name is taken",
		"The name belongs to another node or user; `object` is that one. The name of a local user is also taken when it equals the email or the provider identifier of another user, without regard to case.",
		[]string{
			"`name`: the name that is taken, as the request sent it; `object` names the holder as messages do, which for a user can be its email",
		},
	},
	CodeEmailTaken: {
		http.StatusConflict,
		"The email is taken",
		"The email of a local user equals the name, the email or the provider identifier of another user, without regard to case. A policy names a user by these texts. `object` is that user.",
		[]string{"`email`: the email that is taken, as the request sent it"},
	},
	CodeUserManagedByOIDC: {
		http.StatusConflict,
		"The identity provider owns this user",
		"A change to a user from OIDC, whose fields the identity provider owns. `object` is the user.",
		nil,
	},
	CodeUnhealthy: {
		http.StatusServiceUnavailable,
		"The server is not healthy",
		"A check of the server fails: `GET /health`, and any call whose credential cannot be checked because the database does not answer.",
		[]string{
			"`reasons`: one entry for each failed check, `{code, message, details}`; the codes are under [Reasons of unhealthy](#reasons)",
		},
	},
	CodeInternal: {
		http.StatusInternalServerError,
		"The server failed",
		"A fault in the server. The server log has it, under the `requestId`.",
		nil,
	},
}

// Schema lists the codes in the document, so a client author finds them. A
// client must still accept a code it does not know.
func (Code) Schema(huma.Registry) *huma.Schema {
	all := slices.Sorted(maps.Keys(codes))
	enum := make([]any, len(all))

	for i, c := range all {
		enum[i] = string(c)
	}

	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

// statusCodes maps the statuses huma answers by itself to their code.
// TestHumaStatuses holds the list of those statuses.
var statusCodes = map[int]Code{
	http.StatusBadRequest:            CodeInvalidRequest,
	http.StatusNotFound:              CodeNotFound,
	http.StatusRequestTimeout:        CodeRequestTimeout,
	http.StatusRequestEntityTooLarge: CodeTooLarge,
	http.StatusUnsupportedMediaType:  CodeUnsupportedMediaType,
	http.StatusUnprocessableEntity:   CodeInvalidField,
	http.StatusInternalServerError:   CodeInternal,
}

const (
	problemContentType = "application/problem+json"
	problemTypeBase    = "https://headscale.net/stable/ref/api/problems/#"

	// maxFieldErrors caps errors: huma reports one per bad element of a body.
	maxFieldErrors = 20
)

// Problem is the body of every v0 error, an RFC 9457 problem with the
// extension members code, requestId, object, errors and details.
type Problem struct { //nolint:errname // the name of RFC 9457, and of the schema
	Type      string         `doc:"A URL naming the problem, one per code; it leads to its documentation." json:"type"`
	Title     string         `doc:"A short text, the same for every problem with this code."               json:"title"`
	Status    int            `doc:"The HTTP status."                                                       json:"status"`
	Code      Code           `doc:"The stable code of the problem. Clients branch on this."                json:"code"`
	Detail    string         `doc:"A sentence for a person. It may change; programs must not read it."     json:"detail"`
	RequestID string         `doc:"The ID of this request in the server log."                              json:"requestId"`
	Object    *ProblemObject `doc:"The resource the problem is about, or null."                            json:"object"`
	Errors    []FieldError   `doc:"For invalid_field: one entry per field."                                json:"errors"    nullable:"false"`
	Details   map[string]any `doc:"Data for this code, as its documentation describes."                    json:"details"`
}

// ProblemObject names the resource a [Problem] is about.
type ProblemObject struct {
	_    struct{} `nullable:"true"`
	Kind string   `enum:"node,user,authKey,apiKey,oauthClient,authRequest" json:"kind"`
	ID   string   `json:"id"`
	Name string   `json:"name"`
}

// FieldError is one field or parameter that is not valid.
type FieldError struct {
	Location string `doc:"Where the field is, such as body.tags[2] or query.pageSize." json:"location"`
	Message  string `json:"message"`
}

// HealthMessage is a code with a sentence and its data, the shape of a health
// warning and of a reason in the unhealthy problem.
type HealthMessage struct {
	Code    HealthCode     `json:"code"`
	Message string         `json:"message"`
	Details map[string]any `doc:"Data for this code; {} when it has none." json:"details"`
}

// newProblem builds the problem of c. An unknown code is a fault in v0; it
// answers internal rather than a status of 0.
func newProblem(c Code, detail string) *Problem {
	info, ok := codes[c]
	if !ok {
		log.Error().Str("code", string(c)).Msg("api v0: problem with an unknown code")

		c, info, detail = CodeInternal, codes[CodeInternal], ""
	}

	return &Problem{
		Type:    problemTypeBase + string(c),
		Title:   info.title,
		Status:  info.status,
		Code:    c,
		Detail:  detail,
		Errors:  []FieldError{},
		Details: map[string]any{},
	}
}

// ruleForbidden is the problem of a token that a token rule refuses.
func ruleForbidden(r *tokenRule) *Problem {
	p := newProblem(CodeForbidden, r.why)
	p.Details["scopes"] = []string{}
	p.Details["rule"] = r.name

	return p
}

// forbidden is the problem of a token that lacks scopes.
func forbidden(missing []string) *Problem {
	p := newProblem(
		CodeForbidden,
		"The token lacks the scopes "+strings.Join(missing, ", ")+".",
	)
	p.Details["scopes"] = missing
	p.Details["rule"] = nil

	return p
}

func (p *Problem) Error() string { return string(p.Code) + ": " + p.Detail }

func (p *Problem) GetStatus() int { return p.Status }

func (p *Problem) ContentType(string) string { return problemContentType }

// answer is a code an operation answers of its own. With err set, a
// handler error that is err (errors.Is) answers code with detail; without
// it, the handler returns the *Problem itself. Each operation states its
// answers, so the next resource maps its own errors and inherits none.
type answer struct {
	code   Code
	err    error
	detail string
}

// onError is the answer to a handler error that is err.
func onError(err error, c Code, detail string) answer {
	return answer{code: c, err: err, detail: detail}
}

// mapError is the one path from a handler error to the wire. A *Problem
// with a code the operation declared passes, and so does an error that one
// of own maps; anything else is logged and answered as internal, without
// its text.
func mapError(ctx context.Context, err error, declared []Code, own []answer) error {
	p, ok := errors.AsType[*Problem](err)
	if !ok {
		for _, a := range own {
			if a.err != nil && errors.Is(err, a.err) {
				p = newProblem(a.code, a.detail)

				break
			}
		}
	}

	if p != nil && slices.Contains(declared, p.Code) {
		if oe, ok := errors.AsType[*objectError](err); ok && p.Object == nil {
			p.Object = &oe.obj
		}

		if de, ok := errors.AsType[*detailsError](err); ok {
			maps.Copy(p.Details, de.details)
		}

		return p
	}

	log.Error().
		Err(err).
		Str(zf.RequestID, middleware.GetReqID(ctx)).
		Msg("api v0: internal error")

	return newProblem(CodeInternal, "")
}

// objectError is an error with the resource it is about.
type objectError struct {
	err error
	obj ProblemObject
}

func (e *objectError) Error() string { return e.err.Error() }

func (e *objectError) Unwrap() error { return e.err }

// detailsError is an error with data for the details of its problem.
type detailsError struct {
	err     error
	details map[string]any
}

func (e *detailsError) Error() string { return e.err.Error() }

func (e *detailsError) Unwrap() error { return e.err }

// about is err with the resource it is about; the problem it maps to names
// obj.
func about(err error, obj ProblemObject) error {
	return &objectError{err: err, obj: obj}
}

// problemTransformer turns huma's own errors (validation, body limits,
// unknown parameters) into a [Problem] and stamps the request ID on every
// problem. Other bodies pass.
func problemTransformer(ctx huma.Context, _ string, v any) (any, error) {
	switch v := v.(type) {
	case *Problem:
		v.RequestID = middleware.GetReqID(ctx.Context())
		challenge(ctx, v)

		return v, nil
	case *huma.ErrorModel:
		p := fromHumaError(v)
		p.RequestID = middleware.GetReqID(ctx.Context())

		return p, nil
	default:
		return v, nil
	}
}

// humaMessages are the starts of huma's own messages, which are fixed text.
// Huma also puts Go error text (a JSON decoder, a parser) into messages;
// those become notValid, and a kept message ends before ": ", where huma
// appends one.
var humaMessages = []string{
	"expected ",
	"unexpected property",
	"unknown query parameter",
	"required ",
	"invalid JSON",
}

const notValid = "is not valid"

func fromHumaError(em *huma.ErrorModel) *Problem {
	c, ok := statusCodes[em.Status]
	if !ok {
		// TestHumaStatuses keeps this from happening with the pinned huma.
		log.Warn().
			Int("status", em.Status).
			Msg("api v0: huma answered a status v0 has no code for")

		c = CodeInternal
	}

	// The detail is ours: huma's can hold a Go error text.
	p := newProblem(c, codes[c].title+".")

	// Only invalid_field names fields; the errors of the others are a Go
	// error's text.
	if c != CodeInvalidField {
		return p
	}

	for _, d := range em.Errors {
		// huma keeps a nil detail for a nil error. Value is dropped: for an
		// unknown field it holds the whole body.
		if d == nil {
			continue
		}

		// A resolver gives a field error of its own. The schema's failure at
		// the same place, which comes first, already names the field.
		if f, ok := d.Value.(FieldError); ok {
			if !slices.ContainsFunc(
				p.Errors,
				func(prev FieldError) bool { return prev.Location == f.Location },
			) {
				p.Errors = append(p.Errors, f)
			}

			continue
		}

		// The strict decode of bodyFormat names the member in its message.
		if at, ok := strings.CutPrefix(
			d.Message,
			unknownMember,
		); ok &&
			d.Location == "body" {
			p.Errors = append(
				p.Errors,
				FieldError{Location: fieldLocation(at), Message: "unexpected property"},
			)

			continue
		}

		p.Errors = append(
			p.Errors,
			FieldError{
				Location: fieldLocation(d.Location),
				Message:  humaMessage(d.Message),
			},
		)
	}

	// The cap counts what is left after a repeat is dropped.
	if more := len(p.Errors) - maxFieldErrors; more > 0 {
		p.Errors = append(
			p.Errors[:maxFieldErrors],
			FieldError{Message: "and " + strconv.Itoa(more) + " more"},
		)
	}

	return p
}

// maxLocation bounds a location: the name of an unknown field is the
// client's own text.
const maxLocation = 64

// fieldLocation is l as safe to send back and log: printable ASCII, at most
// maxLocation characters, enough for the CLI to say which field it was.
func fieldLocation(l string) string {
	out := []rune(strings.Map(func(r rune) rune {
		if r < ' ' || r > '~' {
			return '?'
		}

		return r
	}, l))

	return string(out[:min(len(out), maxLocation)])
}

func humaMessage(m string) string {
	if !slices.ContainsFunc(
		humaMessages,
		func(h string) bool { return strings.HasPrefix(m, h) },
	) {
		return notValid
	}

	m, _, _ = strings.Cut(m, ": ")

	return m
}

// writeProblem answers p outside huma: the router's unknown path and wrong
// method.
func writeProblem(w http.ResponseWriter, r *http.Request, p *Problem) {
	p.RequestID = middleware.GetReqID(r.Context())

	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(p.Status)
	//nolint:errchkjson // the status is sent; a failed write has no one to tell
	_ = json.NewEncoder(w).Encode(p)
}

// writeHumaProblem answers p from a huma middleware, which runs before the
// transformer.
func writeHumaProblem(ctx huma.Context, p *Problem) {
	p.RequestID = middleware.GetReqID(ctx.Context())
	challenge(ctx, p)

	ctx.SetHeader("Content-Type", problemContentType)
	ctx.SetStatus(p.Status)
	//nolint:errchkjson // the status is sent; a failed write has no one to tell
	_ = json.NewEncoder(ctx.BodyWriter()).Encode(p)
}

// challenge sends the scheme a 401 asks for, as RFC 9110 requires.
func challenge(ctx huma.Context, p *Problem) {
	if p.Status == http.StatusUnauthorized {
		ctx.SetHeader("WWW-Authenticate", "Bearer")
	}
}

// HealthCode is the stable code of a health warning or reason. New codes may
// come in any release; a client must accept one it does not know.
type HealthCode string

// The reasons of the unhealthy problem.
const (
	ReasonDatabaseUnreachable HealthCode = "database_unreachable"
	//nolint:gosec // a code, not a secret
	ReasonCredentialCheckBusy HealthCode = "credential_check_busy"
)

// healthReasons is the message of each reason, also on the page of codes.
var healthReasons = map[HealthCode]string{ //nolint:gosec // messages, not secrets
	ReasonDatabaseUnreachable: "The database does not answer.",
	ReasonCredentialCheckBusy: "Every slot for checking an old-format credential hash stayed busy, so the credential was not checked.",
}

// healthCodes are the codes of today, reasons and warnings, listed in the
// document.
var healthCodes = []HealthCode{
	ReasonCredentialCheckBusy,
	ReasonDatabaseUnreachable,
	"node_expiry_invalid",
	"node_name_invalid",
}

func (HealthCode) Schema(huma.Registry) *huma.Schema {
	enum := make([]any, len(healthCodes))
	for i, c := range healthCodes {
		enum[i] = string(c)
	}

	return &huma.Schema{Type: huma.TypeString, Enum: enum}
}

// ProblemsPage is docs/ref/api/problems.md, where the type of every problem
// leads: one heading for each code, made from [codes].
func ProblemsPage() []byte {
	var b strings.Builder

	b.WriteString(`# API v0 problem codes

!!! note "Generated page"

    This page is generated from the list of codes in ` + "`hscontrol/api/headscale/v0/problem.go`" + ` by
    ` + "`go run ./cmd/gen-openapi -api headscale/v0`" + `. Edit the list there, not this page.

Every error of ` + "`/api/headscale/v0`" + ` is a problem (RFC 9457). A program reads its ` + "`code`" + `; the
` + "`type`" + ` of the problem leads to the heading of that code here. ` + "`details`" + ` holds the data of the
code, and is ` + "`{}`" + ` when the code has none.
`)

	for _, c := range slices.Sorted(maps.Keys(codes)) {
		info := codes[c]

		fmt.Fprintf(&b, "\n## %s { #%s }\n\n", c, c)
		fmt.Fprintf(&b, "- **Status:** %d\n", info.status)
		fmt.Fprintf(&b, "- **Title:** %s\n", info.title)
		fmt.Fprintf(&b, "- **When:** %s\n", info.when)

		if len(info.details) == 0 {
			b.WriteString("- **`details`:** `{}`\n")

			continue
		}

		b.WriteString("- **`details`:**\n")

		for _, d := range info.details {
			fmt.Fprintf(&b, "    - %s\n", d)
		}
	}

	b.WriteString(
		"\n## Token rules { #rules }\n\nThe `rule` of a `forbidden` problem: what an OAuth access token may not do although its scopes allow it. An API key and the unix socket are not held by these rules. The OpenAPI document lists the rules of each operation under `x-token-rules`.\n",
	)

	for _, r := range slices.SortedFunc(slices.Values(tokenRules), func(a, b *tokenRule) int { return strings.Compare(a.name, b.name) }) {
		fmt.Fprintf(&b, "\n### %s { #%s }\n\n%s\n", r.name, r.name, r.why)
	}

	b.WriteString(
		"\n## Reasons of unhealthy { #reasons }\n\nThe `code` of each entry in `details.reasons`. A client must accept one it does not know.\n",
	)

	for _, r := range slices.Sorted(maps.Keys(healthReasons)) {
		fmt.Fprintf(&b, "\n### %s { #%s }\n\n%s\n", r, r, healthReasons[r])
	}

	return []byte(b.String())
}
