package apiv1

import (
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"gorm.io/gorm"
)

// Status is the error body of /api/v1 as 0.29 sent it: a google.rpc.Status
// written by the grpc-gateway (protojson with EmitUnpopulated). 0.29 never set
// details, so it is always empty. Web UIs read message, and tell an error
// from a result by the presence of code.
type Status struct {
	Code    int32  `doc:"gRPC status code"                       json:"code"`
	Message string `json:"message"`
	Details []any  `doc:"Always empty; kept for the 0.29 shape." json:"details" nullable:"false"`
}

// gRPC status codes, google.golang.org/grpc/codes.
const (
	codeUnknown          int32 = 2
	codeInvalidArgument  int32 = 3
	codeDeadlineExceeded int32 = 4
	codeNotFound         int32 = 5
	codeAlreadyExists    int32 = 6
	codePermissionDenied int32 = 7
	codeResourceExhaust  int32 = 8
	codeUnimplemented    int32 = 12
	codeUnavailable      int32 = 14
	codeUnauthenticated  int32 = 16
)

// grpcCode is the code that the gateway's HTTPStatusFromCode turns into
// status, so code and status agree as they did in 0.29. A 500 is Unknown, what
// 0.29 sent for the plain Go errors behind most of its 500s.
func grpcCode(status int) int32 {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return codeInvalidArgument
	case http.StatusUnauthorized:
		return codeUnauthenticated
	case http.StatusForbidden:
		return codePermissionDenied
	case http.StatusNotFound:
		return codeNotFound
	case http.StatusConflict:
		return codeAlreadyExists
	// gRPC refuses an oversized message with ResourceExhausted.
	case http.StatusRequestEntityTooLarge, http.StatusTooManyRequests:
		return codeResourceExhaust
	case http.StatusNotImplemented:
		return codeUnimplemented
	case http.StatusServiceUnavailable:
		return codeUnavailable
	case http.StatusGatewayTimeout:
		return codeDeadlineExceeded
	default:
		return codeUnknown
	}
}

// statusMessage joins the problem's detail and its errors as the CLI showed
// them, dropping repeats: handlers often pass the error as both.
func statusMessage(em *huma.ErrorModel) string {
	var parts []string

	add := func(s string) {
		if s != "" && (len(parts) == 0 || parts[len(parts)-1] != s) {
			parts = append(parts, s)
		}
	}

	add(em.Detail)

	for _, d := range em.Errors {
		// huma stores a nil detail for a nil error argument.
		if d == nil {
			continue
		}

		// The value is not echoed: for a bad body it can be the whole request.
		if d.Location != "" {
			add(d.Message + " (" + d.Location + ")")
		} else {
			add(d.Message)
		}
	}

	if len(parts) == 0 {
		return em.Title
	}

	return strings.Join(parts, ": ")
}

// grpcStatusTransformer rewrites every Huma error into the 0.29 Status body.
// It is registered on the v1 API only.
func grpcStatusTransformer(ctx huma.Context, _ string, v any) (any, error) {
	em, ok := v.(*huma.ErrorModel)
	if !ok {
		return v, nil
	}

	ctx.SetHeader("Content-Type", "application/json")

	return Status{Code: grpcCode(em.Status), Message: statusMessage(em), Details: []any{}}, nil
}

// statusContext writes Huma's 422 as 400: 0.29 refused every malformed
// request with InvalidArgument.
type statusContext struct{ humaContext }

func (c statusContext) SetStatus(code int) {
	if code == http.StatusUnprocessableEntity {
		code = http.StatusBadRequest
	}

	c.humaContext.SetStatus(code)
}

func statusMiddleware(ctx huma.Context, next func(huma.Context)) {
	next(statusContext{ctx})
}

// routingError answers a path or method no operation serves as 0.29 did: its
// auth middleware ran before the gateway, so a caller without a valid key gets
// the 401 and learns nothing of the routes. Then the gateway's
// DefaultRoutingErrorHandler: 404 NotFound, and 501 Unimplemented for a
// method the path does not take. The message is the routing status's text.
func routingError(b Backend, routing, status int, code int32) http.HandlerFunc {
	// Status texts are ASCII, so %q quotes them as JSON does.
	body := fmt.Appendf(nil, `{"code":%d,"message":%q,"details":[]}`, code, http.StatusText(routing))

	return func(w http.ResponseWriter, r *http.Request) {
		local := r.Context().Value(localTrustKey{}) != nil
		if !authorized(local, r.Header.Get("Authorization"), b) {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))

			return
		}

		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(body)
	}
}

// writeUnauthorized is the 401 of 0.29's HTTP auth middleware, which ran
// before the gateway: plain text, not a Status. headscale-admin matches it.
func writeUnauthorized(ctx huma.Context) {
	ctx.SetHeader("Content-Type", "text/plain; charset=utf-8")
	ctx.SetStatus(http.StatusUnauthorized)
	_, _ = ctx.BodyWriter().Write([]byte("Unauthorized"))
}

// documentStatus makes the OpenAPI document describe the errors v1 sends:
// Status as JSON for every error response, plain text for a 401.
func documentStatus(oapi *huma.OpenAPI, op *huma.Operation) {
	ref := oapi.Components.Schemas.Schema(reflect.TypeFor[Status](), true, "Status")

	for code, resp := range op.Responses {
		if code != "default" {
			n, err := strconv.Atoi(code)
			if err != nil || n < http.StatusBadRequest {
				continue
			}
		}

		resp.Content = map[string]*huma.MediaType{"application/json": {Schema: ref}}
	}

	if len(op.Security) > 0 {
		op.Responses[strconv.Itoa(http.StatusUnauthorized)] = &huma.Response{
			Description: http.StatusText(http.StatusUnauthorized),
			Content: map[string]*huma.MediaType{
				"text/plain": {Schema: &huma.Schema{Type: huma.TypeString}},
			},
		}
	}
}

// mapError translates a state/db-layer error into a Huma HTTP error
// (NotFound→404, invalid input→400, conflict→409, everything else→500).
// Handlers use this default mapping and may return a more specific huma.ErrorN
// directly. msg is a human context prefix, e.g. "getting node".
func mapError(msg string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, types.ErrRegistrationPayloadTooLarge):
		return huma.Error413RequestEntityTooLarge(msg, err)

	case errors.Is(err, state.ErrAuthCacheFull),
		errors.Is(err, state.ErrAuthCacheClosed):
		return huma.Error503ServiceUnavailable(msg, err)

	case errors.Is(err, gorm.ErrRecordNotFound),
		errors.Is(err, state.ErrNodeNotFound),
		errors.Is(err, state.ErrNodeNotInNodeStore),
		errors.Is(err, db.ErrUserNotFound),
		errors.Is(err, db.ErrNodeNotFoundRegistrationCache),
		errors.Is(err, state.ErrRegistrationExpired):
		return huma.Error404NotFound(msg, err)

	case errors.Is(err, state.ErrGivenNameInvalid),
		errors.Is(err, state.ErrGivenNameTaken),
		errors.Is(err, state.ErrNodeNameNotUnique),
		errors.Is(err, state.ErrNodeMarkedTaggedButHasNoTags),
		errors.Is(err, state.ErrNodeHasNeitherUserNorTags),
		errors.Is(err, state.ErrRequestedTagsInvalidOrNotPermitted),
		errors.Is(err, types.ErrExpiryOutOfRange),
		errors.Is(err, types.ErrHostinfoTooLarge),
		errors.Is(err, db.ErrUserStillHasNodes),
		errors.Is(err, db.ErrCannotChangeOIDCUser),
		errors.Is(err, util.ErrUsernameTooShort),
		errors.Is(err, util.ErrUsernameMustStartLetter),
		errors.Is(err, util.ErrUsernameTooManyAt),
		errors.Is(err, util.ErrUsernameInvalidChar),
		errors.Is(err, db.ErrPreAuthKeyNotTaggedOrOwned),
		errors.Is(err, db.ErrSingleUseAuthKeyHasBeenUsed),
		errors.Is(err, state.ErrInvalidPolicy),
		errors.Is(err, state.ErrAuthRequestKind):
		return huma.Error400BadRequest(msg, err)

	// A unique index refused the write, e.g. a racing create or a rename to a
	// taken user name.
	case errors.Is(err, gorm.ErrDuplicatedKey),
		errors.Is(err, state.ErrNodeKeyInUse),
		errors.Is(err, state.ErrAmbiguousNodeOwnership),
		errors.Is(err, state.ErrAuthCacheEntryExists):
		return huma.Error409Conflict(msg, err)

	default:
		return huma.Error500InternalServerError(msg, err)
	}
}
