package apiv1

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/ogen-go/ogen/ogenerrors"
	"github.com/rs/zerolog/log"
	"gorm.io/gorm"
)

const problemContentType = "application/problem+json"

// apiError builds an RFC 7807 problem response with the given HTTP status and
// detail. Handlers return it so expected errors render as problem documents
// with the correct status code (ogen encodes [oas.ErrorStatusCode] directly,
// without going through [errorHandler]).
func apiError(status int, detail string) *oas.ErrorStatusCode {
	return &oas.ErrorStatusCode{
		StatusCode: status,
		Response: oas.Problem{
			Title: oas.NewOptString(http.StatusText(status)),
			//nolint:gosec // G115: status is an HTTP status code, always within int32.
			Status: oas.NewOptInt32(int32(status)),
			Detail: oas.NewOptString(detail),
		},
	}
}

func notFound(
	detail string,
) *oas.ErrorStatusCode {
	return apiError(http.StatusNotFound, detail)
}

func badRequest(
	detail string,
) *oas.ErrorStatusCode {
	return apiError(http.StatusBadRequest, detail)
}

func internalError(detail string) *oas.ErrorStatusCode {
	return apiError(http.StatusInternalServerError, detail)
}

// mapStateError classifies an error returned by the state layer into an HTTP
// problem response. Not-found sentinels become 404; everything else is a 500.
// Handlers that need a different status (e.g. validation 400) build the problem
// explicitly with [badRequest] rather than routing through here.
func mapStateError(err error) *oas.ErrorStatusCode {
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound),
		errors.Is(err, state.ErrNodeNotFound),
		errors.Is(err, state.ErrNodeNotInNodeStore),
		errors.Is(err, db.ErrUserNotFound):
		return notFound(err.Error())
	case errors.Is(err, types.ErrPolicyUpdateIsDisabled):
		return badRequest(err.Error())
	default:
		return internalError(err.Error())
	}
}

// NewError converts an error that ogen raises outside a handler return value —
// failed authentication, request decoding — into a typed problem response. ogen
// calls it from the generated security/decoding paths; the resulting
// [oas.ErrorStatusCode] is then encoded as application/problem+json.
func (s *Server) NewError(_ context.Context, err error) *oas.ErrorStatusCode {
	return classify(err)
}

// errorHandler renders problems for the remaining ogen error path: a plain
// error returned from a handler. Expected errors are returned as
// [oas.ErrorStatusCode] (encoded directly by ogen), so this is the safety net
// for anything else.
func errorHandler(
	_ context.Context,
	w http.ResponseWriter,
	_ *http.Request,
	err error,
) {
	writeProblem(w, classify(err))
}

// classify maps an arbitrary error to a problem response. An already-typed
// [oas.ErrorStatusCode] passes through; ogen's framework errors carry their own
// HTTP status via Code() (security -> 401, decode -> 400); everything else is
// classified by [mapStateError].
func classify(err error) *oas.ErrorStatusCode {
	var esc *oas.ErrorStatusCode
	if errors.As(err, &esc) {
		return esc
	}

	// A failed security requirement (missing/malformed bearer) must not echo
	// ogen's internal "operation X: security ...: not satisfied" message, which
	// leaks the operation name. Return a minimal 401.
	var secErr *ogenerrors.SecurityError
	if errors.As(err, &secErr) {
		return apiError(http.StatusUnauthorized, "valid API key required")
	}

	var coder interface{ Code() int }
	if errors.As(err, &coder) {
		return apiError(coder.Code(), err.Error())
	}

	return mapStateError(err)
}

func writeProblem(w http.ResponseWriter, esc *oas.ErrorStatusCode) {
	w.Header().Set("Content-Type", problemContentType)
	w.WriteHeader(esc.StatusCode)

	p := esc.Response

	status := esc.StatusCode
	if v, ok := p.Status.Get(); ok {
		status = int(v)
	}

	body := problemJSON{
		Title:  p.Title.Or(""),
		Status: status,
		Detail: p.Detail.Or(""),
	}
	if v, ok := p.Type.Get(); ok {
		body.Type = v.String()
	}

	if v, ok := p.Instance.Get(); ok {
		body.Instance = v.String()
	}

	err := json.NewEncoder(w).Encode(body)
	if err != nil {
		log.Error().Err(err).Msg("writing problem response failed")
	}
}

// problemJSON mirrors [oas.Problem] for hand-written encoding in
// [errorHandler]; ogen's own encoder is package-private.
type problemJSON struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}
