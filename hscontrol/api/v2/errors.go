package apiv2

import (
	"errors"
	"net/http"
	"strconv"
	"strings"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/state"
	"gorm.io/gorm"
	"tailscale.com/util/multierr"
)

// apiError is the Tailscale API error body. The official Tailscale Go client
// (and therefore the Terraform provider and tscli built on it) decodes 4xx/5xx
// responses into this shape. Huma's default RFC 9457 problem+json would reach
// them with an empty message, so tailscaleErrorTransformer rewrites every v2
// error into this shape. The HTTP status is read from the response code, not
// from the body's status field.
type apiError struct {
	Message string         `json:"message"`
	Data    []apiErrorData `json:"data,omitempty"`
	Status  int            `json:"status"`
}

type apiErrorData struct {
	User   string   `json:"user,omitempty"`
	Errors []string `json:"errors,omitempty"`
}

// maxErrorDetails caps the errors, or failing tests, one response lists. huma
// reports one error per bad element of the body, so the caller picks how many.
const maxErrorDetails = 20

// tailscaleErrorTransformer rewrites Huma's RFC 9457 error model into the
// Tailscale error shape. It is registered on the v2 API config only, so the
// headscale-native v1 API keeps emitting problem+json. Non-error bodies pass
// through untouched.
func tailscaleErrorTransformer(_ huma.Context, _ string, v any) (any, error) {
	em, ok := v.(*huma.ErrorModel)
	if !ok {
		return v, nil
	}

	message := em.Detail
	if message == "" {
		message = em.Title
	}

	out := apiError{Message: message, Status: em.Status}

	listed := em.Errors[:min(len(em.Errors), maxErrorDetails)]

	details := make([]string, 0, len(listed)+1)
	for _, d := range listed {
		// huma stores a nil detail for a nil error argument.
		if d == nil {
			continue
		}

		// The value is not echoed: for an unexpected property it is the whole
		// request object, once per property.
		if d.Location == "" {
			details = append(details, d.Message)
		} else {
			details = append(details, d.Message+" ("+d.Location+")")
		}
	}

	if more := len(em.Errors) - len(listed); more > 0 {
		details = append(details, "and "+strconv.Itoa(more)+" more")
	}

	if len(details) > 0 {
		out.Data = []apiErrorData{{Errors: details}}
	}

	return out, nil
}

func (e *apiError) Error() string { return e.Message }

func (e *apiError) GetStatus() int { return e.Status }

// policyRefusal is a refused policy as Tailscale reports it: the reason as
// message and, when tests failed, one data entry per failing test naming its
// src.
func policyRefusal(err error) (string, []apiErrorData) {
	var failures []policyv2.TestFailure

	// Range visits every wrapped error, so errors.As would count a failure
	// once per wrapper above it.
	multierr.Range(err, func(e error) bool {
		if tf, ok := e.(*policyv2.TestsFailedError); ok { //nolint:errorlint
			failures = append(failures, tf.Failures...)
		}

		return true
	})

	if len(failures) == 0 {
		return err.Error(), nil
	}

	listed := failures[:min(len(failures), maxErrorDetails)]
	data := make([]apiErrorData, 0, len(listed)+1)

	for _, f := range listed {
		// A policy writes a user known only by name as name@.
		data = append(data, apiErrorData{User: strings.TrimSuffix(f.Src, "@"), Errors: f.Errors})
	}

	if more := len(failures) - len(listed); more > 0 {
		data = append(data, apiErrorData{Errors: []string{"and " + strconv.Itoa(more) + " more"}})
	}

	return "test(s) failed", data
}

// mapError translates a state/db-layer error into a Huma HTTP error
// (not-found→404, invalid input→400, everything else→500). The transformer
// then reshapes it into the Tailscale body.
func mapError(msg string, err error) error {
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, gorm.ErrRecordNotFound),
		errors.Is(err, db.ErrPreAuthKeyNotFound),
		errors.Is(err, db.ErrUserNotFound),
		errors.Is(err, state.ErrNodeNotFound):
		return huma.Error404NotFound(msg, err)

	case errors.Is(err, db.ErrPreAuthKeyNotTaggedOrOwned),
		errors.Is(err, db.ErrPreAuthKeyACLTagInvalid),
		errors.Is(err, db.ErrOAuthClientScopeInvalid),
		errors.Is(err, state.ErrGivenNameInvalid),
		errors.Is(err, state.ErrGivenNameTaken),
		errors.Is(err, state.ErrNodeNameNotUnique),
		errors.Is(err, state.ErrRequestedTagsInvalidOrNotPermitted):
		// As on Tailscale SaaS, the reason is the message.
		return huma.Error400BadRequest(err.Error(), err)

	// A refused policy is answered with its own reason as the message.
	case errors.Is(err, state.ErrInvalidPolicy):
		message, data := policyRefusal(err)

		return &apiError{Message: message, Status: http.StatusBadRequest, Data: data}

	default:
		return huma.Error500InternalServerError(msg, err)
	}
}
