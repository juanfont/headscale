package apiv2

import (
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"gorm.io/gorm"
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

	if len(em.Errors) > 0 {
		details := make([]string, 0, len(em.Errors))
		for _, d := range em.Errors {
			details = append(details, d.Error())
		}

		out.Data = []apiErrorData{{Errors: details}}
	}

	return out, nil
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
		errors.Is(err, state.ErrGivenNameInvalid),
		errors.Is(err, state.ErrGivenNameTaken),
		errors.Is(err, state.ErrNodeNameNotUnique),
		errors.Is(err, state.ErrRequestedTagsInvalidOrNotPermitted):
		return huma.Error400BadRequest(msg, err)

	default:
		return huma.Error500InternalServerError(msg, err)
	}
}
