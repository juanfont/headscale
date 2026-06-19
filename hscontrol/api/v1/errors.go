package apiv1

import (
	"errors"

	"github.com/danielgtaylor/huma/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/state"
	"gorm.io/gorm"
)

// mapError translates a state/db-layer error into a Huma HTTP error
// (NotFound→404, invalid input→400, conflict→409, everything else→500).
// Handlers use this default mapping and may return a more specific huma.ErrorN
// directly. msg is a human context prefix, e.g. "getting node".
func mapError(msg string, err error) error {
	if err == nil {
		return nil
	}

	switch {
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
		errors.Is(err, db.ErrUserStillHasNodes),
		errors.Is(err, db.ErrCannotChangeOIDCUser),
		errors.Is(err, db.ErrPreAuthKeyNotTaggedOrOwned),
		errors.Is(err, db.ErrSingleUseAuthKeyHasBeenUsed):
		return huma.Error400BadRequest(msg, err)

	case errors.Is(err, state.ErrNodeKeyInUse),
		errors.Is(err, state.ErrAmbiguousNodeOwnership):
		return huma.Error409Conflict(msg, err)

	default:
		return huma.Error500InternalServerError(msg, err)
	}
}
