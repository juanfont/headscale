package apiv1

import (
	"context"
	"net/http"

	oas "github.com/juanfont/headscale/gen/api/v1"
)

// HandleBearerAuth validates the API key bearer token against the state layer.
// A missing or malformed Authorization header is reported by ogen before this
// is reached. Any validation failure — a malformed/unknown key (which
// [state.State.ValidateAPIKey] reports as an error) or an expired/invalid one —
// is a 401, matching the previous middleware which rejected every such case
// with Unauthorized.
func (s *Server) HandleBearerAuth(
	ctx context.Context,
	_ oas.OperationName,
	t oas.BearerAuth,
) (context.Context, error) {
	valid, err := s.state.ValidateAPIKey(t.Token)
	if err != nil || !valid {
		return ctx, apiError(http.StatusUnauthorized, "invalid API key")
	}

	return ctx, nil
}
