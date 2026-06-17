// Package apiv1 implements the Headscale v1 HTTP API: thin handlers that
// adapt the ogen-generated server interface ([oas.Handler]) onto the shared
// state layer ([state.State]). Business logic lives in the state layer; these
// handlers only translate between HTTP request/response types and state calls.
//
// The package deliberately does not import the parent hscontrol package: it
// depends only on state, types, and the generated API package, so that
// hscontrol can mount it without an import cycle.
package apiv1

import (
	"net/http"

	oas "github.com/juanfont/headscale/gen/api/v1"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
)

// Server implements the generated [oas.Handler] and [oas.SecurityHandler].
//
// Any operation not implemented here is inherited from
// [oas.UnimplementedHandler] and returns 501; every operation is implemented.
type Server struct {
	oas.UnimplementedHandler

	state  *state.State
	cfg    *types.Config
	change changeFunc
}

// changeFunc distributes state changes to connected nodes. In production this
// is [github.com/juanfont/headscale/hscontrol.Headscale.Change]; tests may pass
// a no-op or a recorder.
type changeFunc func(...change.Change)

// NewHandler builds the v1 API as an [http.Handler] ready to mount at
// /api/v1. changeFn distributes [change.Change]s produced by mutating
// operations; it must not be nil (pass a no-op if changes are irrelevant).
func NewHandler(
	st *state.State,
	cfg *types.Config,
	changeFn func(...change.Change),
) (http.Handler, error) {
	s := &Server{
		state:  st,
		cfg:    cfg,
		change: changeFn,
	}

	return oas.NewServer(s, s, oas.WithErrorHandler(errorHandler))
}
