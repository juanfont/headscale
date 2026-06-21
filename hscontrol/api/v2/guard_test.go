package apiv2

import (
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
)

// selfEnforcedKeyOps are the authenticated operations that intentionally declare
// NO static scope because they multiplex on keyType and authorize inside the
// handler via requireKeyScope (see keys.go). Every other authenticated operation
// must declare a scope.
var selfEnforcedKeyOps = map[string]bool{
	"POST /api/v2/tailnet/{tailnet}/keys":           true,
	"GET /api/v2/tailnet/{tailnet}/keys":            true,
	"GET /api/v2/tailnet/{tailnet}/keys/{keyId}":    true,
	"DELETE /api/v2/tailnet/{tailnet}/keys/{keyId}": true,
}

// TestEveryAuthenticatedOperationDeclaresScope is the structural guarantee that no
// v2 operation ships unprotected: any operation that requires authentication
// (non-empty Security) must either declare a required scope via requireScope, or
// be one of the keyType-multiplexed keys operations that self-enforce. A new
// operation added without scope protection fails this test.
func TestEveryAuthenticatedOperationDeclaresScope(t *testing.T) {
	api := NewAPI(chi.NewMux(), Backend{})

	for path, item := range api.OpenAPI().Paths {
		for method, op := range humaOperations(item) {
			if op == nil || len(op.Security) == 0 {
				continue // unregistered method or a public operation
			}

			key := method + " " + path
			if selfEnforcedKeyOps[key] {
				continue
			}

			if _, ok := op.Metadata[scopeMetaKey].(scope.Scope); !ok {
				t.Errorf("operation %q is authenticated but declares no required scope; "+
					"wrap it in requireScope, or add it to selfEnforcedKeyOps if it "+
					"authorizes inside the handler", key)
			}
		}
	}
}

func humaOperations(item *huma.PathItem) map[string]*huma.Operation {
	return map[string]*huma.Operation{
		"GET":    item.Get,
		"POST":   item.Post,
		"PUT":    item.Put,
		"DELETE": item.Delete,
		"PATCH":  item.Patch,
	}
}
