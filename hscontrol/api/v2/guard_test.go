package apiv2

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/stretchr/testify/require"
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

// TestEveryRequestBodyIsBounded fails an operation whose body has no size or
// read-time limit, or a validated body above maxBodyBytes. huma sets its
// defaults only for a Body input, never for RawBody.
func TestEveryRequestBodyIsBounded(t *testing.T) {
	api := NewAPI(chi.NewMux(), Backend{})

	for path, item := range api.OpenAPI().Paths {
		for method, op := range humaOperations(item) {
			if op == nil || op.RequestBody == nil {
				continue
			}

			if op.MaxBodyBytes <= 0 || op.BodyReadTimeout <= 0 ||
				(!op.SkipValidateBody && op.MaxBodyBytes > maxBodyBytes) {
				t.Errorf("%s %s: MaxBodyBytes=%d BodyReadTimeout=%s",
					method, path, op.MaxBodyBytes, op.BodyReadTimeout)
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

// TestNoUncheckedUserWrite: the source of v2 names none of the user writers
// that skip hsdb.CheckLocalUserTexts (CreateUser, UpdateUser, RenameUser),
// which are for OIDC and /api/v1 only; a write of a user's name or email
// goes through State.CreateLocalUser or State.UpdateLocalUser. It reads
// direct references only: a write delegated through another package is
// not seen.
func TestNoUncheckedUserWrite(t *testing.T) {
	files, err := filepath.Glob("*.go")
	require.NoError(t, err)
	require.Contains(t, files, "devices.go", "run from the directory of the package")

	unchecked := map[string]bool{"CreateUser": true, "UpdateUser": true, "RenameUser": true}
	fset := token.NewFileSet()

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, name, nil, 0)
		require.NoError(t, err)

		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && unchecked[sel.Sel.Name] {
				t.Errorf("%s: %s skips the check of a local user's texts; use CreateLocalUser or UpdateLocalUser", fset.Position(sel.Pos()), sel.Sel.Name)
			}

			return true
		})
	}
}
