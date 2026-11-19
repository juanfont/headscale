package apiv0

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"net/http"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/danielgtaylor/huma/v2"
	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/scope"
	"github.com/stretchr/testify/require"
)

// operationID is what an explicit ID looks like. huma's generated IDs are
// kebab-case from the full path, which a client turns into
// ListApiHeadscaleV0Nodes.
var operationID = regexp.MustCompile(`^[a-z][a-zA-Z]*$`)

// openOperations are the only operations that need no scope, as 002 says.
// Every other operation must name the scopes a token needs.
var openOperations = map[string]accessKind{
	"getVersion": publicAccess,
	"getMe":      anyCredentialAccess,
	"getHealth":  anyCredentialAccess,
}

// nullableLists are the only lists that may be null: null and [] mean
// different things there.
var nullableLists = []string{"Authorization.tags"}

// guard reports every rule an operation of api breaks.
func guard(api huma.API) []string {
	var faults []string

	fault := func(key, format string, args ...any) {
		faults = append(faults, key+": "+fmt.Sprintf(format, args...))
	}

	for path, item := range api.OpenAPI().Paths {
		for method, op := range operations(item) {
			key := method + " " + path

			if !operationID.MatchString(op.OperationID) {
				fault(key, "operation ID %q is not explicit lowerCamelCase", op.OperationID)
			}

			a, _ := op.Metadata[accessMetaKey].(access)

			switch want, open := openOperations[op.OperationID]; {
			case a.kind() == undeclared:
				fault(key, "declares no access; register it with register()")
			case open && a.kind() != want, !open && a.kind() != scopedAccess:
				fault(key, "only getVersion is public, and only getMe and getHealth take any credential; name the scopes")
			}

			var security []string
			if len(op.Security) == 1 {
				security = op.Security[0]["bearer"]
			}

			scopes := make([]string, len(a.scopes))
			for i, s := range a.scopes {
				scopes[i] = string(s)
			}

			if (a.kind() == publicAccess) != (len(op.Security) == 0) || !slices.Equal(security, scopes) {
				fault(key, "security %v does not match access %v", op.Security, scopes)
			}

			for _, s := range a.scopes {
				if !s.Valid() {
					fault(key, "unknown scope %q", s)
				}
			}

			cs, _ := op.Metadata[codesMetaKey].([]Code)
			if len(cs) == 0 {
				fault(key, "declares no problem codes")
			}

			for _, c := range cs {
				info, known := codes[c]
				if !known {
					fault(key, "unknown code %q", c)

					continue
				}

				if op.Responses[strconv.Itoa(info.status)] == nil {
					fault(key, "code %s has no %d response", c, info.status)
				}
			}

			for status, r := range op.Responses {
				for _, mt := range r.Content {
					nullLists(mt.Schema, key+" "+status, false, fault)

					body := mt.Schema
					if body != nil && body.Ref != "" {
						body = api.OpenAPI().Components.Schemas.SchemaFromRef(body.Ref)
					}

					if strings.HasPrefix(status, "2") && body != nil && body.Type == huma.TypeArray {
						fault(key+" "+status, "a list is an object, never a bare array")
					}
				}
			}
		}
	}

	for name, s := range api.OpenAPI().Components.Schemas.Map() {
		// huma's own error model is in the registry, never in v0's answers.
		if name != "ErrorModel" {
			nullLists(s, name, false, fault)
		}
	}

	slices.Sort(faults)

	return faults
}

// nullLists reports each list in s, at any depth, that may be null. A $ref
// is checked where it is defined.
func nullLists(s *huma.Schema, at string, isProp bool, fault func(string, string, ...any)) {
	if s == nil || s.Ref != "" {
		return
	}

	if s.Type == huma.TypeArray && s.Nullable && (!isProp || !slices.Contains(nullableLists, at)) {
		fault(at, "a list must be nullable:\"false\"")
	}

	nullLists(s.Items, at+"[]", false, fault)

	for prop, ps := range s.Properties {
		nullLists(ps, at+"."+prop, true, fault)
	}
}

func TestEveryOperationIsGuarded(t *testing.T) {
	require.Empty(t, guard(NewAPI(chi.NewMux(), Backend{}, "test")))
}

// TestGuardFails proves the guard catches what it must.
func TestGuardFails(t *testing.T) {
	api := NewAPI(chi.NewMux(), Backend{}, "test")
	noop := func(context.Context, *struct{}) (*struct{}, error) { return nil, nil } //nolint:nilnil

	huma.Get(api, Prefix+"/bare", func(context.Context, *struct{}) (*struct {
		Body struct {
			Inner struct {
				Items []string `json:"items"`
			} `json:"inner"`
		}
	}, error,
	) {
		return nil, nil //nolint:nilnil
	})

	huma.Register(api, huma.Operation{OperationID: "headThings", Method: http.MethodHead, Path: Prefix + "/things"}, noop)

	register(api, huma.Operation{Method: http.MethodGet, Path: Prefix + "/noid"}, needs(scope.UsersRead), nil, noop)

	register(api, huma.Operation{OperationID: "listNodes", Method: http.MethodGet, Path: Prefix + "/nodes"}, anyCredential, nil, noop)

	register(api, huma.Operation{OperationID: "listTags", Method: http.MethodGet, Path: Prefix + "/tags"}, needs(scope.DevicesCoreRead), nil,
		func(context.Context, *struct{}) (*struct{ Body []string }, error) { return nil, nil }) //nolint:nilnil

	faults := strings.Join(guard(api), "\n")
	for _, want := range []string{
		"GET " + Prefix + "/bare: operation ID \"get-api-headscale-v0-bare\" is not explicit",
		"GET " + Prefix + "/bare: declares no access",
		"GET " + Prefix + "/bare: declares no problem codes",
		"InnerStruct.items: a list must be nullable",
		"HEAD " + Prefix + "/things: declares no access",
		"GET " + Prefix + "/noid: operation ID \"\" is not explicit",
		"GET " + Prefix + "/nodes: only getVersion is public",
		"GET " + Prefix + "/tags 200: a list must be nullable",
		"GET " + Prefix + "/tags 200: a list is an object, never a bare array",
	} {
		require.Contains(t, faults, want)
	}
}

// TestNoAsStruct fails when code in hscontrol/api names AsStruct, called or
// as a method value: a response reads through the view types, as AGENTS.md
// says. It reads the source; a call through reflection or an interface that
// hides the name is not seen.
func TestNoAsStruct(t *testing.T) {
	err := filepath.WalkDir("../..", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return err
		}

		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}

		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok && sel.Sel.Name == "AsStruct" {
				t.Errorf("%s uses AsStruct; read through the view", path)
			}

			return true
		})

		return nil
	})
	require.NoError(t, err)
}

// problemFillers are the functions whose arguments become the detail of a
// problem.
var problemFillers = []string{"newProblem", "unhealthy", "forbidden"}

// goErrorText reports each place in f where the text of a Go error,
// x.Error(), feeds a problem: an argument of a problemFillers function, or a
// value given to Detail or Details. It reads the syntax only: an error text
// that reaches a problem through a variable, a helper or fmt's %v is not
// seen.
func goErrorText(fset *token.FileSet, f *ast.File) []string {
	var found []string

	hasErrorCall := func(n ast.Node) bool {
		hit := false

		ast.Inspect(n, func(n ast.Node) bool {
			if call, ok := n.(*ast.CallExpr); ok {
				if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Error" && len(call.Args) == 0 {
					hit = true
				}
			}

			return !hit
		})

		return hit
	}

	isDetail := func(e ast.Expr) bool {
		if ix, ok := e.(*ast.IndexExpr); ok {
			e = ix.X
		}

		sel, ok := e.(*ast.SelectorExpr)

		return ok && (sel.Sel.Name == "Detail" || sel.Sel.Name == "Details")
	}

	ast.Inspect(f, func(n ast.Node) bool {
		var bad bool

		switch n := n.(type) {
		case *ast.CallExpr:
			if id, ok := n.Fun.(*ast.Ident); ok && slices.Contains(problemFillers, id.Name) {
				bad = slices.ContainsFunc(n.Args, func(a ast.Expr) bool { return hasErrorCall(a) })
			}
		case *ast.AssignStmt:
			bad = slices.ContainsFunc(n.Lhs, isDetail) && slices.ContainsFunc(n.Rhs, func(a ast.Expr) bool { return hasErrorCall(a) })
		case *ast.KeyValueExpr:
			id, ok := n.Key.(*ast.Ident)
			bad = ok && (id.Name == "Detail" || id.Name == "Details") && hasErrorCall(n.Value)
		}

		if bad {
			found = append(found, fset.Position(n.Pos()).String())

			return false
		}

		return true
	})

	return found
}

// TestNoGoErrorTextInProblems: an error never holds the text of a Go
// error, which can carry a database message or the request.
func TestNoGoErrorTextInProblems(t *testing.T) {
	fset := token.NewFileSet()

	pkgs, err := filepath.Glob("*.go")
	require.NoError(t, err)

	for _, path := range pkgs {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(fset, path, nil, 0)
		require.NoError(t, err)
		require.Empty(t, goErrorText(fset, f), "a problem takes a sentence of ours, never err.Error()")
	}

	probe, err := parser.ParseFile(fset, "probe.go", `package p
func a(err error) {
	newProblem(CodeInternal, "x: "+err.Error())
	p.Detail = err.Error()
	p.Details["why"] = err.Error()
	_ = Problem{Detail: err.Error()}
	newProblem(CodeInternal, "fine")
}`, 0)
	require.NoError(t, err)
	require.Len(t, goErrorText(fset, probe), 4, "the scan must see each kind of place")
}
