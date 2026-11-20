package command

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestNoPackageState: the builder and the table engine keep no state
// between runs and trees. A variable at the level of the package is an
// error to compare with errors.Is and nothing else: a registry, a table of
// words or a default that a test or a command could change is a function.
// A test that runs a tree does not see such a variable, since every tree
// reads the same one, so this reads the source.
func TestNoPackageState(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	more, err := filepath.Glob("../table/*.go")
	require.NoError(t, err)

	for _, name := range append(files, more...) {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)

		for _, d := range f.Decls {
			g, ok := d.(*ast.GenDecl)
			if !ok || g.Tok != token.VAR {
				continue
			}

			for _, spec := range g.Specs {
				v, _ := spec.(*ast.ValueSpec)
				for i, n := range v.Names {
					if !errorsNew(valueAt(v, i)) {
						t.Errorf("%s: var %s is state of the package; make it a function", name, n.Name)
					}
				}
			}
		}
	}
}

// errorsNew is a call of errors.New.
func errorsNew(e ast.Expr) bool {
	call, ok := e.(*ast.CallExpr)
	if !ok {
		return false
	}

	fn, ok := call.Fun.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	pkg, ok := fn.X.(*ast.Ident)

	return ok && pkg.Name == "errors" && fn.Sel.Name == "New"
}

// valueAt is the value of the i-th name of v; nil for none.
func valueAt(v *ast.ValueSpec, i int) ast.Expr {
	if i < len(v.Values) {
		return v.Values[i]
	}

	return nil
}
