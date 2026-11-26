package newcli

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// rapidRoots are the roots of the stack's code, from this package: every
// package under them whose tests import pgregory.net/rapid is checked, so a
// package that moves or is added cannot drop out of the check.
var rapidRoots = []string{
	"../../../cmdline", "../../../cmd/headscale", "../../../client",
	"../../../cmd/gen-openapi", "../../../hscontrol/config", "../../../hscontrol/api",
}

// rapidChecksFloor is how many calls of rapid.Check the packages hold: a
// walk that sees fewer read the wrong files, or none.
const rapidChecksFloor = 39

// TestShrinkableFailures: Rapid shrinks a failure only while it reads the
// same on replay, so a check fails with fixed text and logs its values.
// A Rapid handle (*rapid.T or rapid.TB), as a parameter, a struct field or
// a local copy, in a property or a helper, may call Fatal with a constant or
// a format variable alone, never Fatalf, Error, Errorf, or a require or
// assert function, which print the values; nor may it be handed to a
// function of the package that takes it as anything else.
//
// It scans source and runs no property, so its name does not say Rapid:
// a run that leaves the properties out by name still runs it.
//
// The check reads syntax, not types: go/types would need the export data
// of every dependency, which only the go command builds. So a handle is
// known by its declared type, a nested *testing.T of the same name hides
// it, and a field is known by its name within the package.
func TestShrinkableFailures(t *testing.T) {
	t.Parallel()

	checks := 0

	for _, dir := range rapidPackages(t) {
		bad, n := unstableFailures(t, dir)
		checks += n

		if n == 0 {
			t.Errorf("%s: its tests import rapid and call no rapid.Check", dir)
		}

		for _, b := range bad {
			t.Error(b)
		}
	}

	if checks < rapidChecksFloor {
		t.Errorf(
			"saw %d calls of rapid.Check, want at least %d: the walk read the wrong files",
			checks,
			rapidChecksFloor,
		)
	}
}

// rapidPackages are the directories under rapidRoots whose test files
// import pgregory.net/rapid. A root that is not there fails: a move of the
// code must move the root with it.
func rapidPackages(t *testing.T) []string {
	t.Helper()

	var dirs []string

	for _, root := range rapidRoots {
		err := filepath.WalkDir(
			root,
			func(path string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}

				if d.IsDir() || !strings.HasSuffix(path, "_test.go") ||
					strings.Contains(path, "testdata") {
					return nil
				}

				f, err := parser.ParseFile(
					token.NewFileSet(),
					path,
					nil,
					parser.ImportsOnly,
				)
				if err != nil {
					return err
				}

				dir := filepath.Dir(path)
				if !slices.Contains(dirs, dir) &&
					slices.ContainsFunc(
						f.Imports,
						func(i *ast.ImportSpec) bool { return i.Path.Value == `"pgregory.net/rapid"` },
					) {
					dirs = append(dirs, dir)
				}

				return nil
			},
		)
		if err != nil {
			t.Fatalf("%s: %v", root, err)
		}
	}

	if len(dirs) == 0 {
		t.Fatalf("no package under %q has a property", rapidRoots)
	}

	return dirs
}

// TestShrinkableFailuresGuard holds the check to what it must see and must not.
func TestShrinkableFailuresGuard(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, src string
		bad       int
	}{
		{"param", `func f(rt *rapid.T) { rt.Fatalf("x %d", 1) }`, 1},
		{"interface", `func f(tb rapid.TB) { tb.Errorf("x") }`, 1},
		{"field", `type s struct{ t *rapid.T }; func (s *s) f() { s.t.Fatalf("x %d", 1) }`, 1},
		{"field fatal value", `type s struct{ t *rapid.T }; func (s *s) f(err error) { s.t.Fatal(err) }`, 1},
		{"closure", `func f(rt *rapid.T) { g := func() { rt.Fatalf("x") }; g() }`, 1},
		{"copy", `func f(rt *rapid.T) { h := rt; h.Fatalf("x") }`, 1},
		{"copy of a field", `type s struct{ t *rapid.T }; func (s *s) f() { h := s.t; h.Fatalf("x %d", 1) }`, 1},
		{"require", `func f(rt *rapid.T) { require.Equal(rt, 1, 2) }`, 1},
		{"passed as other type", `func g(tb testing.TB) {}; func f(rt *rapid.T) { g(rt) }`, 1},
		{"stable", `func f(rt *rapid.T) { rt.Fatal("x"); rt.Logf("x %d", 1) }`, 0},
		{"helper", `func fatalf(rt rapid.TB, format string, args ...any) { rt.Logf(format, args...); rt.Fatal(format) }`, 0},
		{"shadowed by testing.T", `func f(t *rapid.T) { _ = func(t *testing.T) { t.Fatalf("x %d", 1) } }`, 0},
		{"passed as handle", `func g(rt *rapid.T) {}; func f(rt *rapid.T) { g(rt) }`, 0},
	} {
		f, err := parser.ParseFile(
			token.NewFileSet(),
			"x_test.go",
			"package x\n"+tt.src,
			0,
		)
		if err != nil {
			t.Fatal(err)
		}

		bad, _ := failuresIn([]*ast.File{f}, token.NewFileSet())
		if len(bad) != tt.bad {
			t.Errorf("%s: %d findings %q, want %d", tt.name, len(bad), bad, tt.bad)
		}
	}

	if _, n := unstableFailures(t, t.TempDir()); n != 0 {
		t.Errorf("an empty directory has %d checks", n)
	}
}

// unstableFailures parses the test files of dir and reports its unstable
// failing calls and its count of rapid.Check calls.
func unstableFailures(t *testing.T, dir string) ([]string, int) {
	t.Helper()

	names, err := filepath.Glob(filepath.Join(dir, "*_test.go"))
	if err != nil {
		t.Fatal(err)
	}

	fset := token.NewFileSet()

	files := make([]*ast.File, 0, len(names))

	for _, name := range names {
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}

		files = append(files, f)
	}

	return failuresIn(files, fset)
}

// failuresIn checks the files of one package.
func failuresIn(files []*ast.File, fset *token.FileSet) ([]string, int) {
	fields := map[string]bool{}
	params := map[string][]ast.Expr{}

	for _, f := range files {
		ast.Inspect(f, func(n ast.Node) bool {
			switch d := n.(type) {
			case *ast.StructType:
				for _, fl := range d.Fields.List {
					if isRapidHandle(fl.Type) {
						for _, n := range fl.Names {
							fields[n.Name] = true
						}
					}
				}
			case *ast.FuncDecl:
				if d.Recv == nil {
					for _, p := range d.Type.Params.List {
						for range max(1, len(p.Names)) {
							params[d.Name.Name] = append(params[d.Name.Name], p.Type)
						}
					}
				}
			}

			return true
		})
	}

	g := &guard{fset: fset, fields: fields, params: params}
	for _, f := range files {
		g.walk(f, nil)
	}

	return g.bad, g.checks
}

type guard struct {
	fset   *token.FileSet
	fields map[string]bool
	params map[string][]ast.Expr
	bad    []string
	checks int
}

// walk inspects n with the names that are Rapid handles in its scope.
func (g *guard) walk(n ast.Node, handles []string) {
	ast.Inspect(n, func(n ast.Node) bool {
		var typ *ast.FuncType

		var body *ast.BlockStmt

		switch x := n.(type) {
		case *ast.FuncDecl:
			typ, body = x.Type, x.Body
		case *ast.FuncLit:
			typ, body = x.Type, x.Body
		case *ast.AssignStmt:
			for i, r := range x.Rhs {
				if g.isHandle(r, handles) && i < len(x.Lhs) {
					if l, ok := x.Lhs[i].(*ast.Ident); ok {
						handles = append(handles, l.Name)
					}
				}
			}

			return true
		case *ast.CallExpr:
			g.call(x, handles)

			return true
		default:
			return true
		}

		if body == nil {
			return false
		}

		inner := slices.Clone(handles)

		for _, p := range typ.Params.List {
			for _, name := range p.Names {
				inner = slices.DeleteFunc(
					inner,
					func(h string) bool { return h == name.Name },
				)
				if isRapidHandle(p.Type) {
					inner = append(inner, name.Name)
				}
			}
		}

		g.walk(body, inner)

		return false
	})
}

// isHandle reports whether e is a Rapid handle: a name in scope, or a
// field that holds one.
func (g *guard) isHandle(e ast.Expr, handles []string) bool {
	switch x := e.(type) {
	case *ast.Ident:
		return slices.Contains(handles, x.Name)
	case *ast.SelectorExpr:
		return g.fields[x.Sel.Name]
	}

	return false
}

func (g *guard) call(c *ast.CallExpr, handles []string) {
	report := func(what string) { g.bad = append(g.bad, g.fset.Position(c.Pos()).String()+": "+what) }

	if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
		if pkg, ok := sel.X.(*ast.Ident); ok && pkg.Name == "rapid" &&
			sel.Sel.Name == "Check" {
			g.checks++
		}

		if pkg, ok := sel.X.(*ast.Ident); ok &&
			(pkg.Name == "require" || pkg.Name == "assert") {
			if len(c.Args) > 0 && g.isHandle(c.Args[0], handles) {
				report(pkg.Name + "." + sel.Sel.Name + " on a Rapid handle")
			}

			return
		}

		if g.isHandle(sel.X, handles) {
			switch sel.Sel.Name {
			case "Fatalf", "Error", "Errorf":
				report(sel.Sel.Name + " on a Rapid handle")
			case "Fatal":
				if !stableArg(c.Args) {
					report("Fatal with a value on a Rapid handle")
				}
			}
		}

		return
	}

	// A handle handed to a function of the package as another type.
	if fn, ok := c.Fun.(*ast.Ident); ok {
		for i, a := range c.Args {
			if types := g.params[fn.Name]; i < len(types) && g.isHandle(a, handles) &&
				!isRapidHandle(types[i]) {
				report("a Rapid handle passed to " + fn.Name + " as another type")
			}
		}
	}
}

func stableArg(args []ast.Expr) bool {
	if len(args) != 1 {
		return false
	}

	switch a := args[0].(type) {
	case *ast.BasicLit:
		return true
	case *ast.Ident:
		return a.Name == "format"
	}

	return false
}

func isRapidHandle(e ast.Expr) bool {
	if s, ok := e.(*ast.StarExpr); ok {
		e = s.X
	}

	sel, ok := e.(*ast.SelectorExpr)
	if !ok {
		return false
	}

	pkg, ok := sel.X.(*ast.Ident)

	return ok && pkg.Name == "rapid" && (sel.Sel.Name == "T" || sel.Sel.Name == "TB")
}
