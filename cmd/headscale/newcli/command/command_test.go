package command

import (
	"bytes"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

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

// fileIn takes a file, which may be - for stdin, as an argument or a flag.
type fileIn struct {
	File Path `arg:"file"`
	Also Path `flag:"also" help:"Another file"`
}

// readTree has a command that prints the file it reads, and one that asks
// first.
func readTree(tb testing.TB) *Tree {
	tb.Helper()

	read := func(c Ctx, in fileIn) (item, error) {
		b, err := c.ReadFile(in.File)

		return item{ID: "1", Name: string(b)}, err
	}

	tree, err := Build("prog", "A program",
		New(Spec[fileIn, item]{
			Name: "read", Short: "S", Long: "S.", Example: []string{"prog read f"}, Local: true, Run: read,
			Done: func(_ fileIn, out item, _ time.Time) string { return "read " + strconv.Quote(out.Name) },
		}),
		New(Spec[fileIn, item]{
			Name: "ask", Short: "S", Long: "S.", Example: []string{"prog ask f"}, Local: true, Run: read,
			Confirm: func(Ctx, fileIn) (Prompt, error) { return Prompt{Question: "Go on?", Action: "go on"}, nil },
			Done:    func(_ fileIn, out item, _ time.Time) string { return "read " + strconv.Quote(out.Name) },
		}),
	)
	require.NoError(tb, err)

	return tree
}

// TestReadFile: a file or stdin for -, whole and as it is, each refusal a
// sentence that names the file; more than 16 MiB is refused, so a device
// that never ends does not fill the memory.
func TestReadFile(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	file := filepath.Join(dir, "p.hujson")
	require.NoError(t, os.WriteFile(file, []byte("a\r\nb\x00"), 0o600))

	latin1 := filepath.Join(dir, "latin1")
	require.NoError(t, os.WriteFile(latin1, []byte("// ok\n// caf\xe9\n{}"), 0o600))

	closed := filepath.Join(dir, "closed")
	require.NoError(t, os.WriteFile(closed, nil, 0o000))

	tree := readTree(t)

	for _, tt := range []struct {
		name, line, stdin string
		stdout, stderr    string
		code              int
	}{
		{name: "a file", line: "read " + file, stdout: `read "a\r\nb\x00"` + "\n"},
		{name: "stdin", line: "read -", stdin: "{}\n", stdout: `read "{}\n"` + "\n"},
		{name: "empty stdin", line: "read -", stdout: `read ""` + "\n"},
		{name: "a file that does not exist", line: "read " + dir + "/nope", stderr: "Error: the file " + dir + "/nope does not exist.\n", code: 1},
		{name: "a directory", line: "read " + dir, stderr: "Error: " + dir + " is a directory, not a file.\n", code: 1},
		{name: "a file the user may not read", line: "read " + closed, stderr: "Error: the file " + closed + " cannot be read: permission denied.\n", code: 1},
		{name: "more than 16 MiB", line: "read /dev/zero", stderr: "Error: /dev/zero is larger than 16 MiB, more than a command reads.\n", code: 1},
		{name: "not UTF-8", line: "read " + latin1, stderr: "Error: " + latin1 + " is not UTF-8 text: line 2 holds a byte that is not.\n", code: 1},
		{name: "stdin not UTF-8", line: "read -", stdin: "\xff", stderr: "Error: (stdin) is not UTF-8 text: line 1 holds a byte that is not.\n", code: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if tt.name == "a file the user may not read" && os.Geteuid() == 0 {
				t.Skip("root reads every file")
			}

			var stdout, stderr bytes.Buffer

			code := Run(tree, strings.Fields(tt.line), Env{Stdin: strings.NewReader(tt.stdin), Stdout: &stdout, Stderr: &stderr})
			require.Equal(t, tt.stdout, stdout.String())
			require.Equal(t, tt.stderr, stderr.String())
			require.Equal(t, tt.code, code)
		})
	}

	t.Run("stdin larger than 16 MiB", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer

		code := Run(tree, []string{"read", "-"}, Env{Stdin: io.LimitReader(zeros{}, maxRead+1), Stdout: io.Discard, Stderr: &stderr})
		require.Equal(t, "Error: (stdin) is larger than 16 MiB, more than a command reads.\n", stderr.String())
		require.Equal(t, 1, code)
	})
}

type zeros struct{}

func (zeros) Read(p []byte) (int, error) {
	clear(p)

	return len(p), nil
}

// TestStdinAnswersNothing: a line that gives - for a Path reads that file
// from stdin, so a question cannot be answered from it, on a terminal too:
// it needs --force, and the error says why.
func TestStdinAnswersNothing(t *testing.T) {
	t.Parallel()

	tree := readTree(t)
	refused := "Error: confirmation needed, but stdin is the file given as -, so it cannot answer.\nRun again with --force to go on.\n"

	for _, tt := range []struct {
		name, line, stdin string
		stdout, stderr    string
		code              int
	}{
		{name: "a file asks", line: "ask f", stdin: "n\n", stderr: "Go on? [y/N] Aborted.\n", code: 1},
		{name: "- as the argument", line: "ask -", stdin: "y\n", stderr: refused, code: 1},
		{name: "- as a flag", line: "ask f --also -", stdin: "y\n", stderr: refused, code: 1},
		{name: "--force reads stdin, and says how to end it", line: "ask - --force", stdin: "y\n", stdout: `read "y\n"` + "\n", stderr: "Reading from stdin: end with Ctrl-D at the start of a line.\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(tree, strings.Fields(tt.line), Env{Stdin: strings.NewReader(tt.stdin), Stdout: &stdout, Stderr: &stderr, Terminal: true})
			require.Equal(t, tt.stdout, stdout.String())
			require.Equal(t, tt.stderr, stderr.String())
			require.Equal(t, tt.code, code)
		})
	}
}

// TestFromStdin: stdin is the file of the command's own argument or flag
// given as -, never --config, which the builder reads and never as stdin.
func TestFromStdin(t *testing.T) {
	t.Parallel()

	tree, err := Build("prog", "A program", New(Spec[fileIn, item]{
		Name: "read", Short: "S", Long: "S.", Example: []string{"prog read f"}, Local: true, ReadsConfig: true,
		Run:  noop[fileIn, item],
		Done: func(fileIn, item, time.Time) string { return "" },
	}))
	require.NoError(t, err)

	for line, want := range map[string]bool{
		"read f":                 false,
		"read -":                 true,
		"read f --also -":        true,
		"read f --config -":      false,
		"read - --config c.yaml": true,
	} {
		parsed, err := tree.parser.Parse(strings.Fields(line))
		require.NoError(t, err, line)
		require.Equal(t, want, fromStdin(parsed), line)
	}
}
