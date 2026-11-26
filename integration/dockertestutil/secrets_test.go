package dockertestutil

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// secretFields are the members that hold a credential's secret: Key of the
// v0 objects that make a credential and of the v2 key, and the names a
// helper of its own would give one.
var secretFields = []string{"Key", "Secret", "ClientSecret", "AccessToken", "Token", "APIKey", "ApiKey"}

// authIDSources return an auth ID, or a URL or command line that holds one:
// it answers a waiting registration or SSH check, so it is a secret too.
// What net/http hands code it calls back is not seen: a request or an
// answer inside an http.RoundTripper, a cookie in a jar. Nor is a
// container's own output; the saved logs are masked whole.
var authIDSources = []string{"LoginWithURL", "findSSHCheckAuthID", "findNewSSHCheckAuthID", "pageCommand"}

// carrierFields are the members of a request or an answer that carry what
// it was made from: an auth ID in a login URL is in the page it returns.
var carrierFields = []string{"Body", "URL", "Request"}

// maskers hide every secret in what they return.
var maskers = []string{"Redact", "Redactf", "RedactError"}

// cleanCalls return no part of their arguments: a length, a test, a count.
var cleanCalls = []string{
	"len", "cap", "Contains", "HasPrefix", "HasSuffix", "EqualFold", "Count", "Index",
	"Is", "As", "NotEmpty", "Equal", "Valid", "Sleep",
}

// runners run the command they are given and return what it printed, which
// holds a secret when the command makes a credential. A runner is judged by
// each call, as its body cannot tell one command from another; its errors
// are checked in its body.
var runners = []string{"Execute", "executeEnv", "ExecuteCommand", "Shell"}

// decoders run a command they are given, which the suite uses for a create
// with -o json among others, and return or fill what it printed: a command
// that reaches one tainted is taken to make a credential.
var decoders = []string{"cliJSON", "cliJSONEnv", "executeAndUnmarshal", "assertJSONRoundtrip"}

// passOn are the calls outside the suite whose result holds what they were
// given: conversions, formatting, the strings package, and the decoders,
// whose errors quote the input they could not read. A generated client's
// *WithResponse call is one too: its error quotes the answer.
var passOn = []string{
	"append", "string", "Sprint", "Sprintf", "Sprintln", "Errorf",
	"TrimSpace", "Trim", "TrimPrefix", "TrimSuffix", "TrimLeft", "TrimRight",
	"Join", "Split", "SplitN", "Fields", "Cut", "CutPrefix", "CutSuffix",
	"Replace", "ReplaceAll", "ToLower", "ToUpper", "Repeat",
	"Unmarshal", "Decode", "Marshal", "MarshalIndent", "Quote",
	// A pattern's match, the request built for a URL, its answer and its
	// body hold what they were given: an auth ID in a login URL is in the
	// page that URL returns, and in the error of a failed request.
	"FindString", "FindStringSubmatch", "FindAllString", "ReplaceAllString",
	"NewRequest", "NewRequestWithContext", "Do", "Get", "ReadAll",
}

// sinkMethods log or fail a test with their arguments, whatever the receiver
// (t, c, ct, b, a logger), and testify's assert and require print every
// argument of a failed assertion.
var sinkMethods = []string{
	"Log", "Logf", "Error", "Errorf", "Fatal", "Fatalf", "Skip", "Skipf",
	"Print", "Printf", "Println", "Fatalln", "Panic", "Panicf", "Panicln",
	"Msg", "Msgf", "Str", "Interface", "Fprint", "Fprintf", "Fprintln",
}

// quietAsserts print a value only when it is empty, zero or nil.
var quietAsserts = []string{"NotEmpty", "NotZero", "NotNil"}

// secretExempt are the sinks a secret may reach, each with its reason, by
// "file:function".
var secretExempt = map[string]string{
	"dockertestutil/redact_test.go:TestRedact":        "feeds sentinel secrets to the masker it tests",
	"hsic/hsic_test.go:TestNoSecretInFailures":        "feeds sentinel secrets to the helpers' failure paths it tests",
	"tsic/login_test.go:TestLoginFailureHidesAuthKey": "feeds a sentinel auth key to the login runner it tests",
	"scenario_test.go:TestLoginDiagnosticsHideAuthID": "feeds a sentinel auth ID to the login helpers it tests",
}

// flow is the taint of the source of the suite: which parameters and
// results of each function, by name, carry a secret.
type flow struct {
	params  map[string]map[int]bool
	results map[string]map[int]bool
	sigs    map[string][]*ast.FuncType
	changed bool
}

func (f *flow) mark(m map[string]map[int]bool, name string, i int) {
	if m[name] == nil {
		m[name] = map[int]bool{}
	}

	if !m[name][i] {
		m[name][i] = true
		f.changed = true
	}
}

// callName is the name of the function a call calls: f, x.f, f[T].
func callName(e ast.Expr) string {
	switch e := e.(type) {
	case *ast.Ident:
		return e.Name
	case *ast.SelectorExpr:
		return e.Sel.Name
	case *ast.IndexExpr:
		return callName(e.X)
	case *ast.IndexListExpr:
		return callName(e.X)
	}

	return ""
}

// createsCredential reports whether a call runs a command that prints a new
// credential: a []string literal with "keys" or "oauth-clients", then
// "create".
func createsCredential(call *ast.CallExpr) bool {
	for _, a := range call.Args {
		lit, ok := a.(*ast.CompositeLit)
		if !ok {
			continue
		}

		var words []string

		for _, e := range lit.Elts {
			if b, ok := e.(*ast.BasicLit); ok && b.Kind == token.STRING {
				w, _ := strconv.Unquote(b.Value)
				words = append(words, w)
			}
		}

		for i := 0; i+1 < len(words); i++ {
			if (words[i] == "keys" || words[i] == "oauth-clients") && words[i+1] == "create" {
				return true
			}
		}
	}

	return false
}

// scope is the taint inside one function body, by identifier name; closures
// share it.
type scope struct {
	f       *flow
	tainted map[string]bool
	// creates are the names bound to a command that creates a credential.
	creates map[string]bool
}

// expr reports whether e may hold a secret; idx is the result taken of a
// call that returns several.
func (s *scope) expr(e ast.Expr, idx int) bool {
	switch e := e.(type) {
	case nil:
		return false
	case *ast.Ident:
		return s.tainted[e.Name]
	case *ast.BasicLit, *ast.FuncLit:
		return false
	case *ast.SelectorExpr:
		// Another member of a value that holds a secret is not the secret,
		// but for the body and the URL of a request or an answer.
		return slices.Contains(secretFields, e.Sel.Name) || slices.Contains(carrierFields, e.Sel.Name) && s.expr(e.X, 0)
	case *ast.StarExpr:
		return s.expr(e.X, 0)
	case *ast.UnaryExpr:
		return s.expr(e.X, 0)
	case *ast.ParenExpr:
		return s.expr(e.X, idx)
	case *ast.BinaryExpr:
		return e.Op == token.ADD && (s.expr(e.X, 0) || s.expr(e.Y, 0))
	case *ast.IndexExpr:
		return s.expr(e.X, 0)
	case *ast.SliceExpr:
		return s.expr(e.X, 0)
	case *ast.TypeAssertExpr:
		return s.expr(e.X, 0)
	case *ast.KeyValueExpr:
		return s.expr(e.Value, 0)
	case *ast.CompositeLit:
		return createsCredential(&ast.CallExpr{Args: []ast.Expr{e}}) ||
			slices.ContainsFunc(e.Elts, func(x ast.Expr) bool { return s.expr(x, 0) })
	case *ast.CallExpr:
		return s.call(e, idx)
	}

	return false
}

func (s *scope) call(c *ast.CallExpr, idx int) bool {
	name := callName(c.Fun)

	argTainted := false

	for i, a := range c.Args {
		if !s.expr(a, 0) {
			continue
		}

		argTainted = true

		for _, sig := range s.f.sigs[name] {
			s.f.mark(s.f.params, name, paramIndex(sig, i))
		}
	}

	// A call that reads a secret into a value given by address, as a decoder
	// or a helper that runs a command and decodes its output, taints it.
	if argTainted && (slices.Contains(passOn, name) || slices.Contains(decoders, name)) || createsCredential(c) {
		for _, a := range c.Args {
			if u, ok := a.(*ast.UnaryExpr); ok && u.Op == token.AND && !slices.Contains(maskers, name) {
				if id, ok := u.X.(*ast.Ident); ok {
					s.tainted[id.Name] = true
				}
			}
		}
	}

	switch {
	case slices.Contains(maskers, name), slices.Contains(cleanCalls, name):
		return false
	case slices.Contains(runners, name):
		return idx == 0 && (createsCredential(c) || slices.ContainsFunc(c.Args, func(a ast.Expr) bool {
			id, ok := a.(*ast.Ident)

			return ok && s.creates[id.Name]
		}))
	case slices.Contains(decoders, name):
		return name != "executeAndUnmarshal" && idx == 0 && (argTainted || createsCredential(c))
	case createsCredential(c), slices.Contains(authIDSources, name):
		return idx == 0
	case s.f.sigs[name] != nil:
		// Functions are matched by name, so a suite method String does not
		// make url.URL's String clean: a method of a tainted value is
		// tainted whatever its name.
		sel, ok := c.Fun.(*ast.SelectorExpr)

		return s.f.results[name][idx] || ok && s.expr(sel.X, 0)
	case slices.Contains(passOn, name):
		return argTainted
	default:
		// Other code outside the suite: a method of a tainted value, such as
		// a builder's String; any other result is taken to hold none of what
		// the call was given.
		sel, ok := c.Fun.(*ast.SelectorExpr)

		return ok && s.expr(sel.X, 0) || strings.HasSuffix(name, "WithResponse") && argTainted
	}
}

// paramIndex is the parameter that argument i lands in, variadic included.
func paramIndex(sig *ast.FuncType, i int) int {
	n := 0

	for _, p := range sig.Params.List {
		names := max(len(p.Names), 1)
		if i < n+names {
			return n + min(i-n, names-1)
		}

		n += names
	}

	return max(n-1, 0)
}

// assign taints each name on the left that a tainted right side reaches.
func (s *scope) assign(lhs, rhs []ast.Expr) {
	for i, l := range lhs {
		var t bool

		switch {
		case len(rhs) == len(lhs):
			t = s.expr(rhs[i], 0)

			if id, ok := l.(*ast.Ident); ok {
				s.creates[id.Name] = createsCredential(&ast.CallExpr{Args: []ast.Expr{rhs[i]}})
			}
		case len(rhs) == 1:
			t = s.expr(rhs[0], i)
		}

		// A whole name assigned a clean value is clean from here: the walk
		// runs in source order.
		if id, ok := l.(*ast.Ident); ok && !t {
			delete(s.tainted, id.Name)

			continue
		}

		if !t {
			continue
		}

		for x := l; x != nil; {
			switch v := x.(type) {
			case *ast.Ident:
				if v.Name != "_" {
					s.tainted[v.Name] = true
				}

				x = nil
			case *ast.SelectorExpr:
				x = v.X
			case *ast.IndexExpr:
				x = v.X
			case *ast.StarExpr:
				x = v.X
			default:
				x = nil
			}
		}
	}
}

// sink is the description of a call that logs or fails with a secret, or "".
func (s *scope) sink(c *ast.CallExpr) string {
	name := callName(c.Fun)
	pkg := ""

	if sel, ok := c.Fun.(*ast.SelectorExpr); ok {
		if id, ok := sel.X.(*ast.Ident); ok {
			pkg = id.Name
		}
	}

	isSink := slices.Contains(sinkMethods, name) ||
		name == "panic" ||
		pkg == "fmt" && name == "Errorf" ||
		(pkg == "assert" || pkg == "require") && !slices.Contains(quietAsserts, name)
	if !isSink {
		return ""
	}

	for _, a := range c.Args {
		if s.expr(a, 0) {
			return name
		}
	}

	return ""
}

// walkFunc runs the taint through one function: its tainted parameters, its
// assignments to a fixpoint, the results it returns, and the sinks it reaches.
func (f *flow) walkFunc(name string, typ *ast.FuncType, body *ast.BlockStmt, report func(token.Pos, string)) {
	if body == nil {
		return
	}

	s := &scope{f: f, tainted: map[string]bool{}, creates: map[string]bool{}}

	i := 0

	for _, p := range typ.Params.List {
		for _, n := range p.Names {
			if f.params[name][i] {
				s.tainted[n.Name] = true
			}

			i++
		}

		if len(p.Names) == 0 {
			i++
		}
	}

	s.walk(body, name, report, true)
}

// walk runs over n in source order: a statement's sinks, then the taint it
// assigns. A function literal is walked where it stands, with the same
// taint; its returns are not the function's.
func (s *scope) walk(n ast.Node, name string, report func(token.Pos, string), top bool) {
	ast.Inspect(n, func(n ast.Node) bool {
		switch n := n.(type) {
		case *ast.FuncLit:
			s.walk(n.Body, name, report, false)

			return false
		case *ast.AssignStmt:
			s.sinks(n, name, report)
			s.assign(n.Lhs, n.Rhs)

			return false
		case *ast.ValueSpec:
			s.sinks(n, name, report)

			lhs := make([]ast.Expr, len(n.Names))
			for i, id := range n.Names {
				lhs[i] = id
			}

			s.assign(lhs, n.Values)

			return false
		case *ast.RangeStmt:
			if s.expr(n.X, 0) {
				s.assign([]ast.Expr{n.Value}, []ast.Expr{n.X})
			}
		case *ast.ReturnStmt:
			s.sinks(n, name, report)

			if top && !slices.Contains(runners, name) && !slices.Contains(decoders, name) {
				for i, r := range n.Results {
					if s.expr(r, 0) {
						s.f.mark(s.f.results, name, i)
					}
				}

				// return f() forwards each result of f, not only the first.
				for _, sig := range s.f.sigs[name] {
					for i := 1; len(n.Results) == 1 && sig.Results != nil && i < sig.Results.NumFields(); i++ {
						if s.expr(n.Results[0], i) {
							s.f.mark(s.f.results, name, i)
						}
					}
				}
			}

			return false
		case *ast.ExprStmt, *ast.GoStmt, *ast.DeferStmt, *ast.SendStmt:
			s.sinks(n, name, report)

			if es, ok := n.(*ast.ExprStmt); ok {
				if c, ok := es.X.(*ast.CallExpr); ok && callName(c.Fun) == "append" && len(c.Args) > 0 && s.expr(c, 0) {
					s.assign([]ast.Expr{c.Args[0]}, []ast.Expr{c})
				}
			}

			return false
		}

		return true
	})
}

// sinks reports each sink in the expressions of n; a function literal in
// them is walked in order.
func (s *scope) sinks(n ast.Node, name string, report func(token.Pos, string)) {
	ast.Inspect(n, func(m ast.Node) bool {
		switch m := m.(type) {
		case *ast.FuncLit:
			s.walk(m.Body, name, report, false)

			return false
		case *ast.CallExpr:
			if report != nil {
				if what := s.sink(m); what != "" {
					report(m.Pos(), what)
				}
			}

			s.expr(m, 0) // marks the parameters of the suite's functions it calls
		}

		return true
	})
}

// secretSinks reads files, the source of the suite, and returns each call
// that logs or fails with a value that may hold a credential's secret,
// unmasked, outside secretExempt.
func secretSinks(fset *token.FileSet, files map[string]*ast.File) []string {
	f := &flow{params: map[string]map[int]bool{}, results: map[string]map[int]bool{}, sigs: map[string][]*ast.FuncType{}}

	type fn struct {
		file, name string
		typ        *ast.FuncType
		body       *ast.BlockStmt
	}

	var fns []fn

	for path, file := range files {
		for _, d := range file.Decls {
			if d, ok := d.(*ast.FuncDecl); ok {
				f.sigs[d.Name.Name] = append(f.sigs[d.Name.Name], d.Type)
				fns = append(fns, fn{path, d.Name.Name, d.Type, d.Body})
			}
		}
	}

	f.changed = true
	for f.changed {
		f.changed = false

		for _, x := range fns {
			f.walkFunc(x.name, x.typ, x.body, nil)
		}
	}

	var found []string

	for _, x := range fns {
		if _, ok := secretExempt[x.file+":"+x.name]; ok {
			continue
		}

		f.walkFunc(x.name, x.typ, x.body, func(pos token.Pos, what string) {
			p := fset.Position(pos)
			found = append(found, fmt.Sprintf("%s:%d: %s in %s", x.file, p.Line, what, x.name))
		})
	}

	slices.Sort(found)

	return found
}

// TestNoSecretReachesALog fails when a value that may hold a credential's
// secret reaches a log line, a test failure or an error of the suite without
// the masker. It reads the source: a secret enters as a Key (or Secret,
// token) member, or as the output of a command that creates a credential,
// and flows by assignment, by the arguments and results of the suite's own
// functions (matched by name), and through any other call that is given it.
// It cannot see a secret in a container's own logs, a field it does not
// name, or flow through a struct it does not assign.
func TestNoSecretReachesALog(t *testing.T) {
	root := ".."
	fset := token.NewFileSet()
	files := map[string]*ast.File{}

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}

		file, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}

		rel, _ := filepath.Rel(root, path)
		files[filepath.ToSlash(rel)] = file

		return nil
	})
	require.NoError(t, err)

	require.Empty(t, secretSinks(fset, files), "a secret reaches these sinks unmasked: mask it with dockertestutil.Redact or Redactf, or drop it")

	for key := range secretExempt {
		file, fn, _ := strings.Cut(key, ":")

		f, ok := files[file]
		require.True(t, ok, "exemption %s names no file", key)
		require.True(t, slices.ContainsFunc(f.Decls, func(d ast.Decl) bool {
			fd, ok := d.(*ast.FuncDecl)

			return ok && fd.Name.Name == fn
		}), "exemption %s names no function", key)
	}
}

// TestSecretFlowCheck runs the check on a fixture with each shape it must
// see, and the masked and quiet forms it must let through.
func TestSecretFlowCheck(t *testing.T) {
	const src = `package x

func helper(cmd []string) error {
	return fmt.Errorf("failed: %v", cmd)
}

func masked(cmd []string) error {
	return Redactf(nil, "failed: %v", cmd)
}

func mint() string {
	out, _ := headscale.Execute([]string{"headscale", "api", "keys", "create"})

	return strings.TrimSpace(out)
}

func TestX(t *testing.T) {
	key := created.Key
	copied := key
	t.Logf("key %s", copied)
	require.NoError(t, helper([]string{"--authkey=" + key}))
	require.NoError(t, masked([]string{"--authkey=" + key}))
	assert.NotEmpty(t, key)
	api := mint()
	log.Printf("api %s", api)
	log.Printf("api %s", Redact(api))
	t.Logf("length %d", len(key))
	u, _ := client.LoginWithURL(endpoint)
	log.Printf("url %s", u.String())
	log.Printf("url %s", Redact(u.String()))
	id := findSSHCheckAuthID(t, client)
	t.Logf("id %s", id)
	body, _ := fetch(u, hc)
	register(body)
}

// A suite method of the same name must not make url.URL's String clean.
func (n node) String() string { return n.name }

func fetch(u *url.URL, hc *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, "GET", u.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return "", fmt.Errorf("sending: %w", err)
	}
	b, _ := io.ReadAll(resp.Body)
	log.Printf("body: %s", string(b))
	return string(b), nil
}

func register(body string) {
	id := authIDPattern.FindString(body)
	log.Printf("registering %s", id)
}
`

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, "x.go", src, 0)
	require.NoError(t, err)

	require.Equal(t, []string{
		"x.go:20: Logf in TestX",
		"x.go:21: NoError in TestX",
		"x.go:25: Printf in TestX",
		"x.go:29: Printf in TestX",
		"x.go:32: Logf in TestX",
		"x.go:44: Errorf in fetch",
		"x.go:47: Printf in fetch",
		"x.go:4: Errorf in helper",
		"x.go:53: Printf in register",
	}, secretSinks(fset, map[string]*ast.File{"x.go": file}))
}

// TestSecretFlowBounds: a create whose command is bound to a name before it
// runs, and a result that a wrapper forwards past result zero, still reach
// the sink.
func TestSecretFlowBounds(t *testing.T) {
	for name, src := range map[string]string{
		"a bound command": `package x
func run() {
	argv := []string{"headscale", "api", "keys", "create"}
	out, _ := runner.Execute(argv)
	log.Printf("%s", out)
}`,
		"a forwarded second result": `package x
func record() (string, string) { return "name", response.Key }
func wrapper() (string, string) { return record() }
func run() {
	_, result := wrapper()
	log.Printf("%s", result)
}`,
	} {
		t.Run(name, func(t *testing.T) {
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, "x.go", src, 0)
			require.NoError(t, err)

			require.Len(t, secretSinks(fset, map[string]*ast.File{"x.go": file}), 1)
		})
	}
}
