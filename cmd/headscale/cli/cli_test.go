package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	gotypes "go/types"
	"io"
	"io/fs"
	"maps"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmd/headscale/cli/command"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// cliCase is one run of the CLI: a row of the table of a command group.
// Every case runs on a server of its own, so a case that writes changes
// no other.
type cliCase struct {
	name string
	// setup prepares the case's server and fills vars, after the setup of
	// the table: a case that needs state, or an order, makes it here.
	setup func(t testing.TB, f *fixture)
	// args is the line after "headscale", split as a shell splits it.
	args string
	// env is added to the fixture's environment.
	env []string
	// stdin is what the case types; terminal says whether stdin and stdout
	// are one, and piped that stdin is a pipe all the same, as in
	// "echo | headscale nodes delete 12".
	stdin    string
	terminal bool
	piped    bool
	// width is the width of that terminal in cells; 0 cuts nothing.
	width int
	// clock is the fixture's clock as a function of the wall clock; nil is
	// the wall clock. The server's own clock stays the wall clock.
	clock func(wall time.Time) time.Time
	// release is the version the binary claims to be; "" is the test
	// binary's, which is no release.
	release string
	// pageSize is the rows of a page of a walk: 0 is 2, so a walk of more
	// than two rows reads more than one page; cliPages is the CLI's own.
	pageSize int
	// stdout and stderr are compared whole, after {name} is replaced with
	// the fixture's var of that name. want gives stdout where a literal
	// cannot, such as the JSON that the server sent in this run; a case
	// sets stdout or want, not both.
	stdout, stderr string
	want           func(t testing.TB, f *fixture, r result) string
	code           int
	// check runs after the comparison: a read of the state back through
	// the API after a write.
	check func(t testing.TB, f *fixture, r result)
	// answered runs as each answer of the server arrives, before the CLI
	// reads it, with the request as "METHOD path?query": a case changes the
	// state there between the CLI's read and its write.
	answered func(t testing.TB, f *fixture, req string)
	// clients is a server that Tailscale clients of the test can join,
	// over its memory network; it has no TCP listener then.
	clients bool
	// server are options of the case's server beyond the fixture's own.
	server []servertest.ServerOption
	// until runs beside a command that runs until it is stopped, such as
	// serve, and stops it when it returns, as a signal does. It returns
	// when ctx ends, which the end of the command brings.
	until func(ctx context.Context, f *fixture)
}

type result struct {
	stdout, stderr string
	code           int
	// answers are the bodies the server sent in this run, by path, in the
	// order sent; asked are the requests that got an answer, as "METHOD
	// path?query". sent is every request that left for the server, answered
	// or not, GET /version among them, as "METHOD path?query body", and
	// headers the headers of each.
	answers map[string][][]byte
	asked   []string
	sent    []string
	headers []http.Header
}

// fixture is the server of one case, reached over its socket and its TCP
// listener, with no config file of the machine in the way.
type fixture struct {
	srv *servertest.TestServer
	now time.Time
	env []string
	// vars fill the {name} places in a case.
	vars map[string]string
	// releases are the release tags that `version` sees; no case reaches
	// GitHub.
	releases []string
	// changes counts the changes a case's answered made.
	changes int
}

func newFixture(
	tb testing.TB,
	clients bool,
	server ...servertest.ServerOption,
) *fixture {
	tb.Helper()

	return newFixtureAt(tb, clients, nil, server...)
}

// newFixtureAt is newFixture with its clock as clock makes it of the wall
// clock.
func newFixtureAt(
	tb testing.TB,
	clients bool,
	clock func(time.Time) time.Time,
	server ...servertest.ServerOption,
) *fixture {
	tb.Helper()

	// One clock for the CLI and for the last seen v0 reports for a connected
	// node ("now"), or a minute could pass between them.
	now := time.Now()
	if clock != nil {
		now = clock(now)
	}

	now = now.UTC().Truncate(time.Second)

	// The node store waits for a batch to fill; a test does not.
	opts := append([]servertest.ServerOption{
		servertest.WithNodeStoreBatchTimeout(time.Millisecond),
		servertest.WithConnectedSeen(func() time.Time { return now }),
	}, server...)
	if !clients {
		opts = append(opts, servertest.WithRealListener())
	}

	srv := servertest.NewServer(tb, opts...)

	dir := tb.TempDir()
	file := filepath.Join(dir, "config.yaml")
	require.NoError(tb, os.WriteFile(file, nil, 0o600))

	return &fixture{
		srv: srv,
		now: now,
		env: []string{
			"HEADSCALE_CONFIG=" + file,
			"HEADSCALE_UNIX_SOCKET=" + srv.SocketPath,
			// A case with no server does not wait the default 5s.
			"HEADSCALE_CLI_TIMEOUT=3s",
			"HOME=" + dir,
		},
		vars: map[string]string{"socket": srv.SocketPath, "url": srv.URL},
	}
}

func (f *fixture) expand(s string) string {
	pairs := make([]string, 0, 2*len(f.vars))
	for k, v := range f.vars {
		pairs = append(pairs, "{"+k+"}", v)
	}

	return strings.NewReplacer(pairs...).Replace(s)
}

// run runs the real tree in the test, as `headscale <args>` would, with
// its own tree, stdin, terminal, environment, build and clock.
func (f *fixture) run(tb testing.TB, tc cliCase) result {
	tb.Helper()

	env := slices.Clone(f.env)
	for _, e := range tc.env {
		env = append(env, f.expand(e))
	}

	build := types.GetVersionInfo()
	if tc.release != "" {
		v := *build
		v.Version = tc.release
		build = &v
	}

	var (
		out, errOut bytes.Buffer
		mu          sync.Mutex
		answers     = map[string][][]byte{}
		asked, sent []string
		headers     []http.Header
	)

	pageSize := tc.pageSize
	if pageSize == 0 {
		pageSize = 2
	}

	if tc.pageSize == cliPages {
		pageSize = 0
	}

	// A command that until never stops ends here, and fails its case.
	ctx, stop := context.WithTimeout(tb.Context(), time.Minute)
	until := make(chan struct{})

	go func() {
		defer close(until)

		if tc.until != nil {
			tc.until(ctx, f)
			stop()
		}
	}()

	// The command has ended: so does until, before the case reads what it
	// found.
	defer func() {
		stop()
		<-until
	}()

	code := command.Run(Tree(), words(f.expand(shell(tc.args))), command.Env{
		Context:        ctx,
		Stdin:          strings.NewReader(f.expand(tc.stdin)),
		Stdout:         &out,
		Stderr:         &errOut,
		Environ:        env,
		Terminal:       tc.terminal && !tc.piped,
		StdoutTerminal: tc.terminal,
		Width:          tc.width,
		StderrWidth:    tc.width,
		PageSize:       pageSize,
		Now:            func() time.Time { return f.now },
		Version:        build,
		Releases:       func(context.Context) ([]string, error) { return f.releases, nil },
		Answered: func(req *http.Request, body []byte) {
			mu.Lock()
			defer mu.Unlock()

			answers[req.URL.Path] = append(answers[req.URL.Path], body)
			asked = append(asked, req.Method+" "+req.URL.RequestURI())

			if tc.answered != nil {
				tc.answered(tb, f, req.Method+" "+req.URL.RequestURI())
			}
		},
		Sent: func(req *http.Request) {
			mu.Lock()
			defer mu.Unlock()

			sent = append(sent, req.Method+" "+req.URL.RequestURI()+" "+bodyOf(tb, req))
			headers = append(headers, req.Header.Clone())
		},
	})

	return result{
		stdout:  out.String(),
		stderr:  errOut.String(),
		code:    code,
		answers: answers,
		asked:   asked,
		sent:    sent,
		headers: headers,
	}
}

// bodyOf is the body the CLI sent with req, read again.
func bodyOf(tb testing.TB, req *http.Request) string {
	tb.Helper()

	if req.GetBody == nil {
		return ""
	}

	body, err := req.GetBody()
	require.NoError(tb, err)

	b, err := io.ReadAll(body)
	require.NoError(tb, err)

	return string(b)
}

// cliPages is a case that walks with the page size of the CLI.
const cliPages = -1

// token is an access token of an OAuth client with scopes, for a case that
// calls as a credential with less than the socket may do.
func (f *fixture) token(tb testing.TB, scopes ...string) string {
	tb.Helper()

	return f.taggedToken(tb, nil, scopes...)
}

// taggedToken is an access token with scopes that holds tags.
func (f *fixture) taggedToken(tb testing.TB, tags []string, scopes ...string) string {
	tb.Helper()

	_, client, err := f.srv.State().CreateOAuthClient(scopes, tags, "ci", nil)
	require.NoError(tb, err)

	expiry := f.now.Add(time.Hour)
	token, _, err := f.srv.State().
		MintAccessToken(client.ClientID, scopes, tags, &expiry)
	require.NoError(tb, err)

	return token
}

// runCases runs the cases of a table, in parallel, each on a server of its
// own, after setup. Every case it runs is recorded for the walk in
// TestMain.
func runCases(t *testing.T, setup func(testing.TB, *fixture), cases []cliCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			runCase(t, setup, tc)
		})
	}
}

// runCasesIn runs cases one after the other in a directory that holds
// files, by name, as a person runs a command next to its files: {dir} is
// that directory. The working directory is the process's, so neither the
// cases nor the test may be parallel.
func runCasesIn(
	t *testing.T,
	files map[string]string,
	setup func(testing.TB, *fixture),
	cases []cliCase,
) {
	t.Helper()

	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}

	t.Chdir(dir)

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			runCase(t, func(tb testing.TB, f *fixture) {
				tb.Helper()

				f.vars["dir"] = dir

				if setup != nil {
					setup(tb, f)
				}
			}, tc)
		})
	}
}

// runCase runs one case of runCases on a server of its own, after setup;
// a test that sets the working directory runs its cases with it, one after
// the other.
func runCase(t *testing.T, setup func(testing.TB, *fixture), tc cliCase) {
	t.Helper()

	require.False(
		t,
		tc.stdout != "" && tc.want != nil,
		"a case sets stdout or want, not both",
	)

	f := newFixtureAt(t, tc.clients, tc.clock, tc.server...)
	if setup != nil {
		setup(t, f)
	}

	if tc.setup != nil {
		tc.setup(t, f)
	}

	r := f.run(t, tc)
	ran.add(tc, f)

	want := f.expand(tc.stdout)
	if tc.want != nil {
		want = tc.want(t, f, r)
	}

	if diff := cmp.Diff(want, r.stdout); diff != "" {
		t.Errorf("stdout (-want +got):\n%s", diff)
	}

	if diff := cmp.Diff(f.expand(tc.stderr), r.stderr); diff != "" {
		t.Errorf("stderr (-want +got):\n%s", diff)
	}

	require.Equal(t, tc.code, r.code, "exit code")

	if tc.check != nil {
		tc.check(t, f, r)
	}
}

// listAt is a list of the API: its path, and the key of the rows in a
// page.
type listAt struct{ path, items string }

// answer is the body that the server sent for path in this run, as -o json
// prints it.
func answer(path string) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		bodies := r.answers[path]
		require.NotEmpty(tb, bodies, "no answer for %s", path)

		return indent(tb, bodies[len(bodies)-1])
	}
}

// rows is what -o json prints for a list: the rows of every page the
// server sent for it, as they came, that keep says to keep.
func (l listAt) rows(
	keep func(row map[string]any) bool,
) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		b, err := json.Marshal(l.kept(tb, r, keep))
		require.NoError(tb, err)

		return indent(tb, b)
	}
}

// row is what -o json prints for one row of a list: a target that a walk
// found.
func (l listAt) row(
	keep func(row map[string]any) bool,
) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		found := l.kept(tb, r, keep)
		require.Len(tb, found, 1)

		return indent(tb, found[0])
	}
}

func (l listAt) kept(
	tb testing.TB,
	r result,
	keep func(row map[string]any) bool,
) []json.RawMessage {
	tb.Helper()

	out := []json.RawMessage{}

	for _, body := range r.answers[l.path] {
		var page map[string]json.RawMessage
		require.NoError(tb, json.Unmarshal(body, &page))

		var list []json.RawMessage
		require.NoError(tb, json.Unmarshal(page[l.items], &list))

		for _, raw := range list {
			var row map[string]any
			require.NoError(tb, json.Unmarshal(raw, &row))

			if keep(row) {
				out = append(out, raw)
			}
		}
	}

	return out
}

func indent(tb testing.TB, body []byte) string {
	tb.Helper()

	var b bytes.Buffer
	require.NoError(tb, json.Indent(&b, bytes.TrimSpace(body), "", "  "))

	return b.String() + "\n"
}

// shell reads the shell variable an example may hold, $id, as the
// fixture's var id, so the example runs as it is written; the walk sees it
// unread.
func shell(line string) string {
	return strings.ReplaceAll(line, "$id", "{id}")
}

// words splits a line as a shell does, for the quotes the examples use.
func words(line string) []string {
	var (
		out   []string
		cur   strings.Builder
		quote rune
		in    bool
	)

	for _, r := range line {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			cur.WriteRune(r)
		case r == '\'' || r == '"':
			quote, in = r, true
		case r == ' ':
			if in {
				out = append(out, cur.String())
				cur.Reset()
			}

			in = false
		default:
			cur.WriteRune(r)

			in = true
		}
	}

	if in {
		out = append(out, cur.String())
	}

	return out
}

// ranCase is a case as the walk sees it: what it ran and what it expected.
type ranCase struct {
	words []string
	// env are the names of the variables the case set.
	env  []string
	code int
}

// ranCases are the cases that ran in this process.
type ranCases struct {
	mu    sync.Mutex
	cases []ranCase
}

var ran ranCases

func (r *ranCases) add(tc cliCase, f *fixture) {
	c := ranCase{words: words(f.expand(tc.args)), code: tc.code}
	for _, e := range tc.env {
		name, _, _ := strings.Cut(e, "=")
		c.env = append(c.env, name)
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	r.cases = append(r.cases, c)
}

// TestMain walks the tree after every test has run: a command, an example
// or an alias that no case ran fails the run. It walks only a whole run,
// since -run leaves cases out.
func TestMain(m *testing.M) {
	if line, ok := os.LookupEnv(childLine); ok {
		os.Exit(child(line))
	}

	if _, ok := os.LookupEnv(holdDB); ok {
		os.Exit(hold())
	}

	// A check of a property here runs CLI processes against a server: the
	// default run makes a few, and the soak gives the count itself.
	flag.Parse()

	given := false

	flag.Visit(func(f *flag.Flag) { given = given || f.Name == "rapid.checks" })

	if n, ok := defaultChecks(given, os.LookupEnv); ok {
		_ = flag.Set("rapid.checks", n)
	}

	code := m.Run()

	if code == 0 && flag.Lookup("test.run").Value.String() == "" &&
		flag.Lookup("test.skip").Value.String() == "" {
		if missing := untested(Tree(), ran.cases); len(missing) > 0 {
			fmt.Fprintln(
				os.Stderr,
				"FAIL: the walk of the command tree:\n  "+strings.Join(missing, "\n  "),
			)

			code = 1
		}
	}

	os.Exit(code)
}

// defaultChecks is the number of checks a property of this package makes
// when the run gives none: Rapid reads RAPID_CHECKS as the default of
// -rapid.checks, and the flag over it, so either one, 0 included, is kept.
func defaultChecks(flagGiven bool, env func(string) (string, bool)) (string, bool) {
	if _, ok := env("RAPID_CHECKS"); ok || flagGiven {
		return "", false
	}

	return "10", true
}

// untested lists each example that no case runs with exit 0, and each
// alias that no case uses with exit 0; every command has an example, so a
// command with no case shows. An example's environment prefix, such as
// HEADSCALE_CLI_ADDRESS=x, needs a case that sets that variable.
func untested(tree *command.Tree, cases []ranCase) []string {
	var missing []string

	passes := func(match func(c ranCase) bool) bool {
		return slices.ContainsFunc(
			cases,
			func(c ranCase) bool { return c.code == 0 && match(c) },
		)
	}

	for _, c := range tree.Commands() {
		for _, e := range c.Example {
			env, line := exampleWords(e)
			if tree.Reached(line) != c.Path || !passes(func(rc ranCase) bool {
				return slices.Equal(rc.words, line) &&
					!slices.ContainsFunc(
						env,
						func(n string) bool { return !slices.Contains(rc.env, n) },
					)
			}) {
				missing = append(missing, `example "`+e+`" has no case that passes`)
			}
		}

		// The alias must be the word that chose the command: the words
		// before it reach the group above.
		parent := c.Path[:max(strings.LastIndex(c.Path, " "), 0)]

		chose := func(rc ranCase, a string) bool {
			i := slices.Index(rc.words, a)

			return i >= 0 && tree.Reached(rc.words[:i]) == parent &&
				tree.Reached(rc.words[:i+1]) == c.Path
		}

		for _, a := range c.Aliases {
			if !passes(func(rc ranCase) bool { return chose(rc, a) }) {
				missing = append(
					missing,
					`alias "`+a+`" of "`+c.Path+`" has no case that passes`,
				)
			}
		}
	}

	return missing
}

// exampleWords are the names of the variables an example sets before
// `headscale`, and its words after it, up to a pipe or a redirect. A
// command a pipe feeds is the example; a case gives what it reads as stdin.
func exampleWords(e string) ([]string, []string) {
	if _, fed, ok := strings.Cut(e, "| headscale "); ok {
		e = "headscale " + fed
	}

	e, _, _ = strings.Cut(e, " |")
	e, _, _ = strings.Cut(e, " >")

	var env []string

	ws := words(e)
	for len(ws) > 0 && ws[0] != "headscale" {
		name, _, _ := strings.Cut(ws[0], "=")
		env = append(env, name)
		ws = ws[1:]
	}

	if len(ws) > 0 {
		ws = ws[1:]
	}

	return env, ws
}

func TestUntested(t *testing.T) {
	t.Parallel()

	ok := func(args string, env ...string) ranCase { return ranCase{words: words(args), env: env} }
	fails := func(args string) ranCase { return ranCase{words: words(args), code: 1} }

	extra := command.New(command.Spec[command.NoInput, command.NoOutput]{
		Name:  "extra",
		Short: "Do nothing",
		Long:  "Do nothing.",
		Local: true,
		Example: []string{
			"headscale extra",
			"HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat",
			"make | headscale extra > out",
		},
		Run: func(command.Ctx, command.NoInput) (command.NoOutput, error) { return command.NoOutput{}, nil },
	})

	tree, err := command.Build("headscale", "short", extra)
	require.NoError(t, err)

	for _, tt := range []struct {
		name  string
		cases []ranCase
		want  []string
	}{
		{
			name:  "every example passes",
			cases: []ranCase{ok("extra"), ok("extra", "HEADSCALE_CLI_ADDRESS")},
		},
		{
			name:  "a pipe into the command and a redirect of it",
			cases: []ranCase{ok("extra", "HEADSCALE_CLI_ADDRESS")},
		},
		{
			name: "a command with no case",
			want: []string{
				`example "headscale extra" has no case that passes`,
				`example "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat" has no case that passes`,
				`example "make | headscale extra > out" has no case that passes`,
			},
		},
		{
			name:  "a help case and a failing case do not count",
			cases: []ranCase{ok("extra --help"), fails("extra")},
			want: []string{
				`example "headscale extra" has no case that passes`,
				`example "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat" has no case that passes`,
				`example "make | headscale extra > out" has no case that passes`,
			},
		},
		{
			name:  "an example's environment needs a case that sets it",
			cases: []ranCase{ok("extra")},
			want:  []string{`example "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat" has no case that passes`},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, untested(tree, tt.cases))
		})
	}

	t.Run("an alias needs a case", func(t *testing.T) {
		t.Parallel()

		tree, err := command.Build(
			"headscale",
			"short",
			command.Group{Name: "items", Short: "Items", Commands: []command.Node{
				command.New(command.Spec[command.NoInput, command.NoOutput]{
					Name:    "delete",
					Short:   "Delete",
					Long:    "Delete.",
					Local:   true,
					Aliases: []string{"rm"},
					Example: []string{"headscale items delete"},
					Confirm: func(command.Ctx, command.NoInput) (command.Prompt, error) { return command.Prompt{}, nil },
					Run:     func(command.Ctx, command.NoInput) (command.NoOutput, error) { return command.NoOutput{}, nil },
				}),
			}},
		)
		require.NoError(t, err)
		require.Equal(
			t,
			[]string{`alias "rm" of "items delete" has no case that passes`},
			untested(tree, []ranCase{ok("items delete")}),
		)
		require.Empty(t, untested(tree, []ranCase{ok("items delete"), ok("items rm")}))
	})
}

// TestTree builds the whole tree, which checks every spec.
func TestTree(t *testing.T) {
	t.Parallel()

	_, err := command.Build("headscale", "short", commands...)
	require.NoError(t, err)
}

func TestWords(t *testing.T) {
	t.Parallel()

	require.Equal(t, []string{"a", "b c", "", "d'e"}, words(`a "b c" '' "d'e"`))
	require.Empty(t, words(""))
}

// TestImports holds what a command may not do by hand: print or exit (fmt,
// os), make its own client or call the server around the facade (net/http,
// clientv0.NewClient), or read the parser. A message names an entity
// through table.Entity, which it cannot do with Sprintf.
func TestImports(t *testing.T) {
	t.Parallel()

	banned := map[string]string{
		`"fmt"`:      "a command returns what it prints; a message names an entity with table.Entity",
		`"os"`:       "a command returns what it prints, and the builder exits",
		`"net/http"`: "a command calls the server through command.API",
		`"github.com/juanfont/headscale/cmdline"`: "only package command reads the parser",
	}

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)

		for _, imp := range f.Imports {
			if why, ok := banned[imp.Path.Value]; ok {
				t.Errorf("%s imports %s: %s", name, imp.Path.Value, why)
			}

			// The database bypass is the one way past the server, and only
			// the policy commands take it.
			server := strings.HasPrefix(
				imp.Path.Value,
				`"github.com/juanfont/headscale/hscontrol/`,
			) &&
				!slices.Contains(
					[]string{
						`"github.com/juanfont/headscale/hscontrol/config"`,
						`"github.com/juanfont/headscale/hscontrol/types"`,
					},
					imp.Path.Value,
				)
			if server &&
				(name != "policy.go" || imp.Path.Value != `"github.com/juanfont/headscale/hscontrol/offline"`) {
				t.Errorf(
					"%s imports %s: a command reaches the server through command.API; only policy.go opens a stopped server's database, through offline",
					name,
					imp.Path.Value,
				)
			}
		}

		src, err := os.ReadFile(name)
		require.NoError(t, err)
		require.NotRegexp(
			t,
			`clientv0\.NewClient`,
			string(src),
			"%s makes its own client: it skips the version check",
			name,
		)
	}

	// serve is the server, and only its log is written past the edge that
	// masks a credential: through zerolog, or ServerOutput. Run turns the
	// log off for every other command, and does nothing else with it.
	more, err := filepath.Glob("*/*.go")
	require.NoError(t, err)

	const off = "zerolog.SetGlobalLevel(zerolog.Disabled)"

	for _, name := range append(files, more...) {
		if name == "serve.go" || strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)

		src, err := os.ReadFile(name)
		require.NoError(t, err)

		for _, imp := range f.Imports {
			if !strings.HasPrefix(imp.Path.Value, `"github.com/rs/zerolog`) {
				continue
			}

			if name == filepath.Join("command", "command.go") &&
				imp.Path.Value == `"github.com/rs/zerolog"` &&
				strings.Count(
					string(src),
					"zerolog.",
				) == 2*strings.Count(
					string(src),
					off,
				) {
				continue
			}

			t.Errorf(
				"%s imports %s: only serve writes a log, and Run only turns it off with %s",
				name,
				imp.Path.Value,
				off,
			)
		}

		require.NotRegexp(
			t,
			`\.ServerOutput\(|hscontrol\.(UseLogConfig|LogWarnings)\(`,
			string(src),
			"%s writes a server's log: only serve does",
			name,
		)
	}
}

// TestOneRule: every answer the CLI reads passes the one rule of the
// generated client, Result or Err (Got, Done), or a list's All or Pages,
// which hold it to the status, the media type and the shape the document
// gives it. A call of a method of the generated client that returns the
// raw *http.Response, a Parse function, or a read of a generated answer's
// fields (its body, its JSON2xx, its HTTPResponse) goes round the rule; no
// file of the CLI makes one, but those named in allowed, with why. The walk
// reads names, not types: it follows the import's alias, and the names
// assigned from an XWithResponse call; an answer handed on through another
// name or a function, or a raw method of the client called through a value
// of an interface of the CLI's, is not seen.
func TestOneRule(t *testing.T) {
	t.Parallel()

	gen, err := parser.ParseFile(
		token.NewFileSet(),
		"../../../gen/client/headscale/v0/client.gen.go",
		nil,
		0,
	)
	require.NoError(t, err)

	// raw are the methods of the generated *Client: each returns the
	// answer unread.
	raw := map[string]bool{}

	for _, d := range gen.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Recv != nil &&
			gotypes.ExprString(fn.Recv.List[0].Type) == "*Client" {
			raw[fn.Name.Name] = true
		}
	}

	require.Contains(t, raw, "GetNode")

	// allowed are the reads round the rule, by file and the text of the
	// expression, with why.
	allowed := map[string]string{
		"generate.go resp.Body": "the YAML of GET /config, after resp.Err()",
		// The names of the rule are read without types: a method of
		// another type with a name of the client's is not the client's.
		"policy.go d.SetPolicy": "offline.DB, the database of a stopped server",
	}

	files, err := filepath.Glob("*.go")
	require.NoError(t, err)

	more, err := filepath.Glob("command/*.go")
	require.NoError(t, err)

	for _, name := range append(files, more...) {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}

		f, err := parser.ParseFile(token.NewFileSet(), name, nil, 0)
		require.NoError(t, err)

		// gen is the name the file gives the generated client's package: its
		// alias, or its package name.
		gen := ""

		for _, imp := range f.Imports {
			if imp.Path.Value == `"github.com/juanfont/headscale/gen/client/headscale/v0"` {
				gen = "clientv0"
				if imp.Name != nil {
					gen = imp.Name.Name
				}
			}
		}

		// answers are the names that hold a generated answer: assigned from
		// a call of an XWithResponse method.
		answers := map[string]bool{}

		ast.Inspect(f, func(n ast.Node) bool {
			if as, ok := n.(*ast.AssignStmt); ok && len(as.Rhs) == 1 {
				if call, ok := as.Rhs[0].(*ast.CallExpr); ok {
					if sel, ok := call.Fun.(*ast.SelectorExpr); ok &&
						strings.HasSuffix(sel.Sel.Name, "WithResponse") {
						if id, ok := as.Lhs[0].(*ast.Ident); ok {
							answers[id.Name] = true
						}
					}
				}
			}

			sel, ok := n.(*ast.SelectorExpr)
			if !ok {
				return true
			}

			text := gotypes.ExprString(sel)
			field := sel.Sel.Name
			id, onAnswer := sel.X.(*ast.Ident)
			onAnswer = onAnswer && answers[id.Name]

			var why string

			switch {
			case gen != "" && gotypes.ExprString(sel.X) == gen && strings.HasPrefix(field, "Parse"):
				why = "a Parse function reads an answer round Result"
			case raw[field] && gotypes.ExprString(sel.X) != gen:
				why = "a method of the generated *Client returns the answer unread"
			case onAnswer && (field == "Body" || field == "HTTPResponse" ||
				strings.HasPrefix(field, "JSON") ||
				strings.HasPrefix(field, "Applicationproblem")):
				why = "a field of a generated answer is read round Result and Err"
			}

			if why != "" {
				if _, ok := allowed[name+" "+text]; !ok {
					t.Errorf("%s: %s: %s", name, text, why)
				}
			}

			return true
		})
	}
}

// TestRootHelp compares the root help with the alignment of its short
// texts folded to three spaces, so a new command adds its line and changes
// no other. The alignment is the help's own test, in package command.
func TestRootHelp(t *testing.T) {
	t.Parallel()

	fold := regexp.MustCompile(`(\S)   +(\S)`)

	for _, args := range [][]string{nil, {"--help"}} {
		var b bytes.Buffer

		require.Equal(t, 0, command.Run(Tree(), args, command.Env{Stdout: &b}))
		require.Equal(
			t,
			rootHelp,
			fold.ReplaceAllString(b.String(), "$1   $2"),
			strconv.Quote(strings.Join(args, " ")),
		)
	}
}

const rootHelp = `headscale is an open source implementation of the Tailscale control server

Local commands (no server needed):

  serve   Run the control server
  version   Print the version
  check config [file]   Check a config file
  check policy <file>   Check a policy file and run its tests
  check derp-map <file>   Check a DERP map file
  check extra-records <file>   Check an extra records file
  check all [config-file]   Check the config and every file it points at
  generate private-key   Print a new private key
  generate config   Print a configuration file with every key
  generate nixos-options   Print the NixOS options for services.headscale.settings
  generate cli-reference   Print the reference page of the command line
  generate man   Print the man page
  completion <shell>   Print the completion script of a shell

Server commands (talk to a running headscale):

  nodes list   List the nodes (alias: ls)
  nodes get <node>   Show one node
  nodes set <node>   Change the name or expiry of a node
  nodes expire <node>   Log a node out
  nodes delete <node>   Delete a node (alias: rm)
  nodes update-client <node>   Ask a node to update its Tailscale client
  nodes routes list [node]   List routes (alias: ls)
  nodes routes set <node> <routes>   Replace the enabled routes of a node (alias: approve)
  nodes routes clear <node>   Remove all enabled routes of a node
  nodes tags list [node]   List tags and their nodes (alias: ls)
  nodes tags set <node> <tags>   Replace the tags of a node
  users list   List the users (alias: ls)
  users get <user>   Show one user
  users create <name>   Create a local user
  users set <user>   Change a local user
  users delete <user>   Delete a user with its keys (alias: rm)
  auth register <auth-id> <user>   Register a node that waits to join
  auth approve <auth-id>   Let an SSH check pass
  auth reject <auth-id>   Refuse a registration or an SSH check
  auth keys list   List the auth keys (alias: ls)
  auth keys get <key>   Show one auth key
  auth keys create <owner>   Create an auth key
  auth keys delete <key>   Revoke an auth key (alias: rm)
  api whoami   Show who the server sees calling
  api keys list   List the API keys (alias: ls)
  api keys get <key>   Show one API key
  api keys create   Create an API key
  api keys delete <key>   Revoke an API key (alias: rm)
  api oauth-clients list   List the OAuth clients (alias: ls)
  api oauth-clients get <client>   Show one OAuth client
  api oauth-clients create <scopes>   Create an OAuth client
  api oauth-clients delete <client>   Revoke an OAuth client (alias: rm)
  policy get   Print the policy
  policy set <file>   Replace the policy
  policy reload   Read the policy again from where it is kept

Debug:

  debug health   Check that the server is healthy
  debug create-node   Make a registration of a made-up node, for tests
  debug mockoidc   Run a mock OIDC server for tests

Server commands take -o json, which prints the API object.
See ` + "`headscale <command> --help`" + ` for examples.
`

// TestUntestedCredit: the walk credits an example only to the command it
// reaches, and an alias only to a case where that alias chose the command,
// not where the word appears later on the line.
func TestUntestedCredit(t *testing.T) {
	t.Parallel()

	spec := func(name string, aliases ...string) command.Node {
		return command.New(command.Spec[command.NoInput, command.NoOutput]{
			Name:    name,
			Aliases: aliases,
			Short:   "S",
			Long:    "S.",
			Example: []string{"headscale widgets list"},
			Local:   true,
			Run:     func(command.Ctx, command.NoInput) (command.NoOutput, error) { return command.NoOutput{}, nil },
		})
	}

	tree, err := command.Build(
		"headscale",
		"A program",
		command.Group{
			Name:     "widgets",
			Short:    "S",
			Commands: []command.Node{spec("list", "ls"), spec("second")},
		},
	)
	require.NoError(t, err)

	got := untested(
		tree,
		[]ranCase{
			{words: []string{"widgets", "list"}},
			{words: []string{"widgets", "list", "ls"}},
		},
	)
	require.Equal(t, []string{
		`alias "ls" of "widgets list" has no case that passes`,
		`example "headscale widgets list" has no case that passes`,
	}, got)

	// second's example is copied from list, so nothing can credit it.
	require.Equal(
		t,
		[]string{`example "headscale widgets list" has no case that passes`},
		untested(
			tree,
			[]ranCase{
				{words: []string{"widgets", "ls"}},
				{words: []string{"widgets", "list"}},
				{words: []string{"widgets", "second"}},
			},
		),
	)
}

// dockerExempt are the commands that no test of the Docker integration
// suite calls, each with why that is enough.
var dockerExempt = map[string]string{
	"serve":                  "every test starts it: the entrypoint hsic builds runs headscale serve",
	"completion":             "local: prints a script; the real-shell and kit tests run it in each shell",
	"check derp-map":         "local: the test config names no DERP map file; the real-shell and check tests run it",
	"check extra-records":    "local: the test config names no extra records file; the real-shell and check tests run it",
	"generate nixos-options": "local: prints the options of the config; the check of generated files runs it",
	"generate cli-reference": "local: prints the reference page of the tree; the check of generated files runs it",
	"generate man":           "local: prints the man page of the tree; the check of generated files runs it",
}

// shellSplit cuts a shell line into its simple commands.
var shellSplit = regexp.MustCompile(`&&|\|\||[;|\n]`)

// dockerCalls reads the call sites of the CLI in f, the source of the
// integration suite: a []string literal that starts with "headscale" or the
// constant binHeadscale, up to its first word that is not a literal; and a
// []string literal that runs a shell with -c, whose line (a literal, or the
// format of fmt.Sprintf) has simple commands that start with headscale. It
// returns the command each reaches, and the sites that reach none: a call of
// a command the tree lacks. A site counts whether or not its test runs.
func dockerCalls(
	tree *command.Tree,
	fset *token.FileSet,
	f *ast.File,
) (map[string]bool, []string) {
	ran := map[string]bool{}

	var wrong []string

	reach := func(pos token.Pos, argv []string) {
		if path := tree.Reached(argv); isLeaf(tree, path) {
			ran[path] = true
		} else {
			wrong = append(
				wrong,
				fmt.Sprintf(
					"%s: headscale %s",
					fset.Position(pos),
					strings.Join(argv, " "),
				),
			)
		}
	}

	ast.Inspect(f, func(n ast.Node) bool {
		lit, ok := n.(*ast.CompositeLit)
		if !ok || len(lit.Elts) < 2 {
			return true
		}

		words := literals(lit.Elts)

		switch {
		case isHeadscale(lit.Elts[0]):
			if len(words) > 1 {
				reach(lit.Pos(), words[1:])
			}
		case len(words) >= 2 && slices.Contains([]string{"sh", "bash", "/bin/sh", "/bin/bash"}, words[0]) && words[1] == "-c" && len(lit.Elts) > 2:
			line, ok := shellLine(lit.Elts[2])
			if !ok {
				return true
			}

			for _, simple := range shellSplit.Split(line, -1) {
				fields := strings.Fields(simple)
				for len(fields) > 0 && strings.Contains(fields[0], "=") {
					fields = fields[1:]
				}

				if len(fields) == 0 || path.Base(fields[0]) != "headscale" {
					continue
				}

				argv := fields[1:]
				for i, w := range argv {
					if strings.ContainsAny(w, "<>") {
						argv = argv[:i]

						break
					}
				}

				reach(lit.Pos(), argv)
			}
		}

		return true
	})

	return ran, wrong
}

// literals are the leading string literals of elts, unquoted.
func literals(elts []ast.Expr) []string {
	var out []string

	for _, e := range elts {
		if isHeadscale(e) && len(out) == 0 {
			out = append(out, "headscale")

			continue
		}

		lit, ok := e.(*ast.BasicLit)
		if !ok || lit.Kind != token.STRING {
			break
		}

		s, err := strconv.Unquote(lit.Value)
		if err != nil {
			break
		}

		out = append(out, s)
	}

	return out
}

// shellLine is the text of a shell's -c argument: a literal, or the format
// of fmt.Sprintf.
func shellLine(e ast.Expr) (string, bool) {
	if call, ok := e.(*ast.CallExpr); ok {
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Sprintf" || len(call.Args) == 0 {
			return "", false
		}

		e = call.Args[0]
	}

	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}

	s, err := strconv.Unquote(lit.Value)

	return s, err == nil
}

func isHeadscale(e ast.Expr) bool {
	switch e := e.(type) {
	case *ast.BasicLit:
		return e.Value == `"headscale"`
	case *ast.Ident:
		return e.Name == "binHeadscale"
	}

	return false
}

func isLeaf(tree *command.Tree, path string) bool {
	return slices.ContainsFunc(
		tree.Commands(),
		func(c command.Command) bool { return c.Path == path },
	)
}

// TestEveryCommandHasAnIntegrationCallSite fails when a command of the tree
// has no call site in the source of the Docker integration suite and is not
// in dockerExempt, and when a call site names a command the tree lacks. It
// measures call sites, not runs: a site in a test that skips still counts.
// The suite runs as one CI job a test, and no job sees what another ran.
func TestEveryCommandHasAnIntegrationCallSite(t *testing.T) {
	t.Parallel()

	tree := Tree()
	fset := token.NewFileSet()
	ran := map[string]bool{}

	var wrong []string

	err := filepath.WalkDir(
		filepath.Join("..", "..", "..", "integration"),
		func(path string, d os.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") {
				return err
			}

			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}

			// The unit tests of the container helpers run no command.
			if f.Name.Name == "hsic" && strings.HasSuffix(path, "_test.go") {
				return nil
			}

			r, w := dockerCalls(tree, fset, f)
			maps.Copy(ran, r)

			wrong = append(wrong, w...)

			return nil
		},
	)
	require.NoError(t, err)

	require.Empty(t, wrong, "these call sites reach no command of the tree")

	var missing, stale []string

	for _, c := range tree.Commands() {
		_, exempt := dockerExempt[c.Path]

		switch {
		case !ran[c.Path] && !exempt:
			missing = append(missing, c.Path)
		case ran[c.Path] && exempt:
			stale = append(stale, c.Path)
		}
	}

	for path := range dockerExempt {
		if !isLeaf(tree, path) {
			stale = append(stale, path)
		}
	}

	require.Empty(
		t,
		missing,
		"no call site of the integration suite runs these commands: call each in a test, or exempt it with the reason",
	)
	require.Empty(
		t,
		stale,
		"these exemptions name a command the suite calls, or no command",
	)
}

func TestDockerCalls(t *testing.T) {
	t.Parallel()

	const src = `package x

const binHeadscale = "headscale"

var (
	a = []string{"headscale", "nodes", "list", "--output", "json"}
	b = []string{binHeadscale, "auth", "keys", "create", owner, "--reusable"}
	c = []string{"headscale", "preauthkeys", "list"}
	d = append([]string{"headscale"}, args...)
	e = []string{"sh", "-c", fmt.Sprintf("HEADSCALE_CLI_ADDRESS=%s headscale api whoami --output json 2>&1", addr)}
	f = []string{"sh", "-c", "headscale --config /tmp/example.yaml users list --output json"}
	g = []string{"sh", "-c", "HEADSCALE_CLI_API_KEY=x headscale apikeys list | cat"}
	h = []string{"bash", "-c", "true; /usr/local/bin/headscale debug health"}
	i = "/usr/local/bin/headscale serve"
	j = "headscale nodes list shows every node"
	k = []string{"tailscale", "status"}
)
`

	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "x.go", src, 0)
	require.NoError(t, err)

	ran, wrong := dockerCalls(Tree(), fset, f)
	require.Equal(
		t,
		map[string]bool{
			"nodes list":       true,
			"auth keys create": true,
			"api whoami":       true,
			"users list":       true,
			"debug health":     true,
		},
		ran,
	)
	require.Equal(
		t,
		[]string{
			"x.go:8:6: headscale preauthkeys list",
			"x.go:12:6: headscale apikeys list",
		},
		wrong,
	)
}

// removedRoots are the first words of 0.29's commands and their aliases
// that the tree does not have. Elsewhere a word after the program may be
// prose ("the headscale server"), so at the root only these, and flags,
// count.
var removedRoots = []string{
	"apikey",
	"apikeys",
	"authkey",
	"configtest",
	"dumpConfig",
	"gen",
	"health",
	"help",
	"mockoidc",
	"node",
	"oauth",
	"oauth-client",
	"oauth-clients",
	"oauthclient",
	"oauthclients",
	"pre",
	"preauthkey",
	"preauthkeys",
	"user",
}

// treeSkip are the paths a walk of the repository does not read: what is
// not ours or not text, the tree's own source and fixtures, whose lines
// are held by their own tests and name old commands on purpose, and the
// changelog, whose "before" lines name them too.
var treeSkip = []string{
	"cmd/headscale/cli",
	"gen",
	"vendor",
	"node_modules",
	"control_logs",
	"result",
	"testdata",
	"CHANGELOG.md",
	"docs/ref/cli.md",
	"docs/ref/headscale.1",
}

// treeText is a file whose text can hold a command line.
func treeText(name string) bool {
	switch filepath.Ext(name) {
	case ".md",
		".go",
		".nix",
		".yml",
		".yaml",
		".sh",
		".service",
		".toml",
		".txt",
		".hujson",
		".json":
		return true
	}

	return strings.HasPrefix(name, "Dockerfile") ||
		slices.Contains([]string{"Makefile", "postinst", "postrm", "prerm"}, name)
}

// programAt finds the program where a command starts: at the start of a
// span, after a space, the slash of a path, an opening quote or
// parenthesis.
var programAt = regexp.MustCompile(`headscale["']?[ \t]+`)

// continued is the end of a shell line that goes on in the next.
var continued = regexp.MustCompile(`\\\r?\n[ \t]*`)

// execArray is a command as a list of quoted words, as a Compose healthcheck,
// a Dockerfile's exec form or a JSON array writes it.
var execArray = regexp.MustCompile(
	`\[\s*"(?:[^"\\]|\\.)*"(?:\s*,\s*"(?:[^"\\]|\\.)*")+\s*\]`,
)

// codeSpan is the text between two backticks on a line.
var codeSpan = regexp.MustCompile("`[^`]*`")

// commandSpans are the parts of a file's text that hold code: in Markdown
// a fenced block and a code span, in Go a code span and a string literal,
// elsewhere every line but a comment, whose code spans count. Prose names
// the program too ("the headscale server"), so it is left out.
func commandSpans(name, text string) []string {
	var out []string

	fenced := false

	// A shell line continued with a backslash is one line.
	if filepath.Ext(name) != ".go" {
		text = continued.ReplaceAllString(text, " ")
	}

	for line := range strings.Lines(text) {
		trimmed := strings.TrimSpace(line)
		spans := codeSpan.FindAllString(line, -1)

		switch ext := filepath.Ext(name); {
		case ext == ".md" && strings.HasPrefix(trimmed, "```"):
			fenced = !fenced
		case ext == ".md" && fenced:
			out = append(out, line)
		case ext == ".go":
			for _, q := range regexp.MustCompile(`"(?:[^"\\]|\\.)*"`).FindAllString(line, -1) {
				spans = append(spans, strings.ReplaceAll(q, `\"`, `'`))
			}

			out = append(out, spans...)
		case ext == ".md",
			strings.HasPrefix(trimmed, "#"),
			strings.HasPrefix(trimmed, "//"):
			out = append(out, spans...)
		default:
			out = append(out, line)
		}
	}

	return out
}

// commandLines are the words after the program in each span of a file
// that runs it, up to where the shell or the quote it stands in ends the
// command. A word in quotes is one word.
func commandLines(name, text string) [][]string {
	var out [][]string

	for _, span := range commandSpans(name, text) {
		span = strings.Trim(span, "`")

		// The suite's []string calls are the walk's, in Go.
		for _, arr := range execArray.FindAllString(span, -1) {
			var words []string
			if filepath.Ext(name) == ".go" ||
				json.Unmarshal([]byte(arr), &words) != nil {
				continue
			}

			// The program is the executable: the first word, or after CMD.
			at := slices.IndexFunc(
				words,
				func(w string) bool { return path.Base(w) == "headscale" },
			)
			if (at == 0 || at == 1 && words[0] == "CMD") && at+1 < len(words) {
				out = append(out, words[at+1:])
			}
		}

		// Each match is judged by the character before it, not by a match
		// before it: in docker exec headscale headscale, the container's
		// name ends where the program begins.
		for _, m := range programAt.FindAllStringIndex(span, -1) {
			p := m[0]
			if p > 0 && !strings.ContainsRune(" \t\n/(\"'", rune(span[p-1])) {
				continue
			}

			// A URL or a mount (host:path) ends with a name, not the program,
			// and after a flag the word is its value: --name headscale.
			start := strings.LastIndexAny(span[:p], " \t\"'(") + 1
			if tok := span[start:p]; strings.Contains(tok, ":") {
				continue
			}

			if before := strings.Fields(
				span[:start],
			); len(before) > 0 &&
				strings.HasPrefix(before[len(before)-1], "-") {
				continue
			}

			rest := span[m[1]:]
			if p > 0 && (span[p-1] == '"' || span[p-1] == '\'') {
				open := span[p-1]
				if end := strings.IndexByte(rest, open); end >= 0 {
					rest = rest[:end]
				}
			}

			if words := shellWords(rest); len(words) > 0 && words[0] != "-" {
				out = append(out, words)
			}
		}
	}

	return out
}

// shellWords splits a shell line into words up to its first operator,
// redirect or comment, without quotes. A trailing full stop or comma is
// prose.
func shellWords(s string) []string {
	var (
		out   []string
		word  strings.Builder
		quote rune
		in    bool
	)

	end := func() {
		if in {
			out = append(out, strings.TrimRight(word.String(), ".,:"))
		}

		word.Reset()

		in = false
	}

	for i, r := range s {
		switch {
		case quote != 0 && r == quote:
			quote = 0
		case quote != 0:
			word.WriteRune(r)
		case (r == '"' || r == '\'') && !strings.ContainsRune(s[i+1:], r):
			end()

			return out
		case r == '"' || r == '\'':
			quote, in = r, true
		case r == ' ' || r == '\t' || r == '\n':
			end()
		case strings.ContainsRune("|;&)`\\", r),
			r == '#' && !in,
			r == '>' && !strings.HasPrefix(word.String(), "<"):
			end()

			return out
		default:
			word.WriteRune(r)

			in = true
		}
	}

	end()

	return out
}

// TestCommandLinesInTheTree fails when a command line in the repository
// names a command or flag that the tree does not have: the docs, the nix
// module and test kit, the workflows and actions, the Dockerfiles, the
// packaging, and the texts and comments of the Go code. A line is read as
// a shell reads it, up to its quote or code span, with its backslash
// continuations joined; a command as a list of quoted words (Compose, a
// Dockerfile's exec form, JSON) is read too. Values are not read, so
// placeholders pass. It needs the whole checkout, which the nix checks do
// not give it.
//
// It cannot read: a Go argv of separate literals with no "headscale" word,
// such as exec.Command(bin, "users", "list") (the walk reads the suite's);
// an argv built at run time; a YAML or nix list with one word an item;
// prose outside a code span. At the root it reports only a flag or one of
// 0.29's first words, so a mistyped new command there passes. The floor of
// treeForms counts the lines a file yields, not the form each came from.
func TestCommandLinesInTheTree(t *testing.T) {
	t.Parallel()

	root, err := os.OpenRoot(filepath.Join("..", "..", ".."))
	require.NoError(t, err)
	t.Cleanup(func() { _ = root.Close() })

	// The nix checks build from a source filtered to the Go files and a few
	// pages: no flake.nix. The test-cli job runs this on the whole tree.
	_, err = root.Stat("flake.nix")
	if err != nil {
		t.Skip(
			"a filtered source (the nix checks): the test-cli job reads the whole checkout",
		)
	}

	tree := Tree()

	var wrong []string

	read := map[string]int{}

	err = fs.WalkDir(root.FS(), ".", func(rel string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if slices.Contains(treeSkip, rel) ||
			slices.Contains(treeSkip, d.Name()) && d.IsDir() ||
			d.IsDir() && strings.HasPrefix(d.Name(), ".") && rel != "." &&
				d.Name() != ".github" {
			if d.IsDir() {
				return filepath.SkipDir
			}

			return nil
		}

		if d.IsDir() || !treeText(d.Name()) {
			return nil
		}

		b, err := root.ReadFile(rel)
		if err != nil {
			return err
		}

		for _, argv := range commandLines(d.Name(), string(b)) {
			if len(argv) == 0 {
				continue
			}

			read[rel]++

			path, word := tree.Unknown(argv)

			switch {
			case word == "":
				continue
			case path == "" && !strings.HasPrefix(word, "-") && !slices.Contains(removedRoots, word):
				continue // prose, such as "the headscale server"
			case len(argv) == 1 && (word == "node" || word == "user"):
				continue // a noun: "the headscale user"
			}

			wrong = append(
				wrong,
				fmt.Sprintf(
					"%s: headscale %s (%q)",
					rel,
					strings.Join(argv, " "),
					word,
				),
			)
		}

		return nil
	})
	require.NoError(t, err)

	slices.Sort(wrong)
	require.Empty(
		t,
		slices.Compact(wrong),
		"these lines name a command or flag that headscale does not have",
	)

	for file, form := range treeForms {
		require.Positive(
			t,
			read[file],
			"the walk read no command line in %s (%s): it lost a form, or the file moved",
			file,
			form,
		)
	}
}

// treeForms are files with a form of command line each, which the walk
// must find at least one line in, so a form it stops reading fails it.
var treeForms = map[string]string{
	"docs/ref/routes.md":                      "a fenced Markdown block",
	"docs/ref/tags.md":                        "a Markdown code span",
	"docs/setup/install/container.md":         "a Compose exec array",
	"nix/testkit.nix":                         "shell in a nix string",
	".github/actions/headscale-up/action.yml": "a YAML run block, in $( )",
	"Dockerfile.integration-ci":               "a Dockerfile RUN",
	"packaging/systemd/headscale.service":     "a path to the program",
	"hscontrol/handlers.go":                   "a Go string",
	"hscontrol/types/node.go":                 "a Go format string",
}

func TestCommandLines(t *testing.T) {
	t.Parallel()

	got := commandLines("x.sh", "run `headscale nodes list -o json` now\n"+
		`  KEY=$(./result/bin/headscale auth keys create "$user" --reusable | tr -d x)`+"\n"+
		`succeed("headscale nodes list")`+"\n"+
		"$ headscale users create dave --display-name 'Dave D' # a comment\n"+
		"headscale debug health >/dev/null 2>&1\n"+
		"tailscale up --login-server http://headscale --auth-key KEY\n"+
		"# the headscale server, and `headscale serve`\n"+
		"Description=headscale coordination\n")
	require.Equal(t, [][]string{
		{"auth", "keys", "create", "$user", "--reusable"},
		{"nodes", "list"},
		{"users", "create", "dave", "--display-name", "Dave D"},
		{"debug", "health"},
		{"serve"},
	}, got, "a code span of a shell line is read twice, as the line and as the span")

	require.Equal(
		t,
		[][]string{{"nodes", "set", "%d", "--name", "<name>"}, {"auth", "approve"}},
		commandLines(
			"x.go",
			"// prose: headscale node ID\n"+`fix := fmt.Sprintf("headscale nodes set %d --name <name>", id)`+"\n"+`"headscale auth approve "+id`+"\n",
		),
	)
	require.Equal(
		t,
		[][]string{{"users", "list"}, {"nodes", "list"}},
		commandLines(
			"x.md",
			"the headscale user\n```shell\nheadscale users list\n```\nrun `headscale nodes list`.\n",
		),
	)

	for _, tt := range []struct{ name, file, text string }{
		{"a continued shell line", "x.md", "```shell\nheadscale nodes list \\\n  --identifier 12\n```\n"},
		{"a Compose exec array", "x.yaml", `test: ["CMD", "headscale", "health"]` + "\n"},
		{"a Dockerfile exec form", "Dockerfile", `CMD ["/usr/bin/headscale", "configtest"]` + "\n"},
		{"a RUN with &&", "Dockerfile", "RUN true && headscale nodes rename 1 x\n"},
		{"a Markdown table cell", "x.md", "| `headscale preauthkeys list` | old |\n"},
		{"a YAML run block in $( )", "x.yml", "run: K=$(./result/bin/headscale apikeys create)\n"},
		{"a nix string", "x.nix", `succeed("headscale policy set -f ${p}")` + "\n"},
		{"a Go string", "x.go", `fix := fmt.Sprintf("headscale nodes expire --identifier %d", id)` + "\n"},
		{"a quoted executable", "x.sh", `"./result/bin/headscale" health` + "\n"},
		{"a root flag", "Dockerfile", "RUN headscale --versio\n"},
		{"docker exec into a container named headscale", "x.md", "```shell\ndocker exec -it headscale \\\n  headscale users destroy -n alice\n```\n"},
		{"docker exec without flags", "x.md", "```shell\ndocker exec headscale headscale preauthkeys list\n```\n"},
	} {
		var found bool

		for _, argv := range commandLines(tt.file, tt.text) {
			if _, word := Tree().Unknown(argv); word != "" {
				found = true
			}
		}

		require.True(t, found, "%s: the stale line is not seen", tt.name)
	}

	// Not a call of the program: its name as a flag's value, or a word of
	// another program's array.
	for _, text := range []string{
		"docker run --name headscale --detach img serve\n",
		`RUN ["printf", "%s\n", "headscale", "health"]` + "\n",
	} {
		for _, argv := range commandLines("Dockerfile", text) {
			_, word := Tree().Unknown(argv)
			require.Empty(t, word, "%q is read as a command: %q", text, argv)
		}
	}

	tree := Tree()
	for _, tt := range []struct {
		argv       []string
		path, word string
	}{
		{argv: []string{"nodes", "set", "<id>", "--name", "<name>"}},
		{argv: []string{"auth", "register", "<auth-id>", "<user>"}},
		{argv: []string{"auth", "register", "--auth-id", "<id>"}, path: "auth register", word: "--auth-id"},
		{argv: []string{"nodes", "rename", "12"}, path: "nodes", word: "rename"},
		{argv: []string{"preauthkeys", "list"}, word: "preauthkeys"},
		{argv: []string{"auth", "keys", "create", "tag:a", "-e", "<DURATION>", "--tags", "x"}, path: "auth keys create", word: "--tags"},
	} {
		path, word := tree.Unknown(tt.argv)
		require.Equal(
			t,
			[2]string{tt.path, tt.word},
			[2]string{path, word},
			"%q",
			tt.argv,
		)
	}
}
