package newcli

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
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
	// stdin is what the case types; terminal says whether stdin is one.
	stdin    string
	terminal bool
	// release is the version the binary claims to be; "" is the test
	// binary's, which is no release.
	release string
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
}

type result struct {
	stdout, stderr string
	code           int
	// answers are the bodies the server sent in this run, by path.
	answers map[string][]byte
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
}

func newFixture(tb testing.TB) *fixture {
	tb.Helper()

	// The node store waits for a batch to fill; a test does not.
	srv := servertest.NewServer(tb, servertest.WithRealListener(), servertest.WithNodeStoreBatchTimeout(time.Millisecond))

	dir := tb.TempDir()
	file := filepath.Join(dir, "config.yaml")
	require.NoError(tb, os.WriteFile(file, nil, 0o600))

	return &fixture{
		srv: srv,
		now: time.Now().UTC().Truncate(time.Second),
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
		answers     = map[string][]byte{}
	)

	code := command.Run(Tree(), words(f.expand(tc.args)), command.Env{
		Stdin:    strings.NewReader(f.expand(tc.stdin)),
		Stdout:   &out,
		Stderr:   &errOut,
		Environ:  env,
		Terminal: tc.terminal,
		Now:      func() time.Time { return f.now },
		Version:  build,
		Releases: func(context.Context) ([]string, error) { return f.releases, nil },
		Answered: func(req *http.Request, body []byte) {
			mu.Lock()
			defer mu.Unlock()

			answers[req.URL.Path] = body
		},
	})

	return result{stdout: out.String(), stderr: errOut.String(), code: code, answers: answers}
}

// runCases runs the cases of a table, in parallel, each on a server of its
// own, after setup. Every case it runs is recorded for the walk in
// TestMain.
func runCases(t *testing.T, setup func(testing.TB, *fixture), cases []cliCase) {
	t.Helper()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			require.False(t, tc.stdout != "" && tc.want != nil, "a case sets stdout or want, not both")

			f := newFixture(t)
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
		})
	}
}

// answer is the body that the server sent for path in this run, as -o json
// prints it.
func answer(path string) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		body, ok := r.answers[path]
		require.True(tb, ok, "no answer for %s", path)

		var b bytes.Buffer
		require.NoError(tb, json.Indent(&b, bytes.TrimSpace(body), "", "  "))

		return b.String() + "\n"
	}
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
	code := m.Run()

	if code == 0 && flag.Lookup("test.run").Value.String() == "" && flag.Lookup("test.skip").Value.String() == "" {
		if missing := untested(Tree(), ran.cases); len(missing) > 0 {
			fmt.Fprintln(os.Stderr, "FAIL: the walk of the command tree:\n  "+strings.Join(missing, "\n  "))

			code = 1
		}
	}

	os.Exit(code)
}

// untested lists each example that no case runs with exit 0, and each
// alias that no case uses with exit 0; every command has an example, so a
// command with no case shows. An example's environment prefix, such as
// HEADSCALE_CLI_ADDRESS=x, needs a case that sets that variable.
func untested(tree *command.Tree, cases []ranCase) []string {
	var missing []string

	passes := func(match func(c ranCase) bool) bool {
		return slices.ContainsFunc(cases, func(c ranCase) bool { return c.code == 0 && match(c) })
	}

	for _, c := range tree.Commands() {
		for _, e := range c.Example {
			env, line := exampleWords(e)
			if !passes(func(rc ranCase) bool {
				return slices.Equal(rc.words, line) && !slices.ContainsFunc(env, func(n string) bool { return !slices.Contains(rc.env, n) })
			}) {
				missing = append(missing, `example "`+e+`" has no case that passes`)
			}
		}

		for _, a := range c.Aliases {
			if !passes(func(rc ranCase) bool { return tree.Reached(rc.words) == c.Path && slices.Contains(rc.words, a) }) {
				missing = append(missing, `alias "`+a+`" of "`+c.Path+`" has no case that passes`)
			}
		}
	}

	return missing
}

// exampleWords are the names of the variables an example sets before
// `headscale`, and its words after it, up to a pipe.
func exampleWords(e string) ([]string, []string) {
	e, _, _ = strings.Cut(e, " |")

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
		Name: "extra", Short: "Do nothing", Long: "Do nothing.", Local: true,
		Example: []string{"headscale extra", "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat"},
		Run:     func(command.Ctx, command.NoInput) (command.NoOutput, error) { return command.NoOutput{}, nil },
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
			name: "a command with no case",
			want: []string{
				`example "headscale extra" has no case that passes`,
				`example "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat" has no case that passes`,
			},
		},
		{
			name:  "a help case and a failing case do not count",
			cases: []ranCase{ok("extra --help"), fails("extra")},
			want: []string{
				`example "headscale extra" has no case that passes`,
				`example "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat" has no case that passes`,
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

		tree, err := command.Build("headscale", "short", command.Group{Name: "items", Short: "Items", Commands: []command.Node{
			command.New(command.Spec[command.NoInput, command.NoOutput]{
				Name: "delete", Short: "Delete", Long: "Delete.", Local: true, Aliases: []string{"rm"},
				Example: []string{"headscale items delete"},
				Run:     func(command.Ctx, command.NoInput) (command.NoOutput, error) { return command.NoOutput{}, nil },
			}),
		}})
		require.NoError(t, err)
		require.Equal(t, []string{`alias "rm" of "items delete" has no case that passes`}, untested(tree, []ranCase{ok("items delete")}))
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
		}

		src, err := os.ReadFile(name)
		require.NoError(t, err)
		require.NotRegexp(t, `clientv0\.NewClient`, string(src), "%s makes its own client: it skips the version check", name)
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
		require.Equal(t, rootHelp, fold.ReplaceAllString(b.String(), "$1   $2"), strconv.Quote(strings.Join(args, " ")))
	}
}

const rootHelp = `headscale is an open source implementation of the Tailscale control server

Local commands (no server needed):

  version   Print the version
  completion <shell>   Print the completion script of a shell

Server commands (talk to a running headscale):

  api whoami   Show what the CLI is connected as

Debug:

  debug health   Check that the server is healthy

Server commands take -o json, which prints the API object.
See ` + "`headscale <command> --help`" + ` for examples.
`
