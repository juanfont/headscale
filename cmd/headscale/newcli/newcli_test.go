package newcli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/parser"
	"go/token"
	"io"
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
	"github.com/juanfont/headscale/cmdline/argtest"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"pgregory.net/rapid"
)

var errModelMismatch = errors.New("CLI model mismatch")

func TestRapidFilterCatalogue(t *testing.T) {
	tree := Tree()
	env := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) (string, error) {
		var out, stderr bytes.Buffer

		rc := command.Run(tree, argv, command.Env{Stdout: &out, Stderr: &stderr, Environ: env})
		if rc != 0 || stderr.Len() != 0 {
			return "", fmt.Errorf("%w: %q: status=%d stderr=%q", errModelMismatch, argv, rc, stderr.String())
		}

		return out.String(), nil
	}

	type list struct{ words, columns, sealed []string }

	resources := []string{"users list", "nodes list", "nodes routes list", "nodes tags list"}

	lists := make([]list, 0, len(resources))
	for _, resource := range resources {
		words := strings.Fields(resource)

		raw, err := run(slices.Concat(words, []string{"--list-columns", "-o", "json"}))
		if err != nil {
			t.Fatal(err)
		}

		var info []struct{ Name, Kind string }

		err = json.Unmarshal([]byte(raw), &info)
		if err != nil || len(info) == 0 {
			t.Fatalf("%s public column list: %v", resource, err)
		}

		cols := make([]string, 0, len(info))

		var seals []string

		for _, c := range info {
			cols = append(cols, c.Name)
			switch c.Kind {
			case "text", "number", "id":
				seal := c.Name + "=1"

				_, err = run(slices.Concat(words, []string{"--list-columns", "--filter", seal}))
				if err != nil {
					t.Fatal(err)
				}

				seals = append(seals, seal)
			}
		}

		if len(seals) == 0 {
			t.Fatalf("%s: no validated filter for completion", resource)
		}

		lists = append(lists, list{words, cols, seals})
	}

	rapid.Check(t, func(rt *rapid.T) {
		ls := rapid.SampledFrom(lists).Draw(rt, "list")
		col := rapid.SampledFrom(ls.columns).Draw(rt, "column")

		prefix := col[:rapid.IntRange(0, len(col)).Draw(rt, "prefix length")]
		if rapid.Bool().Draw(rt, "unmatched prefix") {
			prefix = "zz" + rapid.StringOfN(rapid.RuneFrom([]rune("abcxyz0-αé")), 0, 10, 32).Draw(rt, "unknown suffix")
		}

		sealed := rapid.SliceOfN(rapid.SampledFrom(ls.sealed), 0, 2).Draw(rt, "sealed filters")

		prior := ""
		if len(sealed) > 0 {
			prior = strings.Join(sealed, ",") + ","
		}

		cursor := prior + prefix

		path := slices.Clone(ls.words)
		if rapid.Bool().Draw(rt, "list alias") {
			path[len(path)-1] = "ls"
		}

		protocol := rapid.SampledFrom([]string{"__complete", "__completeNoDesc"}).Draw(rt, "protocol")
		argv := slices.Concat([]string{protocol}, path)
		argv = append(argv, argtest.Option(rt, "--filter", cursor)...)

		output, err := run(argv)
		if err != nil {
			rt.Fatal(err)
		}

		lines := strings.Split(strings.TrimSuffix(output, "\n"), "\n")
		directive := lines[len(lines)-1]
		bits, err := strconv.Atoi(strings.TrimPrefix(directive, ":"))
		candidates := lines[:len(lines)-1]
		// A suppressed list must also disable shell filename fallback.
		if err != nil || !strings.HasPrefix(directive, ":") || bits&4 == 0 || bits&1 != 0 || len(candidates) > 0 && bits&2 == 0 {
			rt.Fatalf("%q: unexpected directive %s", argv, directive)
		}

		var want []string

		for _, name := range ls.columns {
			if strings.HasPrefix(name, prefix) {
				want = append(want, prior+name)
			}
		}

		slices.Sort(want)
		slices.Sort(candidates)

		if !slices.Equal(want, candidates) {
			rt.Fatalf("%q: candidates=%q want public columns=%q", argv, candidates, want)
		}
	})
}

func TestInvalidFilterNoFiles(t *testing.T) {
	tree := Tree()

	for _, resource := range []string{"nodes", "users"} {
		for _, cursor := range []string{",na", "0,na", ",zzunknown", "0,zzunknown"} {
			var out, stderr bytes.Buffer

			argv := []string{"__complete", resource, "list", "--filter=" + cursor}
			code := command.Run(tree, argv, command.Env{Stdout: &out, Stderr: &stderr})
			lines := strings.Split(strings.TrimSuffix(out.String(), "\n"), "\n")
			directive := lines[len(lines)-1]

			bits, err := strconv.Atoi(strings.TrimPrefix(directive, ":"))
			if code != 0 || stderr.Len() != 0 || err != nil || !strings.HasPrefix(directive, ":") || bits&4 == 0 || bits&1 != 0 {
				t.Errorf("%q: status=%d reply=%q stderr=%q; filter completion must disable file fallback", argv, code, out.String(), stderr.String())
			}
		}
	}
}

type helpLeaf struct {
	words, aliases []string
	help           string
	config, output bool
}

type helpReply struct {
	code, answers  int
	stdout, stderr string
}

func helpCatalogue(t *testing.T) ([]helpLeaf, func([]string) helpReply) {
	t.Helper()

	tree := Tree()
	env := []string{"HOME=" + t.TempDir()}
	run := func(argv []string) helpReply {
		var (
			out, diagnostic bytes.Buffer
			reply           helpReply
		)

		reply.code = command.Run(tree, argv, command.Env{Stdout: &out, Stderr: &diagnostic, Environ: env, Answered: func(*http.Request, []byte) { reply.answers++ }})
		reply.stdout, reply.stderr = out.String(), diagnostic.String()

		return reply
	}

	commands := tree.Commands()

	leaves := make([]helpLeaf, 0, len(commands))
	for _, cmd := range commands {
		words := strings.Fields(cmd.Path)
		reply := run(append(slices.Clone(words), "--help"))

		_, flags, found := strings.Cut(reply.stdout, "\nFlags:\n")
		if reply.code != 0 || reply.stderr != "" || !found || !strings.Contains(flags, "--help ") {
			t.Fatalf("%s help: code=%d stderr=%q flags found=%t", cmd.Path, reply.code, reply.stderr, found)
		}

		leaves = append(leaves, helpLeaf{words, cmd.Aliases, reply.stdout, strings.Contains(flags, "--config "), strings.Contains(flags, "--output ")})
	}

	return leaves, run
}

func (l helpLeaf) check(r helpReply, chunks [][]string) error {
	if r.answers != 0 {
		return fmt.Errorf("%w: help received %d API answers", errModelMismatch, r.answers)
	}

	for _, chunk := range chunks {
		spelling, _, _ := strings.Cut(chunk[0], "=")

		var wrong string

		switch {
		case !l.config && (spelling == "-c" || spelling == "--config"):
			wrong = "--config"
		case !l.output && (spelling == "-o" || spelling == "--output"):
			wrong = "--output"
		default:
			continue
		}

		if r.code != 1 || r.stdout != "" || !strings.HasPrefix(r.stderr, "Error: "+wrong+" does not apply to ") {
			return fmt.Errorf("%w: unsupported option: exit=%d stdout=%q stderr=%q", errModelMismatch, r.code, r.stdout, r.stderr)
		}

		return nil
	}

	if r.code != 0 || r.stderr != "" || r.stdout != l.help {
		return fmt.Errorf("%w: exit=%d stderr=%q canonical help matches=%t", errModelMismatch, r.code, r.stderr, r.stdout == l.help)
	}

	return nil
}

// Public help declares which global flags can reach each leaf.
func TestRapidLeafOptionPlacement(t *testing.T) {
	leaves, run := helpCatalogue(t)
	hit := map[string]bool{}

	var accepted, unsupported, withAlias, interleaved int

	rapid.Check(t, func(rt *rapid.T) {
		leaf := leaves[rapid.IntRange(0, len(leaves)-1).Draw(rt, "command index")]

		path := slices.Clone(leaf.words)
		if len(leaf.aliases) > 0 && rapid.Bool().Draw(rt, "alias") {
			path[len(path)-1] = rapid.SampledFrom(leaf.aliases).Draw(rt, "leaf alias")
			withAlias++
		}

		options := [][]string{{rapid.SampledFrom([]string{"-h", "--help"}).Draw(rt, "help spelling")}}
		config := rapid.Bool().Draw(rt, "config")

		output := rapid.Bool().Draw(rt, "output")
		if config {
			flag := rapid.SampledFrom([]string{"-c", "--config"}).Draw(rt, "config spelling")
			value := rapid.SampledFrom([]string{"unused.yaml", "with space.yaml", "--help", "--output", ""}).Draw(rt, "config value")
			options = append(options, argtest.Option(rt, flag, value))
		}

		if output {
			flag := rapid.SampledFrom([]string{"-o", "--output"}).Draw(rt, "output spelling")
			options = append(options, argtest.Option(rt, flag, "json"))
		}

		chunks := argtest.InterleaveChunks(rt, path, options...)

		argv := slices.Concat(chunks...)
		if len(options) > 1 && slices.Index(argv, path[len(path)-1]) > len(path)-1 {
			interleaved++
		}

		err := leaf.check(run(argv), chunks)
		if err != nil {
			rt.Fatalf("argv=%q: %v", argv, err)
		}

		hit[strings.Join(leaf.words, " ")] = true
		if config && !leaf.config || output && !leaf.output {
			unsupported++
		} else {
			accepted++
		}
	})
	t.Logf("model classes accepted-placements=%d refused-placements=%d leaf-aliases=%d help-or-option-before-leaf=%d", accepted, unsupported, withAlias, interleaved)
	t.Logf("reached %d of %d canonical leaves", len(hit), len(leaves))
}

func TestAllLeafGlobalOptionPositions(t *testing.T) {
	leaves, run := helpCatalogue(t)

	var forms, refusals int

	for _, leaf := range leaves {
		for _, last := range append([]string{leaf.words[len(leaf.words)-1]}, leaf.aliases...) {
			path := slices.Clone(leaf.words)
			path[len(path)-1] = last

			for _, option := range []struct {
				spell, value string
				config       bool
			}{{"-c", "unused.yaml", true}, {"--config", "unused.yaml", true}, {"-o", "json", false}, {"--output", "json", false}} {
				for _, words := range [][]string{{option.spell, option.value}, {option.spell + "=" + option.value}} {
					for _, help := range []string{"-h", "--help"} {
						for argv := range argtest.Placements(path, []string{help}, words) {
							err := leaf.check(run(argv), [][]string{words})
							if err != nil {
								t.Fatalf("argv=%q: %v", argv, err)
							}

							forms++

							if option.config && !leaf.config || !option.config && !leaf.output {
								refusals++
							}
						}
					}
				}
			}
		}
	}

	t.Logf("all %d two-option positions/spellings, %d refused, %d canonical leaves", forms, refusals, len(leaves))
}

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

func newFixture(tb testing.TB, clients bool, server ...servertest.ServerOption) *fixture {
	tb.Helper()

	// The node store waits for a batch to fill; a test does not.
	opts := append([]servertest.ServerOption{servertest.WithNodeStoreBatchTimeout(time.Millisecond)}, server...)
	if !clients {
		opts = append(opts, servertest.WithRealListener())
	}

	srv := servertest.NewServer(tb, opts...)

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

	code := command.Run(Tree(), words(shell(f.expand(tc.args))), command.Env{
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

	return result{stdout: out.String(), stderr: errOut.String(), code: code, answers: answers, asked: asked, sent: sent, headers: headers}
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
	token, _, err := f.srv.State().MintAccessToken(client.ClientID, scopes, tags, &expiry)
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

// runCase runs one case of runCases; a test that sets the working
// directory runs its cases with it, one after the other.
func runCase(t *testing.T, setup func(testing.TB, *fixture), tc cliCase) {
	t.Helper()

	require.False(t, tc.stdout != "" && tc.want != nil, "a case sets stdout or want, not both")

	f := newFixture(t, tc.clients, tc.server...)
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
func (l listAt) rows(keep func(row map[string]any) bool) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		b, err := json.Marshal(l.kept(tb, r, keep))
		require.NoError(tb, err)

		return indent(tb, b)
	}
}

// row is what -o json prints for one row of a list: a target that a walk
// found.
func (l listAt) row(keep func(row map[string]any) bool) func(testing.TB, *fixture, result) string {
	return func(tb testing.TB, _ *fixture, r result) string {
		tb.Helper()

		found := l.kept(tb, r, keep)
		require.Len(tb, found, 1)

		return indent(tb, found[0])
	}
}

func (l listAt) kept(tb testing.TB, r result, keep func(row map[string]any) bool) []json.RawMessage {
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

// shell runs the command substitutions an example may hold, as a shell
// would, so the example runs as it is written; the walk sees it unrun.
func shell(line string) string {
	return strings.ReplaceAll(line, "$(openssl rand -hex 12)", string(types.MustAuthID())[len("hskey-authreq-"):])
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
		Name: "extra", Short: "Do nothing", Long: "Do nothing.", Local: true,
		Example: []string{"headscale extra", "HEADSCALE_CLI_ADDRESS=hs.example.com headscale extra | cat", "make | headscale extra > out"},
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

		tree, err := command.Build("headscale", "short", command.Group{Name: "items", Short: "Items", Commands: []command.Node{
			command.New(command.Spec[command.NoInput, command.NoOutput]{
				Name: "delete", Short: "Delete", Long: "Delete.", Local: true, Aliases: []string{"rm"},
				Example: []string{"headscale items delete"},
				Confirm: func(command.Ctx, command.NoInput) (command.Prompt, error) { return command.Prompt{}, nil },
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

			// The database bypass is the one way past the server, and only
			// the policy commands take it.
			server := strings.HasPrefix(imp.Path.Value, `"github.com/juanfont/headscale/hscontrol/`) &&
				!slices.Contains([]string{`"github.com/juanfont/headscale/hscontrol/config"`, `"github.com/juanfont/headscale/hscontrol/types"`}, imp.Path.Value)
			if server && (name != "policy.go" || imp.Path.Value != `"github.com/juanfont/headscale/hscontrol/offline"`) {
				t.Errorf("%s imports %s: a command reaches the server through command.API; only policy.go opens a stopped server's database, through offline", name, imp.Path.Value)
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
  api whoami   Show what the CLI is connected as
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

Server commands take -o json, which prints the API object.
See ` + "`headscale <command> --help`" + ` for examples.
`
