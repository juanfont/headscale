package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline"
	lib "github.com/juanfont/headscale/cmdline/command"
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// The tests of the builder run with Headscale's program: a server, its
// problems, its lookups, its guards.

type item struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type getIn struct {
	Name  string      `arg:"name"   help:"<name> is any word."`
	Extra Opt[string] `arg:"extra"`
	Count int         `flag:"count" help:"How many"            short:"n"`
}

var itemColumns = table.Columns[item]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
}

func noop[In, Out any](Ctx, In) (Out, error) {
	var out Out

	return out, nil
}

var errBroken = errors.New("it broke")

func words(line string) []string {
	w := strings.Fields(line)
	for i := range w {
		if w[i] == "''" {
			w[i] = ""
		}
	}

	return w
}

// allowedAliases are Headscale's aliases.
func allowedAliases() []string { return []string{"ls", "rm", "approve"} }

// build is a tree of Headscale's program with the aliases it may use and
// the entities it looks up: a test of the retry needs a type of its own.
//
//nolint:unparam // the name of a tree, which a test may change
func build(
	name, short string,
	aliases []string,
	ents []lib.Entity,
	nodes ...Node,
) (*Tree, error) {
	p := program(name, short)
	p.Aliases, p.Entities = aliases, ents

	return lib.Build(p, nodes...)
}

// connectTest is connect with the warnings of the run on env's stderr.
func connectTest(cfg *types.Config, env Env) (*API, error) {
	a, err := connect(cfg, env, env.Stderr)
	if err == nil {
		a.read = &reads{}
	}

	return a, err
}

// The library's refusals of a spec, as its error says them.
var (
	errNoQuestion = errors.New(
		"a refusal named in Changed and no Confirm: the write would run again on what it sent before",
	)
	errNoGuardTarget = errors.New(
		"a refusal named in Changed and no target that is an entity: the guard of the question would reach no write",
	)
	errGuardMix = errors.New(
		"a refusal named in Changed on a target with a revision: the write takes one guard, and the token would drop the revision",
	)
	errGuardNoChanged = errors.New(
		"a question handed over a guard, and the spec names no Changed: its refusal would not be asked again",
	)
	errNotEnd = errors.New(
		"a delete of a credential, beside a Secret or of a target with revoked, is made by NewEnd",
	)
	errEndAlone = errors.New(
		"NewEnd is the delete of a credential, and no Secret beside it makes one",
	)
)

// masked is s as the edge of Headscale's program writes it.
func masked(s string) string {
	var b strings.Builder

	t, err := Build("prog", "P", New(Spec[NoInput, NoOutput]{
		Name:    "say",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog say"},
		Local:   true,
		Run:     func(c Ctx, _ NoInput) (NoOutput, error) { c.Note(s); return NoOutput{}, nil },
		Done:    func(NoInput, NoOutput, time.Time) string { return "" },
	}))
	if err != nil {
		panic(err)
	}

	Run(t, []string{"say"}, Env{Stdout: &b, Stderr: &b})

	return strings.TrimSuffix(b.String(), "\n")
}

// fakeServer answers like v0, with a field this build does not know in
// every object: /health changes with each call, /items has two pages,
// /broken fails on its second page, and DELETE /thing has no body.
func fakeServer(t *testing.T) string {
	t.Helper()

	var calls atomic.Int32

	s := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", "dev")
		w.Header().Set("Headscale-Commit", "a491228")

		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/items" && r.URL.Query().Get("pageToken") == "":
			_, _ = w.Write(
				[]byte(
					`{"items": [{"id": "1", "name": "a", "x": 1}], "nextPageToken": "p2"}`,
				),
			)
		case r.URL.Path == "/items":
			_, _ = w.Write([]byte(`{"items": [{"id": "2", "name": "b", "x": 2}]}`))
		case r.URL.Path == "/broken" && r.URL.Query().Get("pageToken") == "":
			_, _ = w.Write(
				[]byte(`{"broken": [{"id": "1", "name": "a"}], "nextPageToken": "p2"}`),
			)
		case r.URL.Path == "/broken":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write(
				[]byte(
					`{"code": "internal", "status": 500, "title": "Internal", "requestId": "r1"}`,
				),
			)
		default:
			n := calls.Add(1)
			_, _ = fmt.Fprintf(
				w,
				`{"healthy": true, "databaseConnectivity": %t, "warnings": [], "call": %d}`,
				n == 1,
				n,
			)
		}
	}))
	t.Cleanup(s.Close)

	return s.URL
}

func listItems(c Ctx) ([]item, error) { return listOfPath(c, "items") }

func listOfPath(c Ctx, path string) ([]item, error) {
	return walkOf[item, anySuccess](
		c.API,
		path,
		func(cl *clientv0.Client, p page) (*http.Response, error) {
			token := ""
			if p.token != nil {
				token = *p.token
			}

			req, err := http.NewRequestWithContext(
				c,
				http.MethodGet,
				cl.Server+path+"?pageToken="+token,
				nil,
			)
			if err != nil {
				return nil, err
			}

			return cl.Client.Do(req)
		},
	)
}

// TestJSONIsTheAnswer: -o json prints the answer that Run's value came
// from, and a value that no answer holds is an error in every mode.
func TestJSONIsTheAnswer(t *testing.T) {
	t.Parallel()

	spec := func(name string, run func(Ctx, NoInput) (clientv0.Health, error)) Node {
		return New(Spec[NoInput, clientv0.Health]{
			Name:    name,
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog " + name},
			Run:     run,
			Done:    func(NoInput, clientv0.Health, time.Time) string { return "done" },
		})
	}

	tree, err := Build(
		"prog",
		"A program",
		spec("first", func(c Ctx, _ NoInput) (clientv0.Health, error) {
			first, err := health(c, c.API)
			if err != nil {
				return first, err
			}

			_, err = health(c, c.API)

			return first, err
		}),
		spec("changed", func(c Ctx, _ NoInput) (clientv0.Health, error) {
			h, err := health(c, c.API)
			h.Healthy = false

			return h, err
		}),
		spec(
			"made",
			func(Ctx, NoInput) (clientv0.Health, error) { return clientv0.Health{Healthy: true}, nil },
		),
		// A zero value is no answer either: only ErrNotRead says that
		// there is nothing to print.
		spec(
			"zero",
			func(Ctx, NoInput) (clientv0.Health, error) { return clientv0.Health{}, nil },
		),
		New(Spec[NoInput, clientv0.Health]{
			Name:    "local",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog local"},
			Local:   true,
			Run:     func(c Ctx, _ NoInput) (clientv0.Health, error) { return health(c, c.API) },
			Done:    func(NoInput, clientv0.Health, time.Time) string { return "done" },
		}),
		NewList(ListSpec[NoInput, item]{
			Name:    "items",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog items"},
			Columns: itemColumns,
			NoRows:  "No items.",
			Run: func(c Ctx, _ NoInput) ([]item, error) {
				rows, err := listItems(c)
				slices.Reverse(rows)

				return rows, err
			},
		}),
		NewList(ListSpec[NoInput, item]{
			Name:    "broken",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog broken"},
			Columns: itemColumns,
			NoRows:  "No items.",
			Run:     func(c Ctx, _ NoInput) ([]item, error) { return listOfPath(c, "broken") },
		}),
		New(Spec[NoInput, item]{
			Name:    "item",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog item"},
			Columns: itemColumns,
			Run: func(c Ctx, _ NoInput) (item, error) {
				rows, err := listItems(c)
				if err != nil {
					return item{}, err
				}

				return rows[1], nil
			},
		}),
		New(Spec[NoInput, NoOutput]{
			Name: "remove", Short: "S", Long: "S.", Example: []string{"prog remove"},
			Run: func(c Ctx, _ NoInput) (NoOutput, error) {
				return callOf[NoOutput, anySuccess](
					c.API,
					func(cl *clientv0.Client) (*http.Response, error) {
						req, err := http.NewRequestWithContext(
							c,
							http.MethodDelete,
							cl.Server+"thing",
							nil,
						)
						if err != nil {
							return nil, err
						}

						return cl.Client.Do(req)
					},
				)
			},
			Done: func(NoInput, NoOutput, time.Time) string { return "removed" },
		}),
	)
	require.NoError(t, err)

	notAnswer := "Error: this command returned an object that the server did not send, so -o json cannot print it\n"

	for _, tt := range []struct {
		line           string
		commit         string
		stdout, stderr string
		code           int
	}{
		{line: "first -o json", stdout: "{\n  \"healthy\": true,\n  \"databaseConnectivity\": true,\n  \"warnings\": [],\n  \"call\": 1\n}\n"},
		{
			line: "first -o json", commit: "3f2a9c1",
			stdout: "{\n  \"healthy\": true,\n  \"databaseConnectivity\": true,\n  \"warnings\": [],\n  \"call\": 1\n}\n",
			stderr: "warning: this headscale is dev (3f2a9c1), the server is dev (a491228).\n",
		},
		{line: "changed -o json", stderr: notAnswer, code: 1},
		{line: "made", stderr: notAnswer, code: 1},
		{line: "made -o json", stderr: notAnswer, code: 1},
		{line: "zero", stderr: notAnswer, code: 1},
		{line: "local", stderr: "Error: this command is Local and has no server to call\n", code: 1},
		{line: "zero -o json", stderr: notAnswer, code: 1},
		{line: "items -o json", stdout: "[\n  {\n    \"id\": \"2\",\n    \"name\": \"b\",\n    \"x\": 2\n  },\n  {\n    \"id\": \"1\",\n    \"name\": \"a\",\n    \"x\": 1\n  }\n]\n"},
		{line: "items", stdout: "ID  NAME\n2   b\n1   a\n"},
		{line: "item -o json", stdout: "{\n  \"id\": \"2\",\n  \"name\": \"b\",\n  \"x\": 2\n}\n"},
		// An empty --config is a mistake, not a fall back to HEADSCALE_CONFIG.
		{line: "items --config=", stderr: "Error: \"\" is not a valid --config: it takes a path.\n", code: 1},
		// A page that fails in the middle prints no part of the list.
		{line: "broken", stderr: "Error: the server had an internal error. Its log has the request r1.\n", code: 1},
		{line: "broken -o json", stderr: "Error: the server had an internal error. Its log has the request r1.\n", code: 1},
		{line: "remove", stdout: "removed\n"},
		{line: "remove -o json"},
	} {
		t.Run(tt.line+tt.commit, func(t *testing.T) {
			t.Parallel()

			file := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(file, nil, 0o600))

			var stdout, stderr bytes.Buffer

			code := Run(tree, strings.Fields(tt.line), Env{
				Stdout:  &stdout,
				Stderr:  &stderr,
				Version: &types.VersionInfo{Version: "dev", Commit: tt.commit},
				Environ: []string{
					"HEADSCALE_CONFIG=" + file,
					"HEADSCALE_CLI_ADDRESS=" + fakeServer(t),
					"HEADSCALE_CLI_API_KEY=key",
				},
			})

			if diff := cmp.Diff(tt.stdout, stdout.String()); diff != "" {
				t.Errorf("stdout (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.stderr, stderr.String()); diff != "" {
				t.Errorf("stderr (-want +got):\n%s", diff)
			}

			require.Equal(t, tt.code, code)
		})
	}
}

// found is an entity that a lookup reads.
type found struct{ ID string }

//nolint:staticcheck // a sentence of the CLI
var errNoMatch = errors.New(`no item matches "nope".`)

// TestLookupKeepsItsSentence: an error of a lookup is printed as the
// lookup wrote it, not as a bad argument.
func TestLookupKeepsItsSentence(t *testing.T) {
	t.Parallel()

	type in struct {
		Item found `arg:"item"`
	}

	lookup := lib.EntityOf("item", func(_ context.Context, word string) (found, error) {
		switch word {
		case "nope":
			return found{}, errNoMatch
		case "down":
			return found{}, &connectError{target: "/run/headscale.sock", err: errBroken}
		}

		return found{ID: word}, nil
	}, nil, func(f found) string { return f.ID }, nil)

	tree, err := build(
		"prog",
		"A program",
		allowedAliases(),
		[]lib.Entity{lookup},
		New(Spec[in, NoOutput]{
			Name:    "get",
			Short:   "S",
			Long:    "S.",
			Example: []string{"prog get 1"},
			Local:   true,
			Run:     noop[in, NoOutput],
			Done:    func(in in, _ NoOutput, _ time.Time) string { return "got " + in.Item.ID },
		}),
	)
	require.NoError(t, err)

	for line, want := range map[string]string{
		"get 1":    "",
		"get nope": "Error: no item matches \"nope\".\n",
		"get down": "Error: " + (&connectError{target: "/run/headscale.sock", err: errBroken}).Error() + "\n",
	} {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(line), Env{Stdout: &stdout, Stderr: &stderr})
		require.Equal(t, want, stderr.String(), line)
	}
}

// TestSentence: a command that wraps a problem, as Go code does, still
// prints the CLI's sentence.
func TestSentence(t *testing.T) {
	t.Parallel()

	p := &ProblemError{
		Problem: clientv0.Problem{Code: clientv0.ProblemCodeUnauthorized},
	}
	require.Equal(
		t,
		"the server did not accept the credential of this CLI: it is unknown, expired or revoked.\nIt is set by cli.api_key in the config file, or HEADSCALE_CLI_API_KEY.",
		sentence(fmt.Errorf("getting user: %w", p)),
	)
	require.Equal(
		t,
		"cannot connect to x: it broke",
		sentence(fmt.Errorf("listing: %w", &connectError{target: "x", err: errBroken})),
	)
	require.Equal(
		t,
		"listing: it broke",
		sentence(fmt.Errorf("listing: %w", errBroken)),
	)
}

// TestRetry: a write the server refuses because the target changed reads
// the target again by its ID, asks again on what it read after a line that
// says why, and writes once more with the new revision; a second refusal
// is the sentence of the refusal. A target whose type has a revision and
// no read is a tree that does not build.
func TestRetry(t *testing.T) {
	t.Parallel()

	type in struct {
		Node guarded `arg:"node"`
	}

	// server holds the node; each read of it bumps the revision this many
	// times first, so the write after it is refused again.
	type server struct {
		mu       sync.Mutex
		rev      int
		bumps    int
		gone     bool
		seen     []string
		prompted []string
		// noRevision answers a read with no revision, as a broken server.
		noRevision bool
	}

	start := func(t *testing.T, s *server) string {
		t.Helper()

		hs := httptest.NewServer(
			versioned(func(w http.ResponseWriter, r *http.Request) {
				s.mu.Lock()
				defer s.mu.Unlock()

				s.seen = append(
					s.seen,
					r.Method+" "+r.URL.Path+" "+r.Header.Get("If-Match"),
				)
				w.Header().Set("Headscale-Version", "dev")

				node := func() string { return fmt.Sprintf(`{"id": "12", "name": "web%d", "revision": "r%d"}`, s.rev, s.rev) }
				if s.noRevision {
					node = func() string { return fmt.Sprintf(`{"id": "12", "name": "web%d"}`, s.rev) }
				}

				switch {
				case r.Method == http.MethodGet && s.gone:
					w.WriteHeader(http.StatusNotFound)
					_, _ = w.Write(
						[]byte(
							`{"code": "not_found", "status": 404, "title": "Not found", "object": {"kind": "node", "id": "12"}}`,
						),
					)
				case r.Method == http.MethodGet:
					_, _ = w.Write([]byte(node()))
					s.rev += s.bumps
				case r.Header.Get("If-Match") != fmt.Sprintf(`"r%d"`, s.rev):
					w.WriteHeader(http.StatusPreconditionFailed)
					_, _ = fmt.Fprintf(
						w,
						`{"code": "precondition_failed", "status": 412, "title": "Precondition failed", "object": {"kind": "node", "id": "12", "name": "web%d"}}`,
						s.rev,
					)
				default:
					_, _ = w.Write([]byte(node()))
				}
			}),
		)
		t.Cleanup(hs.Close)

		return hs.URL
	}

	read := func(ctx context.Context, id string) (guarded, error) {
		return callOf[guarded, anySuccess](
			lib.CtxOf[*API](ctx).API,
			func(cl *clientv0.Client) (*http.Response, error) {
				req, err := http.NewRequestWithContext(
					ctx,
					http.MethodGet,
					cl.Server+"nodes/"+id,
					nil,
				)
				if err != nil {
					return nil, err
				}

				return cl.Client.Do(req)
			},
		)
	}

	build := func(t *testing.T, s *server, reads bool) (*Tree, error) {
		t.Helper()

		find := func(_ context.Context, word string) (guarded, error) {
			if word == "none" {
				word = ""
			}

			return guarded{ID: "12", Name: "web0", Revision: word}, nil
		}

		e := lib.EntityOf(
			"node",
			find,
			nil,
			func(g guarded) string { return g.Name },
			read,
		)
		if !reads {
			e = lib.EntityOf(
				"node",
				find,
				nil,
				func(g guarded) string { return g.Name },
				nil,
			)
		}

		return build(
			"prog",
			"A program",
			allowedAliases(),
			[]lib.Entity{e},
			New(Spec[in, guarded]{
				Name:    "rename",
				Short:   "S",
				Long:    "S.",
				Example: []string{"prog rename r1"},
				Confirm: func(_ Ctx, in in) (Prompt, error) {
					s.mu.Lock()
					defer s.mu.Unlock()

					s.prompted = append(s.prompted, in.Node.Name)

					return Prompt{
						Question: "Rename " + in.Node.Name + "?",
						Action:   "rename it",
					}, nil
				},
				Run: func(c Ctx, in in) (guarded, error) {
					return callOf[guarded, anySuccess](
						c.API,
						func(cl *clientv0.Client) (*http.Response, error) {
							req, err := http.NewRequestWithContext(
								c,
								http.MethodPatch,
								cl.Server+"nodes/"+in.Node.ID,
								nil,
							)
							if err != nil {
								return nil, err
							}

							if rev := c.IfMatch(in.Node.ID); rev != nil {
								req.Header.Set("If-Match", *rev)
							}

							return cl.Client.Do(req)
						},
					)
				},
				Done: func(in in, out guarded, _ time.Time) string { return "renamed " + in.Node.Name + " to " + out.Name },
			}),
		)
	}

	tree := func(t *testing.T, s *server) *Tree {
		t.Helper()

		tr, err := build(t, s, true)
		require.NoError(t, err)

		return tr
	}

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	run := func(tree *Tree, url, args, stdin string) (string, string) {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(args), Env{
			Stdin: strings.NewReader(
				stdin,
			),
			Stdout:   &stdout,
			Stderr:   &stderr,
			Terminal: true,
			Version:  &types.VersionInfo{Version: "dev"},
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=" + url,
				"HEADSCALE_CLI_API_KEY=key",
			},
		})

		return stdout.String(), stderr.String()
	}

	t.Run("changed once: read again, asked again, written", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1", "y\nyes\n")
		require.Equal(
			t,
			"Rename web0? [y/N] Node 12 (web0) changed while you decided.\nRename web2? [y/N] ",
			stderr,
		)
		require.Equal(t, "renamed web2 to web2\n", stdout)
		require.Equal(
			t,
			[]string{
				"GET /api/headscale/v0/version ",
				`PATCH /nodes/12 "r1"`,
				"GET /nodes/12 ",
				`PATCH /nodes/12 "r2"`,
			},
			s.seen,
		)
	})

	t.Run("with --force it still reads again, and asks nothing", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1 --force", "")
		require.Empty(t, stderr)
		require.Equal(t, "renamed web2 to web2\n", stdout)
		require.Equal(t, []string{"web0", "web2"}, s.prompted)
		require.Len(t, s.seen, 4)
	})

	// An answer typed before the second question was shown cannot confirm
	// it: the terminal drops what waits, so the second y is not read.
	t.Run("a y typed ahead does not answer the second question", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		url := start(t, s)
		discarded := 0

		var stdout, stderr bytes.Buffer

		Run(tree(t, s), strings.Fields("rename r1"), Env{
			Stdin: strings.NewReader(
				"y\ny\n",
			),
			Stdout:   &stdout,
			Stderr:   &stderr,
			Terminal: true,
			Version:  &types.VersionInfo{Version: "dev"},
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=" + url,
				"HEADSCALE_CLI_API_KEY=key",
			},
			DiscardInput: func() { discarded++ },
		})
		require.Equal(
			t,
			"Rename web0? [y/N] Node 12 (web0) changed while you decided.\nRename web2? [y/N] Aborted.\n",
			stderr.String(),
		)
		require.Empty(t, stdout.String())
		require.Equal(t, 1, discarded, "before the second question only")
		require.Len(t, s.seen, 3, "no second write")
	})

	t.Run("no to the second question", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1", "y\nn\n")
		require.Equal(
			t,
			"Rename web0? [y/N] Node 12 (web0) changed while you decided.\nRename web2? [y/N] Aborted.\n",
			stderr,
		)
		require.Empty(t, stdout)
		require.Len(t, s.seen, 3, "no second write")
	})

	t.Run("it keeps changing", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2, bumps: 1}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1 --force", "")
		require.Equal(
			t,
			"Error: Node 12 (web4) changed while the command ran. Run it again.\n",
			stderr,
		)
		require.Empty(t, stdout)
		require.Len(t, s.seen, 4, "one retry, no more")
	})

	t.Run("gone when read again", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2, gone: true}
		_, stderr := run(tree(t, s), start(t, s), "rename r1 --force", "")
		require.Equal(
			t,
			"Error: Node 12 (web0) no longer exists.\n",
			stderr,
			"the server names no object that is gone; the target has its name",
		)
	})

	// Never none: a confirmed write with no revision to send is not sent,
	// the first time or after a refusal.
	t.Run("no revision: nothing is written", func(t *testing.T) {
		t.Parallel()

		s := &server{}
		url := start(t, s)
		stdout, stderr := run(tree(t, s), url, "rename none --force", "")
		require.Equal(
			t,
			"Error: the server at "+strings.TrimPrefix(
				url,
				"http://",
			)+" answered Node 12 (web0) with no revision to guard the change with, so nothing was changed. This is a fault of the server.\n",
			stderr,
		)
		require.Empty(t, stdout)
		require.Empty(t, s.seen, "no request at all")
	})

	t.Run("no revision when read again: no second write", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2, noRevision: true}
		url := start(t, s)
		_, stderr := run(tree(t, s), url, "rename r1 --force", "")
		// The read again is refused by its shape (shapeOf) before the guard looks.
		require.Contains(
			t,
			stderr,
			"sent an answer this CLI cannot read: it has no revision.",
		)
		require.Equal(
			t,
			[]string{
				"GET /api/headscale/v0/version ",
				`PATCH /nodes/12 "r1"`,
				"GET /nodes/12 ",
			},
			s.seen,
		)
	})

	t.Run("a type with a revision and no read does not build", func(t *testing.T) {
		t.Parallel()

		_, err := build(t, &server{}, false)
		require.EqualError(
			t,
			err,
			"rename: target command.guarded has a revision and no read: a write the server refuses because the target changed would not run again",
		)
	})
}

// box is an entity with no revision and no read, as a user is: what its
// delete removes comes from a dry run of the server.
type box struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

// TestQuestionFromTheServer: a question made by a call to the server hands
// its token to the write, and a refusal the command names as Changed asks
// the server again, says why in one line, asks again and writes once more
// with the new token; a second refusal is the error. The tree is one for
// every case, as the CLI's leaves are, so -race sees a token kept in it.
func TestQuestionFromTheServer(t *testing.T) {
	t.Parallel()

	type in struct {
		Box box `arg:"box"`
	}

	const boxChanged clientv0.ProblemCode = "box_changed"

	// server holds the contents of box 1: each dry run answers them and a
	// token of their generation; a write with an older token is refused.
	// grow is how many dry runs add an item after they answer.
	type server struct {
		mu    sync.Mutex
		gen   int
		items []string
		grow  int
		seen  []string
		// noToken answers the dry run with no token, as a broken server.
		noToken bool
		url     string
	}

	start := func(t *testing.T, s *server) string {
		t.Helper()

		hs := httptest.NewServer(
			versioned(func(w http.ResponseWriter, r *http.Request) {
				s.mu.Lock()
				defer s.mu.Unlock()

				s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI())

				w.Header().Set("Headscale-Version", "dev")

				answer := func() {
					token := "t" + strconv.Itoa(s.gen)
					if s.noToken {
						token = ""
					}

					_, _ = fmt.Fprintf(
						w,
						`{"items": [%s], "expect": "%s"}`,
						`"`+strings.Join(s.items, `", "`)+`"`,
						token,
					)
				}

				switch {
				case r.URL.Path == "/api/headscale/v0/version":
				case r.URL.Path == "/api/headscale/v0/me":
					_, _ = io.WriteString(w, rowOf[clientv0.Me](`{}`))
				case r.URL.Query().Get("dryRun") == "true":
					answer()

					if s.grow > 0 {
						s.grow--
						s.gen++
						s.items = append(s.items, "new"+strconv.Itoa(s.gen))
					}
				case r.URL.Query().Get("expect") != "t"+strconv.Itoa(s.gen):
					w.WriteHeader(http.StatusConflict)
					_, _ = w.Write(
						[]byte(
							`{"code": "box_changed", "status": 409, "title": "Box changed", "object": {"kind": "box", "id": "1", "name": "b"}}`,
						),
					)
				default:
					answer()
				}
			}),
		)
		t.Cleanup(hs.Close)
		s.url = hs.URL

		return hs.URL
	}

	type removed struct {
		Items  []string `json:"items"`
		Expect string   `json:"expect"`
	}

	del := func(c Ctx, id string, dry bool) (removed, error) {
		return callOf[removed, anySuccess](
			c.API,
			func(cl *clientv0.Client) (*http.Response, error) {
				q := "?dryRun=" + strconv.FormatBool(dry)
				if e := c.Expect(id); e != nil {
					q += "&expect=" + *e
				}

				req, err := http.NewRequestWithContext(
					c,
					http.MethodDelete,
					cl.Server+"boxes/"+id+q,
					nil,
				)
				if err != nil {
					return nil, err
				}

				return cl.Client.Do(req)
			},
		)
	}

	spec := Spec[in, removed]{
		Name:    "delete",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog delete b"},
		Changed: string(boxChanged),
		Confirm: func(c Ctx, in in) (Prompt, error) {
			d, err := del(c, in.Box.ID, true)
			if err != nil {
				return Prompt{}, err
			}

			p := Prompt{
				Question: "Delete box " + in.Box.Name + "?",
				Action:   "delete it",
				List:     d.Items,
				Guard:    d.Expect,
			}
			if in.Box.Name == "mine" {
				p.Warning = OwnWarning(
					c,
					"It is yours.",
					func(clientv0.Me) bool { return true },
				)
			}

			return p, nil
		},
		Run:  func(c Ctx, in in) (removed, error) { return del(c, in.Box.ID, false) },
		Done: func(_ in, out removed, _ time.Time) string { return "deleted " + strings.Join(out.Items, ", ") },
	}

	find := func(_ context.Context, word string) (box, error) { return box{ID: "1", Name: word}, nil }
	ents := []lib.Entity{
		lib.EntityOf("box", find, nil, func(b box) string { return b.Name }, nil),
	}

	tree, err := build("prog", "A program", allowedAliases(), ents, New(spec))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	run := func(s *server, args, stdin string, width int) (string, string) {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(args), Env{
			// stdout is wide, as a file is to the CLI; the question is on stderr.
			Stdin: strings.NewReader(
				stdin,
			),
			Stdout:      &stdout,
			Stderr:      &stderr,
			Terminal:    true,
			Width:       200,
			StderrWidth: width,
			Version:     &types.VersionInfo{Version: "dev"},
			Environ: []string{
				"HEADSCALE_CONFIG=" + file,
				"HEADSCALE_CLI_ADDRESS=" + start(t, s),
				"HEADSCALE_CLI_API_KEY=key",
			},
		})

		return stdout.String(), stderr.String()
	}

	version := "GET /api/headscale/v0/version"

	for _, tt := range []struct {
		name, args, stdin string
		width             int
		items             []string
		grow              int
		noToken           bool
		stdout, stderr    string
		seen              []string
	}{
		{
			name: "the list under the question, [y/N] on its own line, the token of the dry run sent", args: "delete b", stdin: "y\n",
			stderr: "Delete box b?\n  x, y\n[y/N] ", stdout: "deleted x, y\n",
			seen: []string{version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0"},
		},
		{
			name: "no: nothing is written", args: "delete b", stdin: "n\n",
			stderr: "Delete box b?\n  x, y\n[y/N] Aborted.\n",
			seen:   []string{version, "DELETE /boxes/1?dryRun=true"},
		},
		{
			name: "a list cut to the terminal of the question says how many it leaves out", args: "delete b", stdin: "y\n", width: 16,
			items:  []string{"alpha", "beta", "gamma"},
			stderr: "Delete box b?\n  alpha … (+2)\n[y/N] ", stdout: "deleted alpha, beta, gamma\n",
			seen: []string{version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0"},
		},
		{
			name: "changed once: asked the server again, asked again, written with the new token", args: "delete b", stdin: "y\nyes\n", grow: 1,
			stderr: "Delete box b?\n  x, y\n[y/N] box 1 (b) changed while you decided.\nDelete box b?\n  x, y, new1\n[y/N] ",
			stdout: "deleted x, y, new1\n",
			seen: []string{
				version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0",
				"DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t1",
			},
		},
		{
			name: "changed once with --force: nothing asked, nothing said, the new token", args: "delete b --force", grow: 1,
			stdout: "deleted x, y, new1\n",
			seen: []string{
				version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0",
				"DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t1",
			},
		},
		{
			name: "a warning stands after the list, before [y/N]; who calls is asked once", args: "delete mine", stdin: "y\nyes\n", grow: 1,
			stderr: "Delete box mine?\n  x, y\nIt is yours.\n[y/N] box 1 (mine) changed while you decided.\nDelete box mine?\n  x, y, new1\nIt is yours.\n[y/N] ",
			stdout: "deleted x, y, new1\n",
			seen: []string{
				version, "DELETE /boxes/1?dryRun=true", "GET /api/headscale/v0/me", "DELETE /boxes/1?dryRun=false&expect=t0",
				"DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t1",
			},
		},
		{
			name: "changed twice: the sentence of the builder, whatever the code, after one retry", args: "delete b --force", grow: 2,
			stderr: "Error: box 1 (b) changed while the command ran. Run it again.\n",
			seen: []string{
				version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0",
				"DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t1",
			},
		},
		{
			name: "no to the second question", args: "delete b", stdin: "y\nn\n", grow: 1,
			stderr: "Delete box b?\n  x, y\n[y/N] box 1 (b) changed while you decided.\nDelete box b?\n  x, y, new1\n[y/N] Aborted.\n",
			seen:   []string{version, "DELETE /boxes/1?dryRun=true", "DELETE /boxes/1?dryRun=false&expect=t0", "DELETE /boxes/1?dryRun=true"},
		},
		{
			name: "a dry run that answers no token: no question, no write", args: "delete b --force", noToken: true,
			stderr: "Error: the server at {host} sent no token to guard the change with, so nothing was changed. This is a fault of the server.\n",
			seen:   []string{version, "DELETE /boxes/1?dryRun=true"},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			s := &server{items: tt.items, grow: tt.grow, noToken: tt.noToken}
			if s.items == nil {
				s.items = []string{"x", "y"}
			}

			stdout, stderr := run(s, tt.args, tt.stdin, tt.width)
			require.Equal(
				t,
				strings.ReplaceAll(
					tt.stderr,
					"{host}",
					strings.TrimPrefix(s.url, "http://"),
				),
				stderr,
			)
			require.Equal(t, tt.stdout, stdout)
			require.Equal(t, tt.seen, s.seen)
		})
	}

	t.Run(
		"a guard with no Changed to name its refusal is not sent",
		func(t *testing.T) {
			t.Parallel()

			spec := spec
			spec.Changed = ""

			tree, err := build("prog", "A program", allowedAliases(), ents, New(spec))
			require.NoError(t, err)

			s := &server{items: []string{"x"}}

			var stderr bytes.Buffer

			Run(tree, []string{"delete", "b", "--force"}, Env{
				Stdout:  io.Discard,
				Stderr:  &stderr,
				Version: &types.VersionInfo{Version: "dev"},
				Environ: []string{
					"HEADSCALE_CONFIG=" + file,
					"HEADSCALE_CLI_ADDRESS=" + start(t, s),
					"HEADSCALE_CLI_API_KEY=key",
				},
			})
			require.Equal(t, "Error: "+errGuardNoChanged.Error()+"\n", stderr.String())
			require.Equal(t, []string{version, "DELETE /boxes/1?dryRun=true"}, s.seen)
		},
	)

	t.Run("a refusal named in Changed needs a question", func(t *testing.T) {
		t.Parallel()

		spec := spec
		spec.Confirm = nil
		spec.Name = "remove"

		_, err := build("prog", "A program", allowedAliases(), ents, New(spec))
		require.ErrorContains(t, err, "remove: "+errNoQuestion.Error())
	})

	t.Run(
		"a refusal named in Changed needs a target that is an entity",
		func(t *testing.T) {
			t.Parallel()

			_, err := build(
				"prog",
				"A program",
				allowedAliases(),
				ents,
				New(Spec[getIn, NoOutput]{
					Name:    "remove",
					Short:   "S",
					Long:    "S.",
					Example: []string{"prog remove b"},
					Changed: string(boxChanged),
					Confirm: func(Ctx, getIn) (Prompt, error) { return Prompt{}, nil },
					Run:     func(Ctx, getIn) (NoOutput, error) { return NoOutput{}, nil },
				}),
			)
			require.ErrorContains(t, err, "remove: "+errNoGuardTarget.Error())
		},
	)

	t.Run(
		"a refusal named in Changed on a target with a revision does not build",
		func(t *testing.T) {
			t.Parallel()

			type nodeIn struct {
				Node guarded `arg:"node"`
			}

			find := func(_ context.Context, word string) (guarded, error) { return guarded{ID: "1", Name: word}, nil }
			read := func(_ context.Context, id string) (guarded, error) { return guarded{ID: id}, nil }

			_, err := build(
				"prog",
				"A program",
				allowedAliases(),
				[]lib.Entity{
					lib.EntityOf(
						"node",
						find,
						nil,
						func(g guarded) string { return g.Name },
						read,
					),
				},
				New(Spec[nodeIn, NoOutput]{
					Name:    "remove",
					Short:   "S",
					Long:    "S.",
					Example: []string{"prog remove b"},
					Changed: string(boxChanged),
					Confirm: func(Ctx, nodeIn) (Prompt, error) { return Prompt{}, nil },
					Run:     func(Ctx, nodeIn) (NoOutput, error) { return NoOutput{}, nil },
				}),
			)
			require.ErrorContains(t, err, "remove: "+errGuardMix.Error())
		},
	)
}

// TestOwnGuardIsNotTriedAgain: a command that sends a guard of its own,
// as a write of a policy with the ETag it read, gets the refusal of it as
// the error. The builder tries again only a guard it stored: a second try
// would read the other writer's ETag and replace what that writer wrote.
// The question that asks nothing is there for --force, as a command that
// asks only sometimes has it.
func TestOwnGuardIsNotTriedAgain(t *testing.T) {
	t.Parallel()

	var (
		mu     sync.Mutex
		gen    int
		doc    = "theirs-0"
		seen   []string
		writes int
	)

	hs := httptest.NewServer(versioned(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		seen = append(
			seen,
			strings.TrimSpace(r.Method+" "+r.URL.Path+" "+r.Header.Get("If-Match")),
		)
		w.Header().Set("Headscale-Version", "dev")

		switch {
		case r.URL.Path == "/api/headscale/v0/version":
		case r.Method == http.MethodGet:
			w.Header().Set("ETag", fmt.Sprintf(`"e%d"`, gen))
			w.WriteHeader(http.StatusNoContent)

			// Another admin writes between the CLI's read and its write.
			if writes == 0 {
				gen++
				doc = "theirs-1"
				writes++
			}
		case r.Header.Get("If-Match") != fmt.Sprintf(`"e%d"`, gen):
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write(
				[]byte(
					`{"code": "precondition_failed", "status": 412, "title": "Precondition failed"}`,
				),
			)
		default:
			gen++
			doc = "mine"

			w.WriteHeader(http.StatusNoContent)
		}
	}))
	t.Cleanup(hs.Close)

	send := func(c Ctx, method, etag string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(c, method, hs.URL+"/policy", nil)
		if err != nil {
			return nil, err
		}

		if etag != "" {
			req.Header.Set("If-Match", etag)
		}

		//nolint:forcetypeassert // the generated client
		return c.API.ClientInterface.(*clientv0.Client).Client.Do(req)
	}

	tree, err := build(
		"prog",
		"A program",
		allowedAliases(),
		nil,
		New(Spec[NoInput, NoOutput]{
			Name: "set", Short: "S", Long: "S.", Example: []string{"prog set"},
			Confirm: func(Ctx, NoInput) (Prompt, error) { return Prompt{}, nil },
			Run: func(c Ctx, _ NoInput) (NoOutput, error) {
				var etag string

				_, err := callOf[NoOutput, anySuccess](
					c.API,
					func(*clientv0.Client) (*http.Response, error) {
						resp, err := send(c, http.MethodGet, "")
						if err == nil {
							etag = resp.Header.Get("ETag")
						}

						return resp, err
					},
				)
				if err != nil {
					return NoOutput{}, err
				}

				return callOf[NoOutput, anySuccess](
					c.API,
					func(*clientv0.Client) (*http.Response, error) { return send(c, http.MethodPut, etag) },
				)
			},
			Done: func(NoInput, NoOutput, time.Time) string { return "set" },
		}),
	)
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	var stdout, stderr bytes.Buffer

	code := Run(tree, []string{"set"}, Env{
		Stdout:  &stdout,
		Stderr:  &stderr,
		Version: &types.VersionInfo{Version: "dev"},
		Environ: []string{
			"HEADSCALE_CONFIG=" + file,
			"HEADSCALE_CLI_ADDRESS=" + hs.URL,
			"HEADSCALE_CLI_API_KEY=key",
		},
	})

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, 1, code)
	require.Empty(t, stdout.String())
	require.Equal(
		t,
		"Error: Precondition failed (precondition_failed).\n",
		stderr.String(),
	)
	require.Equal(
		t,
		[]string{"GET /policy", `PUT /policy "e0"`},
		seen,
		"no second read, no second write",
	)
	require.Equal(t, "theirs-1", doc, "the other admin's write is kept")
}

// TestAbout: a problem of the server gets what the command knows of it. A
// target that is gone keeps the name the command read; an expiry in the
// past is the time sent, with the way to expire a node now.
func TestAbout(t *testing.T) {
	t.Parallel()

	type in struct {
		Node   clientv0.Node         `arg:"node"`
		Expiry Opt[Expiry[NowNever]] `flag:"expiry" help:"x"`
	}

	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)
	node := clientv0.Node{Id: "12", Name: "mynode"}

	var e Expiry[NowNever]
	require.NoError(t, e.UnmarshalText([]byte("2024-01-01")))

	problem := func(code clientv0.ProblemCode, o clientv0.ProblemObject) error {
		p := clientv0.Problem{Code: code, Title: "T"}
		if o.Id != "" {
			p.Object = nullable.NewNullableWithValue(o)
		}

		return fmt.Errorf("wrapped: %w", &ProblemError{Problem: p})
	}

	for _, tt := range []struct {
		name string
		err  error
		in   in
		want string
	}{
		{"a target that is gone has the name read", problem(clientv0.ProblemCodeNotFound, clientv0.ProblemObject{Kind: "node", Id: "12"}), in{Node: node}, "Node 12 (mynode) no longer exists."},
		{"another object keeps no name", problem(clientv0.ProblemCodeNotFound, clientv0.ProblemObject{Kind: "node", Id: "13"}), in{Node: node}, "Node 13 no longer exists."},
		{"the expiry sent", problem(clientv0.ProblemCodeExpiryInPast, clientv0.ProblemObject{}), in{Node: node, Expiry: cmdline.Some(e)}, "2024-01-01 00:00 UTC is in the past.\nTo expire the node now: headscale nodes expire 12"},
		{"no expiry sent", problem(clientv0.ProblemCodeExpiryInPast, clientv0.ProblemObject{}), in{Node: node}, "the expiry is in the past."},
		{"not a problem", errBroken, in{Node: node}, errBroken.Error()},
	} {
		// What the builder hands the program (lib's TestAbout holds it):
		// the target as read, and the expiry sent.
		var expiry time.Time
		if e, ok := tt.in.Expiry.Get(); ok {
			expiry = e.At(now)
		}

		about(
			tt.err,
			lib.Object{Kind: "node", ID: tt.in.Node.Id, Name: tt.in.Node.Name},
			"",
			expiry,
		)
		require.Equal(t, tt.want, sentence(tt.err), tt.name)
	}
}
