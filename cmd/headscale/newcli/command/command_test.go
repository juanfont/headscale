package command

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
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
		"the server did not accept the API key.",
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
			"Rename web0? [y/N] Node 12 (web0) changed while the question was open.\nRename web2? [y/N] ",
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

	t.Run("no to the second question", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1", "y\nn\n")
		require.Equal(
			t,
			"Rename web0? [y/N] Node 12 (web0) changed while the question was open.\nRename web2? [y/N] Aborted.\n",
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
			expiry,
		)
		require.Equal(t, tt.want, sentence(tt.err), tt.name)
	}
}
