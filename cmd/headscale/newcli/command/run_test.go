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
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

var errBroken = errors.New("it broke")

// testTree is a tree of local commands that shows every way the builder
// prints.
func testTree(t *testing.T) *Tree {
	t.Helper()

	tree, err := Build("prog", "A program",
		Group{Name: "items", Short: "Manage items", OldNames: []string{"item"}, Commands: []Node{
			NewList(ListSpec[NoInput, item]{
				Name: "list", Short: "List items", Long: "List items.", Example: []string{"prog items list"}, Aliases: []string{"ls"},
				Local: true, Columns: itemColumns, NoRows: "No items.",
				Run: func(Ctx, NoInput) ([]item, error) { return []item{{"1", "apple"}, {"2", ""}}, nil },
			}),
			New(Spec[getIn, item]{
				Name: "get", Short: "Show an item", Long: "Show an item.", Example: []string{"prog items get apple"},
				Local: true, Columns: itemColumns,
				Run: func(c Ctx, in getIn) (item, error) {
					c.Note("a note")

					return item{ID: "1", Name: in.Name}, nil
				},
			}),
			New(Spec[getIn, item]{
				Name: "rename", Short: "Rename an item", Long: "Rename an item.", Example: []string{"prog items rename apple"},
				Local: true,
				Run:   func(_ Ctx, in getIn) (item, error) { return item{ID: "1", Name: in.Name}, nil },
				Done:  func(in getIn, out item, _ time.Time) string { return "Item " + out.ID + " is " + in.Name + "." },
			}),
			New(Spec[NoInput, NoOutput]{
				Name: "break", Short: "Fail", Long: "Fail.", Example: []string{"prog items break"}, Local: true,
				Run: func(Ctx, NoInput) (NoOutput, error) { return NoOutput{}, errBroken },
			}),
		}},
	)
	require.NoError(t, err)

	return tree
}

func TestRun(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		line           string
		stdout, stderr string
		code           int
	}{
		{line: "items list", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items ls -o json", stdout: "[\n  {\n    \"id\": \"1\",\n    \"name\": \"apple\"\n  },\n  {\n    \"id\": \"2\",\n    \"name\": \"\"\n  }\n]\n"},
		{line: "items get apple", stdout: "ID:    1\nName:  apple\n", stderr: "a note\n"},
		{line: "items get apple -o json", stdout: "{\n  \"id\": \"1\",\n  \"name\": \"apple\"\n}\n"},
		{line: "items rename pear", stdout: "Item 1 is pear.\n"},
		{line: "items rename pear -o json", stdout: "{\n  \"id\": \"1\",\n  \"name\": \"pear\"\n}\n"},
		{line: "items break", stderr: "Error: it broke\n", code: 1},
		{line: "items get", stderr: "Error: `items get` needs at least 1 argument, got 0.\n\n  prog items get <name> [extra]\n", code: 1},
		{line: "items get a b c", stderr: "Error: `items get` takes at most 2 arguments, got 3.\n\n  prog items get <name> [extra]\n", code: 1},
		{line: "items list x", stderr: "Error: `items list` takes no arguments, got 1.\n\n  prog items list\n", code: 1},
		{line: "items get a --count x", stderr: "Error: \"x\" is not a valid --count: strconv.ParseInt: parsing \"x\": invalid syntax.\n", code: 1},
		{line: "items lst", stderr: "Error: unknown command \"items lst\". Did you mean \"items list\"?\nRun `prog items --help`.\n", code: 1},
		{line: "item list", stderr: "Error: unknown command \"item\". It is now \"items\".\nRun `prog items --help`.\n", code: 1},
		{line: "items --count 1", stderr: "Error: --count does not apply to `items`.\nRun `prog items --help`.\n", code: 1},
		{line: "items list -n 1", stderr: "Error: --count does not apply to `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -x", stderr: "Error: unknown flag -x for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "nodse list", stderr: "Error: unknown command \"nodse\".\nRun `prog --help`.\n", code: 1},
		{line: "--bogus items list", stderr: "Error: unknown flag --bogus for `prog`.\nRun `prog --help`.\n", code: 1},
		{line: "items list --bogus -h", stderr: "Error: unknown flag --bogus for `items list`.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -o", stderr: "Error: --output needs a value.\nRun `prog items list --help`.\n", code: 1},
		{line: "items list -o=", stderr: "Error: \"\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o yaml", stderr: "Error: \"yaml\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o a -o b", stderr: "Error: \"a\" is not a valid --output: the only format is json.\n", code: 1},
		{line: "items list -o json -o json", stderr: "Error: --output is given twice. Only --filter may be repeated.\n", code: 1},
		{line: "--help=1", stderr: "Error: --help takes true or false, not \"1\".\n", code: 1},
		{line: "items list --help=false", stdout: "ID  NAME\n1   apple\n2   -\n"},
		{line: "items -o json", stdout: `Manage items

Commands:

  list                    List items (alias: ls)
  get <name> [extra]      Show an item
  rename <name> [extra]   Rename an item
  break                   Fail

Examples:

  prog items list
  prog items get apple
  prog items rename apple
  prog items break
`},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(testTree(t), strings.Fields(tt.line), Env{Stdout: &stdout, Stderr: &stderr, Now: time.Now})

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

// fakeServer answers like v0, with a field this build does not know in
// every object: /health changes with each call, /items has two pages,
// /broken fails on its second page, and DELETE /thing has no body.
func fakeServer(t *testing.T) string {
	t.Helper()

	var calls atomic.Int32

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Headscale-Version", "dev")
		w.Header().Set("Headscale-Commit", "a491228")

		switch {
		case r.Method == http.MethodDelete:
			w.WriteHeader(http.StatusNoContent)
		case r.URL.Path == "/items" && r.URL.Query().Get("pageToken") == "":
			_, _ = w.Write([]byte(`{"items": [{"id": "1", "name": "a", "x": 1}], "nextPageToken": "p2"}`))
		case r.URL.Path == "/items":
			_, _ = w.Write([]byte(`{"items": [{"id": "2", "name": "b", "x": 2}]}`))
		case r.URL.Path == "/broken" && r.URL.Query().Get("pageToken") == "":
			_, _ = w.Write([]byte(`{"broken": [{"id": "1", "name": "a"}], "nextPageToken": "p2"}`))
		case r.URL.Path == "/broken":
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = w.Write([]byte(`{"code": "internal", "status": 500, "title": "Internal", "requestId": "r1"}`))
		default:
			n := calls.Add(1)
			_, _ = fmt.Fprintf(w, `{"healthy": true, "databaseConnectivity": %t, "warnings": [], "call": %d}`, n == 1, n)
		}
	}))
	t.Cleanup(s.Close)

	return s.URL
}

func listItems(c Ctx) ([]item, error) { return listOfPath(c, "items") }

func listOfPath(c Ctx, path string) ([]item, error) {
	return walk[item](c.API, path, func(cl *clientv0.Client, p page) (*http.Response, error) {
		token := ""
		if p.token != nil {
			token = *p.token
		}

		req, err := http.NewRequestWithContext(c, http.MethodGet, cl.Server+path+"?pageToken="+token, nil)
		if err != nil {
			return nil, err
		}

		return cl.Client.Do(req)
	})
}

// TestJSONIsTheAnswer: -o json prints the answer that Run's value came
// from, and a value that no answer holds is an error in every mode.
func TestJSONIsTheAnswer(t *testing.T) {
	t.Parallel()

	spec := func(name string, run func(Ctx, NoInput) (clientv0.Health, error)) Node {
		return New(Spec[NoInput, clientv0.Health]{
			Name: name, Short: "S", Long: "S.", Example: []string{"prog " + name}, Run: run,
			Done: func(NoInput, clientv0.Health, time.Time) string { return "done" },
		})
	}

	tree, err := Build("prog", "A program",
		spec("first", func(c Ctx, _ NoInput) (clientv0.Health, error) {
			first, err := c.API.Health(c)
			if err != nil {
				return first, err
			}

			_, err = c.API.Health(c)

			return first, err
		}),
		spec("changed", func(c Ctx, _ NoInput) (clientv0.Health, error) {
			h, err := c.API.Health(c)
			h.Healthy = false

			return h, err
		}),
		spec("made", func(Ctx, NoInput) (clientv0.Health, error) { return clientv0.Health{Healthy: true}, nil }),
		// A zero value is no answer either: only ErrNotRead says that
		// there is nothing to print.
		spec("zero", func(Ctx, NoInput) (clientv0.Health, error) { return clientv0.Health{}, nil }),
		New(Spec[NoInput, clientv0.Health]{
			Name: "local", Short: "S", Long: "S.", Example: []string{"prog local"}, Local: true,
			Run:  func(c Ctx, _ NoInput) (clientv0.Health, error) { return c.API.Health(c) },
			Done: func(NoInput, clientv0.Health, time.Time) string { return "done" },
		}),
		NewList(ListSpec[NoInput, item]{
			Name: "items", Short: "S", Long: "S.", Example: []string{"prog items"}, Columns: itemColumns, NoRows: "No items.",
			Run: func(c Ctx, _ NoInput) ([]item, error) {
				rows, err := listItems(c)
				slices.Reverse(rows)

				return rows, err
			},
		}),
		NewList(ListSpec[NoInput, item]{
			Name: "broken", Short: "S", Long: "S.", Example: []string{"prog broken"}, Columns: itemColumns, NoRows: "No items.",
			Run: func(c Ctx, _ NoInput) ([]item, error) { return listOfPath(c, "broken") },
		}),
		New(Spec[NoInput, item]{
			Name: "item", Short: "S", Long: "S.", Example: []string{"prog item"}, Columns: itemColumns,
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
				return call[NoOutput](c.API, func(cl *clientv0.Client) (*http.Response, error) {
					req, err := http.NewRequestWithContext(c, http.MethodDelete, cl.Server+"thing", nil)
					if err != nil {
						return nil, err
					}

					return cl.Client.Do(req)
				})
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
		{line: "zero -o json", stderr: notAnswer, code: 1},
		{line: "local", stderr: "Error: this command is Local and has no server to call\n", code: 1},
		{line: "items -o json", stdout: "[\n  {\n    \"id\": \"2\",\n    \"name\": \"b\",\n    \"x\": 2\n  },\n  {\n    \"id\": \"1\",\n    \"name\": \"a\",\n    \"x\": 1\n  }\n]\n"},
		{line: "items", stdout: "ID  NAME\n2   b\n1   a\n"},
		{line: "item -o json", stdout: "{\n  \"id\": \"2\",\n  \"name\": \"b\",\n  \"x\": 2\n}\n"},
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
				Stdout: &stdout, Stderr: &stderr, Version: &types.VersionInfo{Version: "dev", Commit: tt.commit},
				Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + fakeServer(t), "HEADSCALE_CLI_API_KEY=key"},
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

var errNoMatch = errors.New(`no item matches "nope".`) //nolint:staticcheck // a sentence of the CLI

// TestLookupKeepsItsSentence: an error of a lookup is printed as the
// lookup wrote it, not as a bad argument.
func TestLookupKeepsItsSentence(t *testing.T) {
	t.Parallel()

	type in struct {
		Item found `arg:"item"`
	}

	lookup := entityOf("item", func(_ context.Context, word string) (found, error) {
		switch word {
		case "nope":
			return found{}, errNoMatch
		case "down":
			return found{}, &connectError{target: "/run/headscale.sock", err: errBroken}
		}

		return found{ID: word}, nil
	}, nil, func(f found) string { return f.ID }, nil)

	tree, err := build("prog", "A program", allowedAliases(), []entity{lookup}, New(Spec[in, NoOutput]{
		Name: "get", Short: "S", Long: "S.", Example: []string{"prog get 1"}, Local: true,
		Run:  noop[in, NoOutput],
		Done: func(in in, _ NoOutput, _ time.Time) string { return "got " + in.Item.ID },
	}))
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

// TestTagIsNoUser: a tag where a user is wanted is said to be one, after
// the users were read, and the command's hint follows it; a word of no
// other kind gets no hint.
func TestTagIsNoUser(t *testing.T) {
	t.Parallel()

	type in struct {
		User clientv0.User `arg:"user"`
	}

	tree, err := Build("prog", "A program", New(Spec[in, NoOutput]{
		Name: "give", Short: "S", Long: "S.", Example: []string{"prog give alice"},
		Hint: func(args []string) string { return "a hint for " + args[0] },
		Run:  noop[in, NoOutput],
	}))
	require.NoError(t, err)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Headscale-Version", "dev")
		_, _ = w.Write([]byte(`{"users": [{"id": "1", "name": "alice"}]}`))
	}))
	t.Cleanup(s.Close)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	for line, want := range map[string]string{
		"give alice":  "",
		"give tag:ci": "Error: a tag is not a user.\na hint for tag:ci\n",
		"give bob":    "Error: no user matches \"bob\".\n",
	} {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(line), Env{
			Stdout: &stdout, Stderr: &stderr, Version: &types.VersionInfo{Version: "dev"},
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + s.URL, "HEADSCALE_CLI_API_KEY=key"},
		})
		require.Equal(t, want, stderr.String(), line)
	}
}

// TestSentence: a command that wraps a problem, as Go code does, still
// prints the CLI's sentence.
func TestSentence(t *testing.T) {
	t.Parallel()

	p := &ProblemError{Problem: clientv0.Problem{Code: clientv0.ProblemCodeUnauthorized}}
	require.Equal(t, "the server did not accept the credential of this CLI: it is unknown, expired or revoked.\nIt is set by cli.api_key in the config file, or HEADSCALE_CLI_API_KEY.", sentence(fmt.Errorf("getting user: %w", p)))
	require.Equal(t, "cannot connect to x: it broke", sentence(fmt.Errorf("listing: %w", &connectError{target: "x", err: errBroken})))
	require.Equal(t, "listing: it broke", sentence(fmt.Errorf("listing: %w", errBroken)))
}

// TestNothingToChange: a set needs one of the flags it changes; a set with
// no such flag replaces its argument, and a wrong count comes first.
func TestNothingToChange(t *testing.T) {
	t.Parallel()

	type setIn struct {
		Name  string      `arg:"name"`
		New   Opt[string] `flag:"new-name" help:"New name"`
		Email Opt[string] `flag:"email"    help:"New email"`
		Force bool        `flag:"force"    help:"Do not ask"`
	}

	type replaceIn struct {
		Name string `arg:"name"`
	}

	done := func(setIn, NoOutput, time.Time) string { return "set" }
	tree, err := Build("prog", "A program", Group{Name: "items", Short: "Items", Commands: []Node{
		New(Spec[setIn, NoOutput]{Name: "set", Short: "S", Long: "S.", Example: []string{"prog items set a --email x"}, Local: true, NeedsChange: true, Run: noop[setIn, NoOutput], Done: done}),
		// A set that does not say NeedsChange takes a line with no flag.
		New(Spec[setIn, NoOutput]{Name: "replace", Short: "S", Long: "S.", Example: []string{"prog items replace a"}, Local: true, Run: noop[setIn, NoOutput], Done: done}),
		Group{Name: "tags", Short: "Tags", Commands: []Node{
			New(Spec[replaceIn, NoOutput]{Name: "set", Short: "S", Long: "S.", Example: []string{"prog items tags set a"}, Local: true, Run: noop[replaceIn, NoOutput]}),
		}},
	}})
	require.NoError(t, err)

	for line, want := range map[string]string{
		"items set a":              "Error: nothing to change. Give at least one of\n  --new-name, --email\n",
		"items set a --force":      "Error: nothing to change. Give at least one of\n  --new-name, --email\n",
		"items set":                "Error: `items set` needs 1 argument, got 0.\n\n  prog items set <name>\n",
		"items set a --new-name=":  "",
		"items set a --email x":    "",
		"items tags set a":         "",
		"items replace a":          "",
		"items set a -h --force=x": "Error: --force takes true or false, not \"x\".\n",
	} {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(line), Env{Stdout: &stdout, Stderr: &stderr})
		require.Equal(t, want, stderr.String(), line)
	}
}

// TestNeedsChangeNeedsAFlag: NeedsChange on a command with no Opt flag is
// a wrong spec.
func TestNeedsChangeNeedsAFlag(t *testing.T) {
	t.Parallel()

	type in struct {
		Name string `arg:"name"`
	}

	_, err := Build("prog", "A program", New(Spec[in, NoOutput]{
		Name: "set", Short: "S", Long: "S.", Example: []string{"prog set a"}, Local: true, NeedsChange: true, Run: noop[in, NoOutput],
	}))
	require.EqualError(t, err, "set: NeedsChange and no Opt flag that changes a field")
}

// TestVisibleText: a Done text and everything on stderr show control
// characters of the server as escapes; JSON escapes them itself.
func TestVisibleText(t *testing.T) {
	t.Parallel()

	var stdout, stderr bytes.Buffer

	require.Equal(t, 0, Run(testTree(t), []string{"items", "rename", "a\x1b[31m\u202e"}, Env{Stdout: &stdout, Stderr: &stderr}))
	require.Equal(t, `Item 1 is a\x1b[31m\u202e.`+"\n", stdout.String())

	stdout.Reset()
	require.Equal(t, 0, Run(testTree(t), []string{"items", "rename", "a\x1b\u202e\u0085", "-o", "json"}, Env{Stdout: &stdout, Stderr: &stderr}))
	require.Contains(t, stdout.String(), `"name": "a\u001b\u202e\u0085"`)

	// The last filter keeps the sentence's own breaks and the backslashes
	// that the text of the server already has doubled.
	var b bytes.Buffer

	_, err := visible{&b}.Write([]byte("Error: \x1b[2J\u202e \\\\x\n\tnext\n"))
	require.NoError(t, err)
	require.Equal(t, `Error: \x1b[2J\u202e \\x`+"\n\tnext\n", b.String())
}

// TestPrompt: a command with Confirm asks on stderr and goes on only on y
// or yes; no is "Aborted." and exit 1, no terminal is an error that names
// --force, and --force or a Prompt with no question asks nothing.
func TestPrompt(t *testing.T) {
	t.Parallel()

	ask := true
	tree, err := Build("prog", "A program", New(Spec[getIn, NoOutput]{
		Name: "delete", Short: "Delete an item", Long: "Delete an item.", Example: []string{"prog delete apple"}, Local: true,
		Confirm: func(_ Ctx, in getIn) (Prompt, error) {
			if !ask || in.Name == "pear" {
				return Prompt{}, nil
			}

			return Prompt{Question: "Delete Item 1 (" + in.Name + ")?", Action: "delete Item 1 (" + in.Name + ")"}, nil
		},
		Run:  func(Ctx, getIn) (NoOutput, error) { return NoOutput{}, nil },
		Done: func(in getIn, _ NoOutput, _ time.Time) string { return "Item 1 (" + in.Name + ") deleted." },
	}))
	require.NoError(t, err)

	for _, tt := range []struct {
		name, args, stdin string
		terminal          bool
		stdout, stderr    string
		code              int
	}{
		{name: "yes", args: "delete apple", stdin: "y\n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "yes in words", args: "delete apple", stdin: " YES \n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "no", args: "delete apple", stdin: "n\n", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{name: "enter is no", args: "delete apple", stdin: "\n", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{name: "no answer is no", args: "delete apple", terminal: true, stderr: "Delete Item 1 (apple)? [y/N] Aborted.\n", code: 1},
		{
			name: "no terminal", args: "delete apple", stdin: "y\n",
			stderr: "Error: confirmation needed, but there is no terminal.\nRun again with --force to delete Item 1 (apple).\n", code: 1,
		},
		{name: "--force asks nothing", args: "delete apple --force", stdout: "Item 1 (apple) deleted.\n"},
		{name: "--force=false asks", args: "delete --force=false apple", stdin: "y\n", terminal: true, stdout: "Item 1 (apple) deleted.\n", stderr: "Delete Item 1 (apple)? [y/N] "},
		{name: "a prompt with no question asks nothing", args: "delete pear", stdout: "Item 1 (pear) deleted.\n"},
		{name: "--force where nothing is asked", args: "delete pear --force", stdout: "Item 1 (pear) deleted.\n"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			code := Run(tree, strings.Fields(tt.args), Env{Stdin: strings.NewReader(tt.stdin), Stdout: &stdout, Stderr: &stderr, Terminal: tt.terminal})
			require.Equal(t, tt.stdout, stdout.String())
			require.Equal(t, tt.stderr, stderr.String())
			require.Equal(t, tt.code, code)
		})
	}
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
	}

	start := func(t *testing.T, s *server) string {
		t.Helper()

		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.seen = append(s.seen, r.Method+" "+r.URL.Path+" "+r.Header.Get("If-Match"))
			w.Header().Set("Headscale-Version", "dev")

			node := func() string { return fmt.Sprintf(`{"id": "12", "name": "web%d", "revision": "r%d"}`, s.rev, s.rev) }

			switch {
			case r.Method == http.MethodGet && s.gone:
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"code": "not_found", "status": 404, "title": "Not found", "object": {"kind": "node", "id": "12"}}`))
			case r.Method == http.MethodGet:
				_, _ = w.Write([]byte(node()))
				s.rev += s.bumps
			case r.Header.Get("If-Match") != fmt.Sprintf(`"r%d"`, s.rev):
				w.WriteHeader(http.StatusPreconditionFailed)
				_, _ = fmt.Fprintf(w, `{"code": "precondition_failed", "status": 412, "title": "Precondition failed", "object": {"kind": "node", "id": "12", "name": "web%d"}}`, s.rev)
			default:
				_, _ = w.Write([]byte(node()))
			}
		}))
		t.Cleanup(hs.Close)

		return hs.URL
	}

	read := func(ctx context.Context, id string) (guarded, error) {
		return call[guarded](ctxOf(ctx).API, func(cl *clientv0.Client) (*http.Response, error) {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, cl.Server+"nodes/"+id, nil)
			if err != nil {
				return nil, err
			}

			return cl.Client.Do(req)
		})
	}

	build := func(t *testing.T, s *server, reads bool) (*Tree, error) {
		t.Helper()

		find := func(_ context.Context, word string) (guarded, error) {
			return guarded{ID: "12", Name: "web0", Revision: word}, nil
		}

		e := entityOf("node", find, nil, func(g guarded) string { return g.Name }, read)
		if !reads {
			e = entityOf("node", find, nil, func(g guarded) string { return g.Name }, nil)
		}

		return build("prog", "A program", allowedAliases(), []entity{e}, New(Spec[in, guarded]{
			Name: "rename", Short: "S", Long: "S.", Example: []string{"prog rename r1"},
			Confirm: func(_ Ctx, in in) (Prompt, error) {
				s.mu.Lock()
				defer s.mu.Unlock()

				s.prompted = append(s.prompted, in.Node.Name)

				return Prompt{Question: "Rename " + in.Node.Name + "?", Action: "rename it"}, nil
			},
			Run: func(c Ctx, in in) (guarded, error) {
				return call[guarded](c.API, func(cl *clientv0.Client) (*http.Response, error) {
					req, err := http.NewRequestWithContext(c, http.MethodPatch, cl.Server+"nodes/"+in.Node.ID, nil)
					if err != nil {
						return nil, err
					}

					if rev := c.API.ifMatch(in.Node.ID); rev != nil {
						req.Header.Set("If-Match", *rev)
					}

					return cl.Client.Do(req)
				})
			},
			Done: func(in in, out guarded, _ time.Time) string { return "renamed " + in.Node.Name + " to " + out.Name },
		}))
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
			Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr, Terminal: true, Version: &types.VersionInfo{Version: "dev"},
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + url, "HEADSCALE_CLI_API_KEY=key"},
		})

		return stdout.String(), stderr.String()
	}

	t.Run("changed once: read again, asked again, written", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1", "y\nyes\n")
		require.Equal(t, "Rename web0? [y/N] Node 12 (web0) changed while you decided.\nRename web2? [y/N] ", stderr)
		require.Equal(t, "renamed web2 to web2\n", stdout)
		require.Equal(t, []string{"GET /api/headscale/v0/version ", `PATCH /nodes/12 "r1"`, "GET /nodes/12 ", `PATCH /nodes/12 "r2"`}, s.seen)
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
		require.Equal(t, "Rename web0? [y/N] Node 12 (web0) changed while you decided.\nRename web2? [y/N] Aborted.\n", stderr)
		require.Empty(t, stdout)
		require.Len(t, s.seen, 3, "no second write")
	})

	t.Run("it keeps changing", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2, bumps: 1}
		stdout, stderr := run(tree(t, s), start(t, s), "rename r1 --force", "")
		require.Equal(t, "Error: Node 12 (web4) changed while the command ran. Run it again.\n", stderr)
		require.Empty(t, stdout)
		require.Len(t, s.seen, 4, "one retry, no more")
	})

	t.Run("gone when read again", func(t *testing.T) {
		t.Parallel()

		s := &server{rev: 2, gone: true}
		_, stderr := run(tree(t, s), start(t, s), "rename r1 --force", "")
		require.Equal(t, "Error: Node 12 (web0) no longer exists.\n", stderr, "the server names no object that is gone; the target has its name")
	})

	t.Run("a type with a revision and no read does not build", func(t *testing.T) {
		t.Parallel()

		_, err := build(t, &server{}, false)
		require.EqualError(t, err, "rename: target command.guarded has a revision and no read: a write the server refuses because the target changed would not run again")
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

		hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			s.mu.Lock()
			defer s.mu.Unlock()

			s.seen = append(s.seen, r.Method+" "+r.URL.RequestURI())

			w.Header().Set("Headscale-Version", "dev")

			answer := func() {
				token := "t" + strconv.Itoa(s.gen)
				if s.noToken {
					token = ""
				}

				_, _ = fmt.Fprintf(w, `{"items": [%s], "expect": "%s"}`, `"`+strings.Join(s.items, `", "`)+`"`, token)
			}

			switch {
			case r.URL.Path == "/api/headscale/v0/version":
			case r.URL.Path == "/api/headscale/v0/me":
				_, _ = w.Write([]byte(`{}`))
			case r.URL.Query().Get("dryRun") == "true":
				answer()

				if s.grow > 0 {
					s.grow--
					s.gen++
					s.items = append(s.items, "new"+strconv.Itoa(s.gen))
				}
			case r.URL.Query().Get("expect") != "t"+strconv.Itoa(s.gen):
				w.WriteHeader(http.StatusConflict)
				_, _ = w.Write([]byte(`{"code": "box_changed", "status": 409, "title": "Box changed", "object": {"kind": "box", "id": "1", "name": "b"}}`))
			default:
				answer()
			}
		}))
		t.Cleanup(hs.Close)
		s.url = hs.URL

		return hs.URL
	}

	type removed struct {
		Items  []string `json:"items"`
		Expect string   `json:"expect"`
	}

	del := func(c Ctx, id string, dry bool) (removed, error) {
		return call[removed](c.API, func(cl *clientv0.Client) (*http.Response, error) {
			q := "?dryRun=" + strconv.FormatBool(dry)
			if e := c.API.expect(id); e != nil {
				q += "&expect=" + *e
			}

			req, err := http.NewRequestWithContext(c, http.MethodDelete, cl.Server+"boxes/"+id+q, nil)
			if err != nil {
				return nil, err
			}

			return cl.Client.Do(req)
		})
	}

	spec := Spec[in, removed]{
		Name: "delete", Short: "S", Long: "S.", Example: []string{"prog delete b"},
		Changed: boxChanged,
		Confirm: func(c Ctx, in in) (Prompt, error) {
			d, err := del(c, in.Box.ID, true)
			if err != nil {
				return Prompt{}, err
			}

			p := Prompt{Question: "Delete box " + in.Box.Name + "?", Action: "delete it", List: d.Items, Guard: d.Expect}
			if in.Box.Name == "mine" {
				p.Warning = OwnWarning(c, "It is yours.", func(clientv0.Me) bool { return true })
			}

			return p, nil
		},
		Run:  func(c Ctx, in in) (removed, error) { return del(c, in.Box.ID, false) },
		Done: func(_ in, out removed, _ time.Time) string { return "deleted " + strings.Join(out.Items, ", ") },
	}

	find := func(_ context.Context, word string) (box, error) { return box{ID: "1", Name: word}, nil }
	ents := []entity{entityOf("box", find, nil, func(b box) string { return b.Name }, nil)}

	tree, err := build("prog", "A program", allowedAliases(), ents, New(spec))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	run := func(s *server, args, stdin string, width int) (string, string) {
		var stdout, stderr bytes.Buffer

		Run(tree, strings.Fields(args), Env{
			// stdout is wide, as a file is to the CLI; the question is on stderr.
			Stdin: strings.NewReader(stdin), Stdout: &stdout, Stderr: &stderr, Terminal: true, Width: 200, StderrWidth: width, Version: &types.VersionInfo{Version: "dev"},
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + start(t, s), "HEADSCALE_CLI_API_KEY=key"},
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
			require.Equal(t, strings.ReplaceAll(tt.stderr, "{host}", strings.TrimPrefix(s.url, "http://")), stderr)
			require.Equal(t, tt.stdout, stdout)
			require.Equal(t, tt.seen, s.seen)
		})
	}

	t.Run("a guard with no Changed to name its refusal is not sent", func(t *testing.T) {
		t.Parallel()

		spec := spec
		spec.Changed = ""

		tree, err := build("prog", "A program", allowedAliases(), ents, New(spec))
		require.NoError(t, err)

		s := &server{items: []string{"x"}}

		var stderr bytes.Buffer

		Run(tree, []string{"delete", "b", "--force"}, Env{
			Stdout: io.Discard, Stderr: &stderr, Version: &types.VersionInfo{Version: "dev"},
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + start(t, s), "HEADSCALE_CLI_API_KEY=key"},
		})
		require.Equal(t, "Error: "+errGuardNoChanged.Error()+"\n", stderr.String())
		require.Equal(t, []string{version, "DELETE /boxes/1?dryRun=true"}, s.seen)
	})

	t.Run("a refusal named in Changed needs a question", func(t *testing.T) {
		t.Parallel()

		spec := spec
		spec.Confirm = nil
		spec.Name = "remove"

		_, err := build("prog", "A program", allowedAliases(), ents, New(spec))
		require.ErrorContains(t, err, "remove: "+errNoQuestion.Error())
	})

	t.Run("a refusal named in Changed needs a target that is an entity", func(t *testing.T) {
		t.Parallel()

		_, err := build("prog", "A program", allowedAliases(), ents, New(Spec[getIn, NoOutput]{
			Name: "remove", Short: "S", Long: "S.", Example: []string{"prog remove b"}, Changed: boxChanged,
			Confirm: func(Ctx, getIn) (Prompt, error) { return Prompt{}, nil },
			Run:     func(Ctx, getIn) (NoOutput, error) { return NoOutput{}, nil },
		}))
		require.ErrorContains(t, err, "remove: "+errNoGuardTarget.Error())
	})

	t.Run("a refusal named in Changed on a target with a revision does not build", func(t *testing.T) {
		t.Parallel()

		type nodeIn struct {
			Node guarded `arg:"node"`
		}

		find := func(_ context.Context, word string) (guarded, error) { return guarded{ID: "1", Name: word}, nil }
		read := func(_ context.Context, id string) (guarded, error) { return guarded{ID: id}, nil }

		_, err := build("prog", "A program", allowedAliases(), []entity{entityOf("node", find, nil, func(g guarded) string { return g.Name }, read)}, New(Spec[nodeIn, NoOutput]{
			Name: "remove", Short: "S", Long: "S.", Example: []string{"prog remove b"}, Changed: boxChanged,
			Confirm: func(Ctx, nodeIn) (Prompt, error) { return Prompt{}, nil },
			Run:     func(Ctx, nodeIn) (NoOutput, error) { return NoOutput{}, nil },
		}))
		require.ErrorContains(t, err, "remove: "+errGuardMix.Error())
	})
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

	hs := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()

		seen = append(seen, strings.TrimSpace(r.Method+" "+r.URL.Path+" "+r.Header.Get("If-Match")))
		w.Header().Set("Headscale-Version", "dev")

		switch {
		case r.URL.Path == "/api/headscale/v0/version":
		case r.Method == http.MethodGet:
			w.Header().Set("ETag", fmt.Sprintf(`"e%d"`, gen))
			_, _ = w.Write([]byte(`{}`))

			// Another admin writes between the CLI's read and its write.
			if writes == 0 {
				gen++
				doc = "theirs-1"
				writes++
			}
		case r.Header.Get("If-Match") != fmt.Sprintf(`"e%d"`, gen):
			w.WriteHeader(http.StatusPreconditionFailed)
			_, _ = w.Write([]byte(`{"code": "precondition_failed", "status": 412, "title": "Precondition failed"}`))
		default:
			gen++
			doc = "mine"
			_, _ = w.Write([]byte(`{}`))
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

		return c.API.c.Client.Do(req)
	}

	tree, err := build("prog", "A program", allowedAliases(), nil, New(Spec[NoInput, NoOutput]{
		Name: "set", Short: "S", Long: "S.", Example: []string{"prog set"},
		Confirm: func(Ctx, NoInput) (Prompt, error) { return Prompt{}, nil },
		Run: func(c Ctx, _ NoInput) (NoOutput, error) {
			var etag string

			_, err := call[NoOutput](c.API, func(*clientv0.Client) (*http.Response, error) {
				resp, err := send(c, http.MethodGet, "")
				if err == nil {
					etag = resp.Header.Get("ETag")
				}

				return resp, err
			})
			if err != nil {
				return NoOutput{}, err
			}

			return call[NoOutput](c.API, func(*clientv0.Client) (*http.Response, error) { return send(c, http.MethodPut, etag) })
		},
		Done: func(NoInput, NoOutput, time.Time) string { return "set" },
	}))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	var stdout, stderr bytes.Buffer

	code := Run(tree, []string{"set"}, Env{
		Stdout: &stdout, Stderr: &stderr, Version: &types.VersionInfo{Version: "dev"},
		Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + hs.URL, "HEADSCALE_CLI_API_KEY=key"},
	})

	mu.Lock()
	defer mu.Unlock()

	require.Equal(t, 1, code)
	require.Empty(t, stdout.String())
	require.Equal(t, "Error: Precondition failed (precondition_failed).\n", stderr.String())
	require.Equal(t, []string{"GET /policy", `PUT /policy "e0"`}, seen, "no second read, no second write")
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

	ents := map[reflect.Type]entity{}
	for _, e := range entities() {
		ents[e.t] = e
	}

	c := Ctx{entities: ents, now: func() time.Time { return time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC) }}
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
		require.Equal(t, tt.want, sentence(c.about(tt.err, tt.in)), tt.name)
	}
}

// TestValid: Valid refuses a line before any call or lookup, with its own
// sentence; a line it takes runs.
func TestValid(t *testing.T) {
	t.Parallel()

	ran := false
	tree, err := Build("prog", "A program", New(Spec[getIn, NoOutput]{
		Name: "get", Short: "Get", Long: "Get.", Example: []string{"prog get a"}, Local: true,
		Valid: func(in getIn) error {
			if in.Name != "a" {
				return errors.New(strconv.Quote(in.Name) + " is not a.") //nolint:err113 // a sentence of the test
			}

			return nil
		},
		Run: func(Ctx, getIn) (NoOutput, error) { ran = true; return NoOutput{}, nil },
	}))
	require.NoError(t, err)

	var stderr bytes.Buffer

	require.Equal(t, 1, Run(tree, []string{"get", "b"}, Env{Stdout: io.Discard, Stderr: &stderr}))
	require.Equal(t, "Error: \"b\" is not a.\n", stderr.String())
	require.False(t, ran)

	require.Equal(t, 0, Run(tree, []string{"get", "a"}, Env{Stdout: io.Discard, Stderr: io.Discard}))
	require.True(t, ran)
}
