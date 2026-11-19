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
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
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
				Local: true, Columns: itemColumns,
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
// every object: /health changes with each call, /items has two pages, and
// DELETE /thing has no body.
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
		default:
			n := calls.Add(1)
			_, _ = fmt.Fprintf(w, `{"healthy": true, "databaseConnectivity": %t, "warnings": [], "call": %d}`, n == 1, n)
		}
	}))
	t.Cleanup(s.Close)

	return s.URL
}

func listItems(c Ctx) ([]item, error) {
	return walk[item](c.API, "items", func(cl *clientv0.Client, token string) (*http.Response, error) {
		req, err := http.NewRequestWithContext(c, http.MethodGet, cl.Server+"items?pageToken="+token, nil)
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
		New(Spec[NoInput, clientv0.Health]{
			Name: "local", Short: "S", Long: "S.", Example: []string{"prog local"}, Local: true,
			Run:  func(c Ctx, _ NoInput) (clientv0.Health, error) { return c.API.Health(c) },
			Done: func(NoInput, clientv0.Health, time.Time) string { return "done" },
		}),
		NewList(ListSpec[NoInput, item]{
			Name: "items", Short: "S", Long: "S.", Example: []string{"prog items"}, Columns: itemColumns,
			Run: func(c Ctx, _ NoInput) ([]item, error) {
				rows, err := listItems(c)
				slices.Reverse(rows)

				return rows, err
			},
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
		{line: "local", stderr: "Error: this command is Local and has no server to call\n", code: 1},
		{line: "items -o json", stdout: "[\n  {\n    \"id\": \"2\",\n    \"name\": \"b\",\n    \"x\": 2\n  },\n  {\n    \"id\": \"1\",\n    \"name\": \"a\",\n    \"x\": 1\n  }\n]\n"},
		{line: "items", stdout: "ID  NAME\n2   b\n1   a\n"},
		{line: "item -o json", stdout: "{\n  \"id\": \"2\",\n  \"name\": \"b\",\n  \"x\": 2\n}\n"},
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

	lookup := cmdline.LateReader(func(_ context.Context, word string) (found, error) {
		switch word {
		case "nope":
			return found{}, errNoMatch
		case "down":
			return found{}, &connectError{target: "/run/headscale.sock", err: errBroken}
		}

		return found{ID: word}, nil
	})

	tree, err := build("prog", "A program", allowedAliases, []cmdline.Option{lookup}, New(Spec[in, NoOutput]{
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

// TestSentence: a command that wraps a problem, as Go code does, still
// prints the CLI's sentence.
func TestSentence(t *testing.T) {
	t.Parallel()

	p := &ProblemError{Problem: clientv0.Problem{Code: clientv0.Unauthorized}}
	require.Equal(t, "the server did not accept the API key.", sentence(fmt.Errorf("getting user: %w", p)))
	require.Equal(t, "cannot connect to x: it broke", sentence(fmt.Errorf("listing: %w", &connectError{target: "x", err: errBroken})))
	require.Equal(t, "listing: it broke", sentence(fmt.Errorf("listing: %w", errBroken)))
}
