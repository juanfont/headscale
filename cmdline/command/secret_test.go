package command

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/cmdline/table"
	"github.com/stretchr/testify/require"
)

// secreted is a result that holds a secret, such as a new key.
type secreted struct {
	ID  string `json:"id"`
	Key string `json:"key"`
}

const madeKey = "hskey-auth-ab12cd345678-s3cret" //nolint:gosec // a made-up secret

// secretTree has a create that prints what made gives, with list and
// delete beside it, as a Secret command needs.
func secretTree(tb testing.TB, made func() (secreted, error)) *Tree {
	tb.Helper()

	tree, err := testBuild(
		"prog",
		"A program",
		Group{Name: "keys", Short: "Keys", Commands: []Node{
			NewList(ListSpec[testS, NoInput, item]{
				Name:    "list",
				Short:   "S",
				Long:    "S.",
				Example: []string{"prog keys list"},
				Local:   true,
				Columns: itemColumns,
				NoRows:  "No keys.",
				Run:     noop[NoInput, []item],
			}),
			New(Spec[testS, NoInput, secreted]{
				Name:    "create",
				Short:   "S",
				Long:    "S.",
				Example: []string{"prog keys create"},
				Local:   true,
				Run:     func(Ctx[testS], NoInput) (secreted, error) { return made() },
				Secret:  func(out secreted) string { return out.Key },
				Done:    func(_ NoInput, out secreted, _ time.Time) string { return "Key " + out.ID + ".\nShown once." },
			}),
			endOf(),
		}},
	)
	require.NoError(tb, err)

	return tree
}

// failing is a stdout that cannot be written, such as /dev/full.
type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, syscall.ENOSPC }

// ordered records which stream each write went to.
type ordered struct {
	name string
	log  *[]string
}

func (o ordered) Write(p []byte) (int, error) {
	*o.log = append(*o.log, o.name)

	return len(p), nil
}

// TestSecret: the note with the ID goes to stderr first, then the secret
// alone to stdout, past the rule that masks a credential; -o json prints
// the object and no note. A secret that reaches nobody is an error that
// names the command that revokes the credential.
func TestSecret(t *testing.T) {
	t.Parallel()

	revoke := "The new one, ID 7, works, and nobody holds its secret. Revoke it:\n  prog keys delete 7\n"
	find := "If a new one was made, it works, and nobody holds its secret. Find it and revoke it:\n  prog keys list\n"

	for _, tt := range []struct {
		name, line     string
		made           secreted
		err            error
		stdout, stderr string
		code           int
	}{
		{name: "the secret alone", line: "keys create", made: secreted{"7", madeKey}, stdout: madeKey + "\n", stderr: "Key 7.\nShown once.\n"},
		{name: "as JSON", line: "keys create -o json", made: secreted{"7", madeKey}, stdout: "{\n  \"id\": \"7\",\n  \"key\": \"" + madeKey + "\"\n}\n"},
		{name: "no secret", line: "keys create", made: secreted{ID: "7"}, stderr: "Error: the answer has no secret.\n" + revoke, code: 1},
		{name: "no secret, as JSON", line: "keys create -o json", made: secreted{ID: "7"}, stderr: "Error: the answer has no secret.\n" + revoke, code: 1},
		{name: "no secret and no ID", line: "keys create", stderr: "Error: the answer has no secret.\n" + find, code: 1},
		// The program says which errors leave a write unknown
		// (Program.MayBeMade): the test program, a madeError.
		{
			name: "an error that may be a made write", line: "keys create", err: &madeError{"the server at x sent an answer this CLI cannot read: bad"},
			stderr: "Error: the server at x sent an answer this CLI cannot read: bad\n" + find, code: 1,
		},
		{
			name: "an error that may be a made write, as JSON", line: "keys create -o json", err: &madeError{"the server at x did not answer the change: no answer in time."},
			stderr: "Error: the server at x did not answer the change: no answer in time.\n" + find, code: 1,
		},
		//nolint:err113 // a sentence of the test
		{name: "any other error", line: "keys create", err: errors.New("refused."), stderr: "Error: refused.\n", code: 1},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			tree := secretTree(t, func() (secreted, error) { return tt.made, tt.err })
			code := Run(tree, words(tt.line), Env{Stdout: &stdout, Stderr: &stderr})

			if diff := cmp.Diff(tt.stdout, stdout.String()); diff != "" {
				t.Errorf("stdout (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.stderr, stderr.String()); diff != "" {
				t.Errorf("stderr (-want +got):\n%s", diff)
			}

			require.Equal(t, tt.code, code)
		})
	}

	t.Run("the ID before the secret", func(t *testing.T) {
		t.Parallel()

		var log []string

		tree := secretTree(
			t,
			func() (secreted, error) { return secreted{"7", madeKey}, nil },
		)
		require.Equal(
			t,
			0,
			Run(
				tree,
				words("keys create"),
				Env{Stdout: ordered{"stdout", &log}, Stderr: ordered{"stderr", &log}},
			),
		)
		require.Equal(t, []string{"stderr", "stdout"}, log)
	})

	t.Run("a stdout that fails", func(t *testing.T) {
		t.Parallel()

		var stderr bytes.Buffer

		tree := secretTree(
			t,
			func() (secreted, error) { return secreted{"7", madeKey}, nil },
		)
		require.Equal(
			t,
			1,
			Run(tree, words("keys create"), Env{Stdout: failing{}, Stderr: &stderr}),
		)
		require.Equal(
			t,
			"Key 7.\nShown once.\nError: the secret cannot be written: no space left on device.\n"+revoke,
			stderr.String(),
		)
	})
}

// TestSecretClosedPipe: in a process of its own, as main runs it, a Secret
// command whose stdout is a closed pipe says how to revoke what it made and
// exits 1, in text and JSON; any other command still ends at the pipe,
// quietly, by the signal, also after a Secret command ran in the same
// process, written or not.
func TestSecretClosedPipe(t *testing.T) {
	t.Parallel()

	if line := os.Getenv("SECRET_PIPE_LINE"); line != "" {
		tree := secretTree(
			t,
			func() (secreted, error) { return secreted{"7", madeKey}, nil },
		)

		if os.Getenv("SECRET_PIPE_BEFORE") != "" {
			Run(tree, words("keys create"), Env{Stdout: io.Discard, Stderr: io.Discard})
			Run(tree, words("keys create"), Env{Stdout: failing{}, Stderr: io.Discard})
		}

		os.Exit(Run(tree, words(line), Env{Stdout: os.Stdout, Stderr: os.Stderr}))
	}

	revoke := "Error: the secret cannot be written: broken pipe.\nThe new one, ID 7, works, and nobody holds its secret. Revoke it:\n  prog keys delete 7\n"

	for _, tt := range []struct {
		line           string
		closed         bool
		before         bool
		stdout, stderr string
		status         string
	}{
		{line: "keys create", closed: true, stderr: "Key 7.\nShown once.\n" + revoke, status: "exit status 1"},
		{line: "keys create -o json", closed: true, stderr: revoke, status: "exit status 1"},
		{line: "keys create", stdout: madeKey + "\n", stderr: "Key 7.\nShown once.\n"},
		{line: "keys list --help", closed: true, status: "signal: broken pipe"},
		{line: "keys list --help", closed: true, before: true, status: "signal: broken pipe"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			t.Parallel()

			var stdout, stderr bytes.Buffer

			//nolint:gosec // this test's own binary
			cmd := exec.CommandContext(
				t.Context(),
				os.Args[0],
				"-test.run=^TestSecretClosedPipe$",
			)

			cmd.Env = append(os.Environ(), "SECRET_PIPE_LINE="+tt.line)
			if tt.before {
				cmd.Env = append(cmd.Env, "SECRET_PIPE_BEFORE=1")
			}

			cmd.Stdout, cmd.Stderr = &stdout, &stderr

			if tt.closed {
				r, w, err := os.Pipe()
				require.NoError(t, err)
				require.NoError(t, r.Close())

				cmd.Stdout = w

				defer w.Close()
			}

			err := cmd.Run()
			if tt.status == "" {
				require.NoError(t, err, stderr.String())
			} else {
				require.EqualError(t, err, tt.status, stderr.String())
			}

			require.Equal(t, tt.stdout, stdout.String())
			require.Equal(t, tt.stderr, stderr.String())
		})
	}
}

// TestNotRead: a Run whose change is made and whose object cannot be read
// prints Done, and with -o json nothing.
func TestNotRead(t *testing.T) {
	t.Parallel()

	tree, err := testBuild("prog", "A program", New(Spec[testS, NoInput, item]{
		Name:    "gone",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog gone"},
		Local:   true,
		Run:     func(Ctx[testS], NoInput) (item, error) { return item{}, ErrNotRead },
		Done:    func(NoInput, item, time.Time) string { return "Done." },
	}))
	require.NoError(t, err)

	for line, want := range map[string]string{"gone": "Done.\n", "gone -o json": ""} {
		var stdout, stderr bytes.Buffer

		require.Equal(
			t,
			0,
			Run(tree, words(line), Env{Stdout: &stdout, Stderr: &stderr}),
			line,
		)
		require.Equal(t, want, stdout.String(), line)
		require.Empty(t, stderr.String(), line)
	}
}

// TestSecretChecks: the start-up checks that keep a secret out of every
// output but its own, as a second line behind the rule at the edge.
func TestSecretChecks(t *testing.T) {
	t.Parallel()

	note := func(NoInput, secreted, time.Time) string { return "" }
	key := func(secreted) string { return "" }

	type (
		nested struct {
			ID    string `json:"id"`
			Inner struct {
				Secret string `json:"secret"`
			} `json:"inner"`
		}
		pointed struct {
			ID  string  `json:"id"`
			Key *string `json:"key"`
		}
		noID struct {
			Key string `json:"key"`
		}
	)

	beside := func(n Node) []Node {
		return []Node{Group{Name: "keys", Short: "Keys", Commands: []Node{
			n,
			NewList(
				ListSpec[testS, NoInput, item]{
					Name:    "list",
					Short:   "S",
					Long:    "S.",
					Example: []string{"prog keys list"},
					Local:   true,
					Columns: itemColumns,
					NoRows:  "None.",
					Run:     noop[NoInput, []item],
				},
			),
			endOf(),
		}}}
	}

	create := func(s Spec[testS, NoInput, secreted]) Node {
		s.Name, s.Short, s.Long, s.Example, s.Local, s.Run = "create", "S", "S.", []string{
			"prog keys create",
		}, true, noop[NoInput, secreted]

		return New(s)
	}

	for _, tt := range []struct {
		name  string
		nodes []Node
		want  string
	}{
		{"a secret with no Secret", beside(create(Spec[testS, NoInput, secreted]{Done: note})), "keys create: " + errSecret.Error() + "\nkeys delete: " + errEndAlone.Error()},
		{"a Secret with no note", beside(create(Spec[testS, NoInput, secreted]{Secret: key})), "keys create: " + errNoShow.Error() + "\n" + errSecretNote.Error()},
		{
			"a Secret and a sheet",
			beside(create(Spec[testS, NoInput, secreted]{Secret: key, Done: note, Columns: table.Columns[secreted]{{Name: "id", Field: "id", Default: true}}})),
			"keys create: " + errBoth.Error() + "\n" + errSecretNote.Error(),
		},
		{"a Secret with nothing beside it", []Node{create(Spec[testS, NoInput, secreted]{Secret: key, Done: note})}, "create: " + errSecretEnds.Error()},
		{
			"a Secret on a result with no secret",
			[]Node{New(Spec[testS, NoInput, item]{Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, item], Done: func(NoInput, item, time.Time) string { return "" }, Secret: func(item) string { return "" }})},
			"get: " + errSecret.Error() + "\nget: " + errSecretEnds.Error(),
		},
		{
			"a secret a struct down",
			[]Node{New(Spec[testS, NoInput, nested]{Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, nested], Done: func(NoInput, nested, time.Time) string { return "" }})},
			"get: " + errSecret.Error(),
		},
		{
			"a key behind a pointer",
			[]Node{New(Spec[testS, NoInput, pointed]{Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, pointed], Done: func(NoInput, pointed, time.Time) string { return "" }})},
			"get: " + errSecret.Error(),
		},
		{
			"a list of secrets as one result",
			[]Node{New(Spec[testS, NoInput, []secreted]{Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, []secreted], Done: func(NoInput, []secreted, time.Time) string { return "" }})},
			"get: " + errSecret.Error(),
		},
		{
			"a result that is any",
			[]Node{New(Spec[testS, NoInput, any]{Name: "get", Short: "S", Long: "S.", Example: []string{"prog get"}, Local: true, Run: noop[NoInput, any], Done: func(NoInput, any, time.Time) string { return "" }})},
			"get: interface {} " + errOpaque.Error(),
		},
		{
			"a Secret's result with no ID",
			beside(New(Spec[testS, NoInput, noID]{
				Name: "create", Short: "S", Long: "S.", Example: []string{"prog keys create"}, Local: true, Run: noop[NoInput, noID],
				Done: func(NoInput, noID, time.Time) string { return "" }, Secret: func(noID) string { return "" },
			})),
			"keys create: " + errSecretID.Error(),
		},
		{
			"a list of rows that hold a secret",
			[]Node{NewList(ListSpec[testS, NoInput, secreted]{
				Name: "list", Short: "S", Long: "S.", Example: []string{"prog list"}, Local: true, NoRows: "None.", Run: noop[NoInput, []secreted],
				Columns: table.Columns[secreted]{{Name: "id", Field: "id", Default: true}},
			})},
			"list: " + errSecretRow.Error(),
		},
	} {
		_, err := testBuild("prog", "A program", tt.nodes...)
		require.EqualError(t, err, tt.want, tt.name)
	}

	// A pointer to a result is walked, not a panic.
	_, err := testBuild("prog", "A program", New(Spec[testS, NoInput, *item]{
		Name:    "get",
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog get"},
		Local:   true,
		Run:     noop[NoInput, *item],
		Done:    func(NoInput, *item, time.Time) string { return "" },
	}))
	require.NoError(t, err)
}

// TestCreatedNote: the owner ends at a semicolon, a name with no owner at a
// colon, and the last line says what is shown once.
func TestCreatedNote(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct{ name, owner, what, word, want string }{
		{"Auth key 9 (ef34gh)", "tag:build, tag:ci", "ephemeral, expires in 1h", "key", "Auth key 9 (ef34gh) for tag:build, tag:ci; ephemeral, expires in 1h.\nThis is the only time the key is shown."},
		{"API key 3 (vw56xy)", "User 3 (alice)", "expires in 90d", "key", "API key 3 (vw56xy) for User 3 (alice); expires in 90d.\nThis is the only time the key is shown."},
		{"API key 3 (vw56xy)", "", "expires in 90d", "key", "API key 3 (vw56xy): expires in 90d.\nThis is the only time the key is shown."},
		{"OAuth client c9f2", "", "scopes devices:core; tags tag:ci", "secret", "OAuth client c9f2: scopes devices:core; tags tag:ci.\nThis is the only time the secret is shown."},
		{"API key 3 (vw56xy)", "User 3 (alice)", "", "key", "API key 3 (vw56xy) for User 3 (alice).\nThis is the only time the key is shown."},
	} {
		require.Equal(t, tt.want, CreatedNote(tt.name, tt.owner, tt.what, tt.word))
	}
}

// madeError is an error that leaves a write unknown, as the test program
// says (Program.MayBeMade).
type madeError struct{ text string }

func (e *madeError) Error() string { return e.text }

// endOf is a delete of what a Secret command beside it makes.
func endOf() Node {
	return New(Spec[testS, getIn, item]{
		Name:    "delete",
		Aliases: []string{"rm"},
		Short:   "S",
		Long:    "S.",
		Example: []string{"prog keys delete 7"},
		Local:   true,
		Confirm: func(Ctx[testS], getIn) (Prompt, error) { return Prompt{}, nil },
		Run:     noop[getIn, item],
		Done:    func(getIn, item, time.Time) string { return "" },
		End:     true,
	})
}
