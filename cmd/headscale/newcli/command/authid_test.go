package command

import (
	"bytes"
	"cmp"
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

type wholeIn struct {
	ID   AuthID      `arg:"id"`
	Key  Opt[AuthID] `flag:"key"  help:"Key"`
	More []AuthID    `flag:"more" help:"More"`
}

// numberID is a credential typed whole that is no text.
type numberID int

// TestWholeCredential: a field that takes a credential whole refuses a word
// of another kind with the rule's sentence, and any other word that is not
// of its form with its own, before Run, quoting neither; a word of its form
// is taken as it is typed. Commands lists the field.
func TestWholeCredential(t *testing.T) {
	t.Parallel()

	const id = "hskey-authreq-s3cr3ts3cr3t"

	notID := "Error: <id> " + errNotAuthID.Error() + ".\n"

	for _, tt := range []struct {
		args   []string
		stderr string
		// got is the ID Run gets; "" is args[0].
		got string
	}{
		{args: []string{id}},
		{args: []string{id + "x", "--key", id, "--more", id + "a," + id + "b"}},
		{args: []string{"hskey-authreq-"}, stderr: notID},
		{args: []string{"12"}, stderr: notID},
		{args: []string{""}, stderr: notID},
		{args: []string{strings.ToUpper(id)}, stderr: notID},
		// The URL the node shows is pasted whole: the ID is taken from it.
		{args: []string{"https://hs.example.com/register/" + id}, got: id},
		{args: []string{"hs.example.com/a/b/" + id}, got: id},
		{args: []string{"https://hs.example.com/register/" + id + "?x=1"}, stderr: notID},
		{args: []string{id, "--key", "s3cr3t"}, stderr: "Error: --key " + errNotAuthID.Error() + ".\n"},
		{args: []string{id, "--more", id + ",s3cr3t"}, stderr: "Error: --more " + errNotAuthID.Error() + ".\n"},
		{args: []string{"hskey-api-ab12cd345678-s3cr3t"}, stderr: "Error: <id> takes only a credential hskey-authreq-: hskey-api-*** is not sent.\n"},
		// What the edge could not mask whole, if it came back.
		{args: []string{"hskey-authreq-hskey-api-ab12cd345678-s3cr3t"}, stderr: notID},
		{args: []string{"hskey-authreq-s3cr3t-HSKEY-auth-x"}, stderr: notID},
		{args: []string{id + ".def"}, stderr: notID},
		{args: []string{id + ")"}, stderr: notID},
		{args: []string{id + "/"}, stderr: notID},
		{args: []string{id + "?x=1"}, stderr: notID},
		{args: []string{id + "#f"}, stderr: notID},
		{args: []string{id + " x"}, stderr: notID},
		{args: []string{id + "\nx"}, stderr: notID},
		{args: []string{id + "é"}, stderr: notID},
		{args: []string{"hskey-authreq-***"}, stderr: notID},
		{args: []string{"hskey-authreq-" + strings.Repeat("s3cr3t", 15)}, stderr: notID},
		{args: []string{"hskey-authreq-" + strings.Repeat("a", maxAuthID-len(authIDPrefix))}},
		{args: []string{"hskey-authreq-" + strings.Repeat("a", 10000)}, stderr: notID},
	} {
		var got AuthID

		tree, err := Build("prog", "A program", New(Spec[wholeIn, NoOutput]{
			Name:    "run",
			Short:   "Run",
			Long:    "Run.",
			Example: []string{"prog run x"},
			Local:   true,
			Run:     func(_ Ctx, in wholeIn) (NoOutput, error) { got = in.ID; return NoOutput{}, nil },
		}))
		require.NoError(t, err)

		var stderr bytes.Buffer

		code := Run(
			tree,
			append([]string{"run"}, tt.args...),
			Env{Stdout: io.Discard, Stderr: &stderr},
		)
		require.Equal(t, tt.stderr, stderr.String(), tt.args)
		require.Equal(
			t,
			map[bool]int{true: 0, false: 1}[tt.stderr == ""],
			code,
			tt.args,
		)
		require.NotContains(t, stderr.String(), "s3cr3t", tt.args)

		if tt.stderr == "" {
			require.Equal(t, AuthID(cmp.Or(tt.got, tt.args[0])), got)
			require.NotContains(t, stderr.String(), "example", tt.args)
		}

		require.Equal(
			t,
			[]Command{
				{
					Path:    "run",
					Example: []string{"prog run x"},
					Whole:   []string{"<id>", "--key", "--more"},
				},
			},
			tree.Commands(),
		)
	}

	t.Run("a credential typed whole is text", func(t *testing.T) {
		t.Parallel()

		type in struct {
			N numberID `arg:"n"`
		}

		_, err := Build("prog", "A program", New(Spec[in, NoOutput]{
			Name:    "run",
			Short:   "Run",
			Long:    "Run.",
			Example: []string{"prog run x"},
			Local:   true,
			Run:     noop[in, NoOutput],
		}))
		require.ErrorContains(t, err, "<n> "+errWholeKind.Error())
	})
}

// FuzzWhole holds the input rule of a secret typed whole to the edge: a
// word the rule takes is masked whole wherever it stands, so the CLI can
// promise never to print it.
func FuzzWhole(f *testing.F) {
	for _, s := range []string{"hskey-authreq-0123", "hskey-authreq-a.b", "hskey-authreq-hskey-api-x", "hskey-authreq-***", "hskey-authreq-a_b-C", "hskey-authreq-é"} {
		f.Add(s, "x ", ".")
	}

	f.Fuzz(func(t *testing.T, word, before, after string) {
		if AuthID("").Whole(word) != nil {
			return
		}

		require.Equal(t, authIDPrefix+"***", masked(word))

		// A text around it that does not run into it: what a sentence or a
		// cell of JSON has.
		if before != "" && credentialRune(rune(before[len(before)-1])) ||
			after != "" && (credentialRune(rune(after[0])) || after[0] == '*') {
			return
		}

		require.NotContains(t, masked(before+word+after), word)
	})
}

func (numberID) Credential() string { return "authreq" }
func (numberID) Whole(string) error { return nil }
