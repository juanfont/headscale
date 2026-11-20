package command

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

func TestMasked(t *testing.T) {
	t.Parallel()

	for in, want := range map[string]string{ //nolint:gosec // made-up secrets, to be masked
		"hskey-auth-ab12cd345678-S3cr3t":         "hskey-auth-***",
		"hskey-auth-ab12cd345678-S3c-r3t_x":      "hskey-auth-***",
		"HSKEY-AUTH-AB12CD345678-S3CR3T":         "hskey-auth-***",
		"hskey-auht-ab12cd345678-S3cr3t":         "hskey-***",
		"hskey-S3cr3t":                           "hskey-***",
		"no user matches \"xhskey-api-S3cr3t\".": "no user matches \"xhskey-api-***\".",
		"alice,hskey-authreq-S3cr3t,bob":         "alice,hskey-authreq-***,bob",
		"--hskey-client-S3cr3t":                  "--hskey-client-***",
		"hskey-auth-ab12cd345678-***":            "hskey-auth-***",
		// No more than the kind holds no secret: help texts keep it.
		"hskey-auth-<prefix>-*** names the key": "hskey-auth-<prefix>-*** names the key",
		"hskey-auth-***":                        "hskey-auth-***",
		"hskey-":                                "hskey-",
		"a hskey-auth key":                      "a hskey-auth key",
		"no credential here":                    "no credential here",
	} {
		require.Equal(t, want, masked(in), in)
	}
}

// TestMaskingWrites: a credential cut across writes is masked whole, and a
// rune is never cut in two.
func TestMaskingWrites(t *testing.T) {
	t.Parallel()

	text := "Error: no user matches \"hskey-auth-ab12cd345678-S3cr3t***\" — ünïcode.\nDelete it? [y/N] "

	for cut := range len(text) + 1 {
		var b bytes.Buffer

		m := &masking{w: &b}
		_, err := m.Write([]byte(text[:cut]))
		require.NoError(t, err)

		_, err = m.Write([]byte(text[cut:]))
		require.NoError(t, err)

		require.Equal(t, masked(text), b.String(), "before Flush, cut at %d: a prompt ends in a space and waits for nothing", cut)
		require.NoError(t, m.Flush())
		require.Equal(t, masked(text), b.String())
	}

	var b bytes.Buffer

	m := &masking{w: &b}
	_, _ = m.Write([]byte("ends in hskey-auth-ab12cd345678-S3c"))

	require.Equal(t, "ends in ", b.String(), "a word waits for its end")

	_, _ = m.Write([]byte("r3t"))
	require.NoError(t, m.Flush())
	require.Equal(t, "ends in hskey-auth-***", b.String())
}

// held is a result of a test tree that holds a credential in fields that
// no start-up check knows: one at the top, one a struct down.
type held struct {
	ID    string `json:"id"`
	Note  string `json:"note"`
	Inner struct {
		Hint string `json:"hint"`
	} `json:"inner"`
}

type wordIn struct {
	Word  string `arg:"word"   help:"<word> is any word."`
	Count int    `flag:"count" help:"How many"`
}

// TestCredentialAtTheEdge: a credential, typed or held by a result, comes
// out of no door the CLI writes as more than its kind: not a cell, a sheet
// line, a Done sentence, a note, the text of an error, a problem's object, a
// prompt, or a sentence that quotes a word of the line.
func TestCredentialAtTheEdge(t *testing.T) {
	t.Parallel()

	const secret = "hskey-auth-ab12cd345678-S3cr3t" //nolint:gosec // a made-up secret, to be masked

	h := held{ID: "1", Note: "made with " + secret}
	h.Inner.Hint = "join with " + strings.ToUpper(secret)

	cols := table.Columns[held]{
		{Name: "id", Field: "id", Default: true},
		{Name: "note", Field: "note", Default: true},
		{Name: "hint", Field: "inner.hint", Default: true},
	}

	tree, err := Build("prog", "A program",
		NewList(ListSpec[NoInput, held]{
			Name: "list", Short: "List", Long: "List.", Example: []string{"prog list"}, Local: true, Columns: cols, NoRows: "None.",
			Run: func(Ctx, NoInput) ([]held, error) { return []held{h}, nil },
		}),
		New(Spec[wordIn, held]{
			Name: "get", Short: "Get", Long: "Get.", Example: []string{"prog get x"}, Local: true, Columns: cols,
			Run: func(Ctx, wordIn) (held, error) { return h, nil },
		}),
		New(Spec[wordIn, NoOutput]{
			Name: "done", Short: "Done", Long: "Done.", Example: []string{"prog done x"}, Local: true,
			Run:  func(c Ctx, in wordIn) (NoOutput, error) { c.Note("noted " + in.Word); return NoOutput{}, nil },
			Done: func(in wordIn, _ NoOutput, _ time.Time) string { return "made " + in.Word + " and " + secret },
		}),
		New(Spec[wordIn, NoOutput]{
			Name: "fail", Short: "Fail", Long: "Fail.", Example: []string{"prog fail x"}, Local: true,
			Run: func(_ Ctx, in wordIn) (NoOutput, error) {
				return NoOutput{}, fmt.Errorf("no thing matches %q.", in.Word) //nolint:err113 // a sentence of the test
			},
		}),
		New(Spec[wordIn, NoOutput]{
			Name: "gone", Short: "Gone", Long: "Gone.", Example: []string{"prog gone x"}, Local: true,
			Run: func(_ Ctx, in wordIn) (NoOutput, error) {
				o := clientv0.ProblemObject{Kind: "authRequest", Id: in.Word}
				return NoOutput{}, &ProblemError{Problem: clientv0.Problem{Code: clientv0.ProblemCodeNotFound, Object: nullable.NewNullableWithValue(o)}}
			},
		}),
		New(Spec[wordIn, NoOutput]{
			Name: "delete", Short: "Delete", Long: "Delete.", Example: []string{"prog delete x"}, Local: true, Run: noop[wordIn, NoOutput],
			Confirm: func(_ Ctx, in wordIn) (Prompt, error) {
				return Prompt{Question: "Delete " + in.Word + "?", Action: "delete " + in.Word}, nil
			},
		}),
	)
	require.NoError(t, err)

	for _, typed := range []string{
		secret,
		strings.ToUpper(secret),
		"hskey-auht-ab12cd345678-S3cr3t",
		"hskey-auth-ab12cd345678-S3c-r3t",
		"hskey-authreq-S3cr3t",
		"alice," + secret,
		"x" + secret,
	} {
		for _, line := range []string{
			"list", "get x",
			"done " + typed, "fail " + typed, "gone " + typed, "delete " + typed, "delete " + typed + " --force",
			typed, "get --" + typed, "get x --count " + typed, "list --columns " + typed, "list --filter " + typed, "list --sort " + typed,
		} {
			var stdout, stderr bytes.Buffer

			Run(tree, strings.Fields(line), Env{Stdout: &stdout, Stderr: &stderr, Stdin: strings.NewReader("n\n"), Terminal: true})

			out := strings.ToLower(stdout.String() + stderr.String())
			require.NotContains(t, out, "s3cr3t", line)
			require.NotContains(t, out, "s3c-r3t", line)
		}
	}

	// JSON is the server's data: a credential-shaped word in it comes out
	// as it came, while the table and the sheet mask it.
	for line, want := range map[string]string{
		"list":          "hskey-auth-***",
		"get x":         "hskey-auth-***",
		"list -o json":  `"note": "made with ` + secret + `"`,
		"get x -o json": `"note": "made with ` + secret + `"`,
	} {
		var stdout bytes.Buffer

		require.Equal(t, 0, Run(tree, strings.Fields(line), Env{Stdout: &stdout, Stderr: &stdout}), line)
		require.Contains(t, stdout.String(), want, line)
	}

	var stderr bytes.Buffer

	Run(tree, []string{"gone", "hskey-authreq-S3cr3t"}, Env{Stdout: &stderr, Stderr: &stderr})
	require.Equal(t, "Error: Auth request hskey-authreq-*** no longer exists.\n", stderr.String())
}
