package kit

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// nullAdapter fails everything. It proves the suite compiles, runs and writes its table.
type nullAdapter struct{}

func (nullAdapter) Run(context.Context, *Tree, []string, Stdio) error { return errors.New("null") }
func (nullAdapter) Complete(context.Context, *Tree, []string) (Completion, error) {
	return Completion{}, errors.New("null")
}
func (nullAdapter) Script(*Tree, string, io.Writer) error { return errors.New("null") }

func TestNullAdapter(t *testing.T) {
	r := Run(nullAdapter{})
	md := filepath.Join(t.TempDir(), "null.md")
	if err := os.WriteFile(md, []byte(r.Markdown("null")), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, row := range r.Rows {
		if row.Class == Must && row.Status != "FAIL" && row.ID != "I01" {
			t.Errorf("%s passed on the null adapter: %s", row.ID, row.Got)
		}
	}
	b, _ := os.ReadFile(md)
	if n := strings.Count(string(b), "\n| "); n != len(r.Rows)+2 { // header and separator
		t.Errorf("table has %d lines, want %d", n, len(r.Rows)+2)
	}
	t.Log(r.Summary())
}

// replay answers each case with its own expected outcome, through Exec. Every
// MUST case passing proves the expectations are outcomes Exec can produce:
// paths exist, flags belong to the command, argument counts fit.
type replay struct{}

func (replay) Run(ctx context.Context, t *Tree, argv []string, std Stdio) error {
	for _, c := range runCases {
		if line(c.argv) != line(argv) {
			continue
		}
		w := c.want
		switch w.Kind {
		case "run":
			return t.Exec(ctx, std, Call{Path: w.Path, Flags: w.Flags, Args: w.Args})
		case "help":
			return t.Exec(ctx, std, Call{Path: w.Path, Flags: map[string][]string{"help": {"true"}}})
		case "version":
			return t.Exec(ctx, std, Call{Flags: map[string][]string{"version": {"true"}}})
		case "":
			return errors.New("observe")
		}
		return &UsageError{ErrKind(w.Kind), w.Path, w.Word}
	}
	return errors.New("no case")
}

func (replay) Complete(_ context.Context, _ *Tree, argv []string) (Completion, error) {
	var comp Completion // v3: several cases may share a line (Q06 and C03): answer them all
	found := false
	for _, c := range compCases {
		if line(c.argv) == line(argv) {
			comp.Words, comp.Files, found = append(comp.Words, c.has...), c.wantFiles, true
		}
	}
	if !found {
		return comp, errors.New("no case")
	}
	return comp, nil
}

func (replay) Script(_ *Tree, _ string, w io.Writer) error {
	_, err := io.WriteString(w, "# headscale\n")
	return err
}

func TestReplayPassesEveryMust(t *testing.T) {
	Conformance(t, "replay", replay{}, filepath.Join(t.TempDir(), "replay.md"))
}

func TestExec(t *testing.T) {
	tree := NewTree()
	ctx, rec := withRecorder(context.Background())
	std := Stdio{Out: io.Discard, Err: io.Discard}

	if err := tree.Exec(ctx, std, Call{Path: []string{"nodes", "set"}, Args: []string{"12"}, Flags: map[string][]string{"name": {""}}}); err != nil {
		t.Fatal(err)
	}
	if in := rec.in.(nodesSetIn); in.Name == nil || *in.Name != "" || in.Expiry != nil {
		t.Errorf("--name '' must give Name=&\"\" and Expiry=nil, got %+v", in)
	}
	if err := tree.Exec(ctx, std, Call{Path: []string{"auth", "keys", "create"}, Args: []string{"a"}, Flags: map[string][]string{"tags": {"x,y"}, "reusable": {"true"}}}); err != nil {
		t.Fatal(err)
	}
	if in := rec.in.(authKeysCreateIn); len(in.Tags) != 2 || !in.Reusable {
		t.Errorf("got %+v", in)
	}

	for _, tc := range []struct {
		call Call
		want ErrKind
	}{
		{Call{Path: []string{"check", "config"}, Flags: map[string][]string{"o": {"json"}}}, UnknownFlag},
		{Call{Path: []string{"nodes", "list"}, Flags: map[string][]string{"output": {"json", "json"}}}, FlagRepeated},
		{Call{Path: []string{"nodes", "rm"}, Args: []string{"1"}, Flags: map[string][]string{"force": {"maybe"}}}, BadValue},
		{Call{Path: []string{"nodes"}, Args: []string{"lst"}}, UnknownCommand},
		{Call{Path: []string{"nodes", "delete"}}, ArgCount},
	} {
		var ue *UsageError
		if err := tree.Exec(ctx, std, tc.call); !errors.As(err, &ue) || ue.Kind != tc.want {
			t.Errorf("%+v: want %s, got %v", tc.call, tc.want, err)
		}
	}
	var ue *UsageError
	if err := tree.Exec(ctx, std, Call{Path: []string{"check", "config"}, Flags: map[string][]string{"o": {"json"}, "h": {"true"}}}); !errors.As(err, &ue) || ue.Kind != UnknownFlag {
		t.Errorf("v3: an unknown flag must win over -h (D19), got %v", err)
	}
	if err := tree.Exec(context.Background(), std, Call{}); err == nil {
		t.Error("Exec must refuse a context that did not come from the caller")
	}
}
