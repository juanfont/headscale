package headscale

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"spike/cmdline"
	"spike/kit"
)

func TestConformance(t *testing.T) {
	out := os.Getenv("CONF_OUT")
	if out == "" {
		out = "RESULT.md"
	}
	kit.Conformance(t, "final-typed", Adapter{}, out)
}

// TestTwin: the typed specs describe the tree that the kit's own specs do,
// command by command, so the kit's cases and the other parsers' adapters
// talk about the same tree. The usage line made from the input struct (D47)
// names the arguments that the kit's hand-written Use names.
func TestTwin(t *testing.T) {
	got, want := Describe(KitTree()), kit.NewTree().Commands
	if len(got) != len(want) {
		t.Fatalf("%d commands, the kit has %d", len(got), len(want))
	}
	for i := range want {
		if fmt.Sprintf("%+v", got[i]) != fmt.Sprintf("%+v", want[i]) { // nil and empty lists are the same here
			t.Errorf("command %v:\n got %+v\nwant %+v", want[i].Path, got[i], want[i])
		}
	}
	if u := KitTree().Root().Commands[4].Commands[3].Commands[0].Usage; u != "headscale nodes routes set <node> <routes>" {
		t.Errorf("usage line: %q", u)
	}
	if u := KitTree().Root().Commands[2].Commands[0].Usage; u != "headscale check config [file]" {
		t.Errorf("usage line: %q", u)
	}
}

// TestInput: Run gets the struct the library filled, typed.
func TestInput(t *testing.T) {
	line, err := KitTree().Parse(kit.Sh("nodes set 12 --name '' -o json"))
	if err != nil {
		t.Fatal(err)
	}
	in, _ := cmdline.Get[nodesSetIn](line)
	name, given := in.Name.Get()
	if _, exp := in.Expiry.Get(); in.Node != "12" || name != "" || !given || exp {
		t.Errorf("nodes set: %+v", in)
	}
	if out, ok := cmdline.Get[outputFlags](line); !ok || out.Output != "json" {
		t.Errorf("--output: %+v %v", out, ok)
	}
	if _, ok := cmdline.Get[forceFlags](line); ok {
		t.Error("nodes set has no --force")
	}
	line, _ = KitTree().Parse(kit.Sh("auth keys create alice --tags tag:a,tag:b --reusable"))
	if in, _ := cmdline.Get[authKeysCreateIn](line); len(in.Tags) != 2 || in.Tags[1] != "tag:b" || !in.Reusable || in.Owner != "alice" {
		t.Errorf("auth keys create: %+v", in)
	}
	line, _ = KitTree().Parse(kit.Sh("nodes list --filter a,b --filter c --columns id,-ip"))
	if l, _ := cmdline.Get[listFlags[nodeRow]](line); len(l.Filter) != 2 || len(l.Filter[0]) != 2 || len(l.Columns) != 2 || l.Columns[1] != "-ip" {
		t.Errorf("nodes list: %+v", l)
	}
}

// TestFormat: --output takes only json (D49). The mistake is the library's
// BadValue at the flag, with the word that was typed and the type's reason.
func TestFormat(t *testing.T) {
	_, err := KitTree().Parse(kit.Sh("nodes list -o a -o b"))
	ue, _ := errors.AsType[*cmdline.UsageError](err)
	if ue == nil || ue.Kind != cmdline.BadValue || ue.Flag != "output" || ue.Word != "-o" || ue.Value != "a" || ue.At != 2 || ue.Err == nil {
		t.Errorf("got %v", err)
	}
	if line, err := KitTree().Parse(kit.Sh("-o json nodes list")); err != nil {
		t.Error(err)
	} else if out, _ := cmdline.Get[outputFlags](line); out.Output != "json" {
		t.Errorf("--output: %q", out.Output)
	}
}

// TestDidYouMean: next to an unknown command the Line holds the group that
// was reached, and the group lists its commands and their aliases: what a
// "did you mean" and the old-names table need, as data.
func TestDidYouMean(t *testing.T) {
	line, err := KitTree().Parse(kit.Sh("-c /x nodes lst --bogus"))
	ue, _ := errors.AsType[*cmdline.UsageError](err)
	if ue == nil || ue.Kind != cmdline.UnknownCommand || ue.Word != "lst" || ue.At != 3 || strings.Join(ue.Path, " ") != "nodes" {
		t.Fatalf("got %v", err)
	}
	var names []string
	for _, c := range line.Command.Commands {
		names = append(append(names, c.Name), c.Aliases...)
	}
	if got := strings.Join(names, " "); got != "list ls delete rm set routes" {
		t.Errorf("the candidates: %s", got)
	}
}
