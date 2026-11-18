package probekong

import (
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/alecthomas/kong"
)

// Missing value and flag-looking value, with and without WithHyphenPrefixedParameters.
func TestMissingValue(t *testing.T) {
	type leaf struct {
		Name  string `name:"name"`
		Force bool   `name:"force"`
		Sort  string `name:"sort"`
	}
	for _, hy := range []bool{false, true} {
		for _, args := range [][]string{
			{"--name"}, {"--name", "--force"}, {"--sort", "-last-seen"}, {"--sort=-last-seen"},
			{"--name", "-"}, {"--name="},
		} {
			var g leaf
			k, _ := kong.New(&g, kong.NoDefaultHelp(), kong.WithHyphenPrefixedParameters(hy))
			ctx, err := k.Parse(args)
			set := []string{}
			if ctx != nil {
				for _, p := range ctx.Path {
					if p.Flag != nil {
						set = append(set, p.Flag.Name)
					}
				}
			}
			t.Logf("hyphen=%v %-28q -> %+v set=%v err=%v", hy, args, g, set, err)
		}
	}
}

// Leaf identity: our own tag key survives into the model.
func TestCustomTag(t *testing.T) {
	k, err := Build(tree())
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := k.Parse([]string{"nodes", "routes", "approve", "1", "2"})
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("selected=%s hsid=%q path=%q", ctx.Selected().Name, ctx.Selected().Tag.Get("hsid"), ctx.Selected().Path())
}

// Approach (b): kong reads the spec's real input struct (001's tags).
type nodeRef struct{ raw string }

type routesSetIn struct {
	Node   nodeRef        `arg:"node"`
	Routes []netip.Prefix `arg:"routes"`
	Expiry time.Time      `flag:"expiry" short:"e" help:"When it ends"`
	Tags   []string       `flag:"tags" help:"Tags"`
	Name   *string        `flag:"display-name" help:"name"`
}

func TestRealStruct(t *testing.T) {
	var in routesSetIn
	_, err := kong.New(&in, kong.NoDefaultHelp())
	t.Logf("no mappers: err=%v", err)

	nodeMapper := kong.MapperFunc(func(ctx *kong.DecodeContext, target reflect.Value) error {
		tok, err := ctx.Scan.PopValue("node")
		if err != nil {
			return err
		}
		target.Set(reflect.ValueOf(nodeRef{raw: tok.String()}))
		return nil
	})
	k, err := kong.New(&in, kong.NoDefaultHelp(), kong.TypeMapper(reflect.TypeFor[nodeRef](), nodeMapper))
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range k.Model.Flags {
		t.Logf("flag name=%q short=%q (from field name, our flag:%q tag ignored)", n.Name, string(n.Short), n.Tag.Get("flag"))
	}
	for _, p := range k.Model.Positional {
		t.Logf("positional name=%q required=%v", p.Name, p.Required)
	}
	for _, args := range [][]string{
		{"n1", "10.0.0.0/8,10.1.0.0/16", "-e", "2027-01-01T00:00:00Z", "--tags", "a,b"},
		{"n1", "10.0.0.0/8", "-e", "90d"},
		{"n1"},
		{"n1", "10.0.0.0/8", "--name", ""},
		{"n1", "10.0.0.0/8", "--display-name", ""},
	} {
		in = routesSetIn{}
		_, err := k.Parse(args)
		nm := "<nil>"
		if in.Name != nil {
			nm = fmt.Sprintf("%q", *in.Name)
		}
		t.Logf("%q -> node=%q routes=%v exp=%v tags=%q name=%s err=%v", args, in.Node.raw, in.Routes, in.Expiry, in.Tags, nm, err)
	}
}

// Hand-built model: graft a leaf node built by one kong.New into another app's tree.
func TestGraft(t *testing.T) {
	type leafIn struct {
		Force bool     `name:"force"`
		Args  []string `arg:"" optional:""`
	}
	type root struct {
		Nodes struct{} `cmd:""`
	}
	var r root
	k, err := kong.New(&r, kong.NoDefaultHelp())
	if err != nil {
		t.Fatal(err)
	}
	var l leafIn
	lk, err := kong.New(&struct {
		Delete *leafIn `cmd:""`
	}{Delete: &l}, kong.NoDefaultHelp())
	if err != nil {
		t.Fatal(err)
	}
	nodes := k.Model.Children[0]
	del := lk.Model.Children[0]
	del.Parent = nodes
	nodes.Children = append(nodes.Children, del)
	ctx, err := k.Parse([]string{"nodes", "delete", "12", "--force"})
	if err != nil {
		t.Fatalf("graft parse: %v", err)
	}
	t.Logf("graft: cmd=%q leaf=%+v", ctx.Command(), l)
}

// DynamicCommand only adds at the root.
func TestDynamic(t *testing.T) {
	type del struct {
		Args []string `arg:"" optional:""`
	}
	var root struct{}
	k, err := kong.New(&root, kong.NoDefaultHelp(), kong.DynamicCommand("nodes", "", "", &struct {
		Delete del `cmd:""`
	}{}))
	if err != nil {
		t.Fatal(err)
	}
	ctx, err := k.Parse([]string{"nodes", "delete", "x"})
	t.Logf("dynamic: %v %v", ctx.Command(), err)
}

// Building the tree twice in one process, and its cost.
func TestBuildTwice(t *testing.T) {
	for range 2 {
		if _, err := Build(tree()); err != nil {
			t.Fatal(err)
		}
	}
}

func BenchmarkBuildAndParse(b *testing.B) {
	big := tree()
	// widen to ~70 leaves like 001's tree
	for i := range 10 {
		big.Children = append(big.Children, &Node{Name: fmt.Sprintf("g%d", i), Children: tree().Children[0].Children})
	}
	for b.Loop() {
		if _, err := Parse(big, []string{"nodes", "routes", "set", "1", "2"}); err != nil {
			b.Fatal(err)
		}
	}
}

// -o=json: kong keeps the '='. An argv rewrite in the adapter fixes it.
func TestShortEquals(t *testing.T) {
	fix := func(args []string) []string {
		out := make([]string, 0, len(args))
		for i, a := range args {
			if a == "--" {
				return append(out, args[i:]...)
			}
			if len(a) > 2 && a[0] == '-' && a[1] != '-' && a[2] == '=' {
				out = append(out, a[:2], a[3:])
				continue
			}
			out = append(out, a)
		}
		return out
	}
	r, err := Parse(tree(), fix([]string{"nodes", "list", "-o=json"}))
	t.Logf("%v %v", r.Flags, err)
	r, err = Parse(tree(), fix([]string{"nodes", "set", "1", "-e="}))
	t.Logf("%v %v", r.Flags, err)
}

// The help flag of kong, kept but with our printer, and an Exit that returns.
func TestKongHelpFlagExitReturns(t *testing.T) {
	var out strings.Builder
	type leaf struct {
		Args []string `arg:""`
	}
	var g struct {
		Nodes struct {
			Delete leaf `cmd:""`
		} `cmd:""`
	}
	exited := -1
	k, _ := kong.New(&g, kong.Writers(&out, &out), kong.Exit(func(c int) { exited = c }),
		kong.Help(func(_ kong.HelpOptions, ctx *kong.Context) error {
			fmt.Fprintf(ctx.Stdout, "OUR HELP for %q\n", ctx.Command())
			return nil
		}))
	_, err := k.Parse([]string{"nodes", "delete", "--help"})
	t.Logf("exit=%d out=%q err=%v", exited, out.String(), err)
	var pe *kong.ParseError
	t.Logf("is ParseError: %v", errors.As(err, &pe))
}
