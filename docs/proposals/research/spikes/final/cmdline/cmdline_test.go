package cmdline

import (
	"bytes"
	"fmt"
	"maps"
	"os/exec"
	"slices"
	"strings"
	"testing"
)

// tree is a small tree with the shapes that matter: flags on the root that
// some commands also take, a group two deep, aliases, bools, a value flag
// with a completer, a repeatable flag, a file flag, a non-ASCII short,
// positionals with and without a completer, help texts.
func tree() *Command {
	out := Flag{Name: "output", Short: 'o', Help: "Output format", Complete: Words("json", "yaml")}
	cfg := Flag{Name: "config", Short: 'c', Help: "Config file", Complete: Files}
	help := Flag{Name: "help", Short: 'h', Bool: true, Help: "Show help"}
	return &Command{Name: "prog", Flags: []Flag{help, out, cfg}, Commands: []*Command{
		{Name: "nodes", Help: "Manage nodes", Flags: []Flag{help}, Commands: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Help: "List nodes", Flags: []Flag{help, out, cfg,
				{Name: "sort", Complete: Words("id", "name")},
				{Name: "filter", Repeat: true, Complete: Words("id", "name")},
				{Name: "name", Complete: seen}}},
			{Name: "delete", Aliases: []string{"rm"}, Help: "Delete a node", Flags: []Flag{help, out,
				{Name: "force", Bool: true, Help: "Do not ask"}, {Name: "oe", Short: 'ø', Bool: true}},
				Args: []Completer{Words("12", "13")}},
			{Name: "routes", Help: "Manage routes", Flags: []Flag{help}, Commands: []*Command{
				{Name: "set", Aliases: []string{"approve"}, Help: "Set routes", Flags: []Flag{help, out}, Args: []Completer{nil, seen}},
			}},
		}},
		{Name: "policy", Flags: []Flag{help}, Commands: []*Command{
			{Name: "check", Flags: []Flag{help, cfg}, Args: []Completer{Files}},
		}},
	}}
}

// seen echoes the line it was given, so a test can see what a Completer gets.
func seen(m *Match, prefix string) ([]string, Directive) {
	var fl []string
	for _, g := range m.Flags {
		fl = append(fl, g.Name+":"+g.Value)
	}
	return []string{fmt.Sprintf("path=%s;flags=%v;args=%q;prefix=%q", strings.Join(m.Path, "/"), fl, m.Args, prefix)}, NoFiles | NoSpace
}

func show(m *Match, err error) string {
	if err != nil {
		e := err.(*Error)
		return fmt.Sprintf("ERR %d [%s] %q @%d", e.Kind, strings.Join(e.Path, " "), e.Word, e.At)
	}
	byName := map[string][]string{}
	for _, g := range m.Flags {
		byName[g.Name] = append(byName[g.Name], g.Value)
	}
	var kv []string
	for _, k := range slices.Sorted(maps.Keys(byName)) {
		kv = append(kv, fmt.Sprintf("%s=%q", k, byName[k]))
	}
	return fmt.Sprintf("[%s] {%s} %q", strings.Join(m.Path, " "), strings.Join(kv, " "), m.Args)
}

// TestParse: rows for the rules of rules.md groups L, V, B, R, W, C, M and X. argv is split
// on "|" so "" survives; "<nil>" is no argv at all.
func TestParse(t *testing.T) {
	for _, tc := range []struct{ id, argv, want string }{
		// lexing one word
		{"P01", "<nil>", `[] {} []`},
		{"P02", "nodes|delete|-", `[nodes delete] {} ["-"]`},
		{"P03", "nodes|delete|", `[nodes delete] {} [""]`},
		{"P04", "-", `ERR 1 [] "-" @0`},
		{"P05", "", `ERR 1 [] "" @0`},
		{"P06", "nodes|delete|-5", `ERR 2 [nodes delete] "-5" @2`},
		{"P07", "--|nodes", `ERR 1 [] "--" @0`},
		{"P08", "nodes|--|list", `ERR 1 [nodes] "--" @1`},
		{"P09", "nodes|delete|--|--force|-h|--|-", `[nodes delete] {} ["--force" "-h" "--" "-"]`},
		{"P10", "nodes|delete|12|--", `[nodes delete] {} ["12"]`},
		{"P11", "nodes|delete|\xff\xfe|a\x00b", "[nodes delete] {} [\"\\xff\\xfe\" \"a\\x00b\"]"},
		{"P12", "nodes|delete|-\xff", `ERR 2 [nodes delete] "-\xff" @2`},
		{"P13", "nodes|delete|-ø", `[nodes delete] {oe=["true"]} []`},
		{"P14", "nodes|delete|-\xc3", `ERR 2 [nodes delete] "-\xc3" @2`},
		{"P15", "NODES", `ERR 1 [] "NODES" @0`},
		{"P16", "nodes|list|---sort|x", `ERR 2 [nodes list] "---sort" @2`},
		{"P17", "nodes|list|--=x", `ERR 2 [nodes list] "--" @2`},
		{"P18", "nodes|list|-=x", `ERR 2 [nodes list] "-" @2`},
		{"P19", "nodes|list|-ojson", `ERR 2 [nodes list] "-ojson" @2`},
		{"P20", "nodes|list|-ho|json", `ERR 2 [nodes list] "-ho" @2`},
		{"P21", "nodes|list|-output|json", `ERR 2 [nodes list] "-output" @2`},
		{"P22", "nodes|list|--o|json", `ERR 2 [nodes list] "--o" @2`},
		{"P23", "nodes|list|--sor", `ERR 2 [nodes list] "--sor" @2`},
		{"P24", "nodes|list|--Sort=x", `ERR 2 [nodes list] "--Sort" @2`},
		// values
		{"P25", "nodes|list|--sort=a=b|--name=", `[nodes list] {name=[""] sort=["a=b"]} []`},
		{"P26", "nodes|list|-o=", `[nodes list] {output=[""]} []`},
		{"P27", "nodes|list|--sort|-name", `[nodes list] {sort=["-name"]} []`},
		{"P28", "nodes|list|--sort|--output|x", `[nodes list] {sort=["--output"]} ["x"]`},
		{"P29", "nodes|list|--name|--", `[nodes list] {name=["--"]} []`},
		{"P30", "nodes|list|--name||-h", `[nodes list] {help=["true"] name=[""]} []`},
		{"P31", "-c|nodes|nodes|list", `[nodes list] {config=["nodes"]} []`},
		{"P32", "nodes|list|--sort", `ERR 3 [nodes list] "--sort" @2`},
		{"P33", "-o", `ERR 3 [] "-o" @0`},
		{"P34", "nodes|-c", `ERR 3 [nodes] "-c" @1`},
		{"P35", "nodes|delete|--force|maybe", `[nodes delete] {force=["true"]} ["maybe"]`},
		{"P36", "nodes|delete|12|--force=maybe|--force=", `[nodes delete] {force=["maybe" ""]} ["12"]`},
		{"P37", "nodes|list|-o|json", `[nodes list] {output=["json"]} []`},
		// repeats
		{"P38", "nodes|list|-o=json|--output|yaml", `[nodes list] {output=["json" "yaml"]} []`},
		{"P39", "-o|a|nodes|-o|b|list|-o|c", `[nodes list] {output=["a" "b" "c"]} []`},
		{"P40", "nodes|delete|12|--force=false|--force", `[nodes delete] {force=["false" "true"]} ["12"]`},
		// where flags may stand
		{"P41", "nodes|-o|json|list", `[nodes list] {output=["json"]} []`},
		{"P42", "-o|json|policy|check", `ERR 2 [policy check] "-o" @0`},
		{"P43", "policy|check|-o|json", `ERR 2 [policy check] "-o" @2`},
		{"P44", "nodes|--force|delete|12", `ERR 2 [nodes] "--force" @1`},
		{"P45", "nodes|delete|--force|12|-o|x|13", `[nodes delete] {force=["true"] output=["x"]} ["12" "13"]`},
		{"P46", "-o|x|policy|check|--bogus", `ERR 2 [policy check] "-o" @0`},
		{"P47", "--bogus|nodes|list", `ERR 2 [] "--bogus" @0`},
		// the walk
		{"P48", "nodes|ls", `[nodes list] {} []`},
		{"P49", "nodes|routes|approve|1|2", `[nodes routes set] {} ["1" "2"]`},
		{"P50", "node|ls", `ERR 1 [] "node" @0`},
		{"P51", "nodes|help", `ERR 1 [nodes] "help" @1`},
		{"P52", "nodes|lis", `ERR 1 [nodes] "lis" @1`},
		{"P53", "nodes", `[nodes] {} []`},
		{"P54", "-h|nodes|-o|json", `[nodes] {help=["true"] output=["json"]} []`},
		{"P55", "nodes|delete|list|routes", `[nodes delete] {} ["list" "routes"]`},
		{"P56", "nodes|delete|12|13|14", `[nodes delete] {} ["12" "13" "14"]`},
		{"P57", "prog|nodes", `ERR 1 [] "prog" @0`},
		{"P58", "nodes|list|--bogus|-h", `ERR 2 [nodes list] "--bogus" @2`},
		{"P59", "nodes|list|-h|--bogus", `ERR 2 [nodes list] "--bogus" @3`},
	} {
		argv := strings.Split(tc.argv, "|")
		if tc.argv == "<nil>" {
			argv = nil
		}
		orig := slices.Clone(argv)
		if got := show(Parse(tree(), argv)); got != tc.want {
			t.Errorf("%s %q:\n got %s\nwant %s", tc.id, tc.argv, got, tc.want)
		}
		if !slices.Equal(argv, orig) {
			t.Errorf("%s: Parse changed argv", tc.id)
		}
	}
}

func TestErrorText(t *testing.T) {
	for _, tc := range []struct {
		e    Error
		want string
	}{
		{Error{UnknownCommand, nil, "x", 0}, `unknown command "x"`},
		{Error{UnknownCommand, []string{"nodes"}, "x", 0}, `unknown command "x" for "nodes"`},
		{Error{UnknownFlag, []string{"nodes", "list"}, "--x", 0}, `unknown flag --x for "nodes list"`},
		{Error{MissingValue, []string{"nodes"}, "-o", 0}, `flag -o needs a value`},
	} {
		if got := tc.e.Error(); got != tc.want {
			t.Errorf("got %q, want %q", got, tc.want)
		}
	}
}

// TestComplete: rows for the rules of rules.md group T. The line is split on
// spaces; the last word is under the cursor (a trailing space starts a new
// one). want is the __complete answer with lines joined by " | ".
func TestComplete(t *testing.T) {
	for _, tc := range []struct{ id, line, want string }{
		{"T01", "", "nodes\tManage nodes | policy | :4"},
		{"T02", "no", "nodes\tManage nodes | :4"},
		{"T03", "nodes ", "list\tList nodes | delete\tDelete a node | routes\tManage routes | :4"},
		{"T04", "nodes r", "routes\tManage routes | :4"}, // rm fits too, but a name fits
		{"T05", "nodes routes ap", "approve\tSet routes | :4"},
		{"T06", "nodes rm", "rm\tDelete a node | :4"},
		{"T07", "-o json nodes l", "list\tList nodes | :4"},
		{"T08", "-o ", "json | yaml | :4"},
		{"T09", "nodes list --", "--help\tShow help | --output\tOutput format | --config\tConfig file | --sort | --filter | --name | :4"},
		{"T10", "nodes list -", "--help\tShow help | --output\tOutput format | --config\tConfig file | --sort | --filter | --name | :4"},
		{"T11", "nodes list -o", "-o\tOutput format | :4"},
		{"T12", "nodes list -s", ":4"},
		{"T13", "nodes list -o ", "json | yaml | :4"},
		{"T14", "nodes list --output=j", "json | :4"},
		{"T15", "nodes list --force=", ":4"},
		{"T16", "nodes delete --force=", ":4"},
		{"T17", "nodes list --bogus=x", ":4"},
		{"T18", "nodes list --sort i", "id | :4"},
		{"T19", "nodes list --sort -o ", ":4"}, // -o is the value of --sort (D20); the cursor word is a positional
		{"T20", "nodes list --sort -", ":4"},   // the cursor word is --sort's value: no flag names
		{"T21", "nodes list --sort ", "id | name | :4"},
		{"T22", "nodes delete ", "12 | 13 | :4"},
		{"T23", "nodes delete 12 ", ":4"},
		{"T24", "nodes delete o ", ":4"}, // "o" is the positional, not -o: no json
		{"T25", "nodes delete --force ", "12 | 13 | :4"},
		{"T26", "nodes delete 12 -- --", ":4"},
		{"T27", "nodes delete -- ", "12 | 13 | :4"},
		{"T28", "nodes delete -- --output=", ":4"},
		{"T29", "nodes list --name -- --", "--help\tShow help | --output\tOutput format | --config\tConfig file | --sort | --filter | :4"}, // that "--" is --name's value
		{"T30", "policy check ", ":0"},
		{"T31", "policy check x ", ":4"},
		{"T32", "-c ", ":0"},
		{"T33", "nodes list --config=", ":0"},
		{"T34", "nodez ", "nodes\tManage nodes | policy | :4"},
		{"T35", "-1 no", "nodes\tManage nodes | :4"},
		{"T36", "nodes list --bogus --s", "--sort | :4"},
		{"T37", "nodes list --bogus ", ":4"},
		{"T38", "nodes lst ", "list\tList nodes | delete\tDelete a node | routes\tManage routes | :4"},
		{"T39", "-- nodes ", "list\tList nodes | delete\tDelete a node | routes\tManage routes | :4"},
		{"T40", "nodes list --sort id --", "--help\tShow help | --output\tOutput format | --config\tConfig file | --filter | --name | :4"},
		{"T41", "-o json nodes list --", "--help\tShow help | --config\tConfig file | --sort | --filter | --name | :4"},
		{"T42", "nodes list --filter x --f", "--filter | :4"},
		{"T43", "nodes list -h --", "--output\tOutput format | --config\tConfig file | --sort | --filter | --name | :4"},
		{"T44", "-h no", "nodes\tManage nodes | :4"},
		{"T45", "nodes --", "--help\tShow help | :4"},
		{"T46", "--", "--help\tShow help | --output\tOutput format | --config\tConfig file | :4"},
		{"T47", "-c /x nodes list --name ", "path=nodes/list;flags=[config:/x];args=[];prefix=\"\" | :6"},
		{"T48", "nodes routes set 1 ", "path=nodes/routes/set;flags=[];args=[\"1\"];prefix=\"\" | :6"},
		{"T49", "nodes routes set ", ":4"},
		{"T50", "nodes routes set 1 2 ", ":4"},
		{"T51", "nodes list --name=-x", "path=nodes/list;flags=[];args=[];prefix=\"-x\" | :6"},
		{"T52", "N", ":4"},
		{"T53", "nodes delete -", "--help\tShow help | --output\tOutput format | --force\tDo not ask | --oe | :4"},
		{"T54", "nodes delete -ø", "-ø | :4"},
		{"T55", "nodes list -c x -o ", "json | yaml | :4"},
		{"T56", "nodes list -o= --output=", ":4"},                    // --output given once already (D15)
		{"T57", "nodes list -o json -o ", ":4"},                      // the same for the next-word form
		{"T58", "nodes list --filter a --filter ", "id | name | :4"}, // --filter may repeat
	} {
		words := strings.Split(tc.line, " ")
		var b bytes.Buffer
		if !Serve(&b, tree(), append([]string{"__complete"}, words...)) {
			t.Fatal("Serve refused __complete")
		}
		if got := strings.Join(strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n"), " | "); got != tc.want {
			t.Errorf("%s %q:\n got %q\nwant %q", tc.id, tc.line, got, tc.want)
		}
	}
}

// TestServe holds the protocol rules (rules.md group S).
func TestServe(t *testing.T) {
	var b bytes.Buffer
	if Serve(&b, tree(), []string{"nodes"}) || Serve(&b, tree(), nil) || Serve(&b, tree(), []string{"x", "__complete"}) || b.Len() != 0 {
		t.Error("S01: Serve answered a line that is no completion request")
	}
	b.Reset()
	Serve(&b, tree(), []string{"__complete"})
	if b.String() != "nodes\tManage nodes\npolicy\n:4\n" {
		t.Errorf("S02: no words: %q", b.String())
	}
	b.Reset()
	Serve(&b, tree(), []string{"__completeNoDesc", "nodes", ""})
	if b.String() != "list\ndelete\nroutes\n:4\n" {
		t.Errorf("S03: __completeNoDesc: %q", b.String())
	}
	b.Reset()
	Serve(&b, tree(), []string{"__complete", "nodes", "list", "--name", "a\tb"})
	if !strings.Contains(b.String(), `prefix="a\tb"`) {
		t.Errorf("S04: the cursor word reaches the Completer as typed: %q", b.String())
	}
}

// TestPure: Parse and Complete leave the tree as they found it (S05).
func TestPure(t *testing.T) {
	r := tree()
	before := fmt.Sprintf("%+v", *r.Commands[0].Commands[0])
	Parse(r, strings.Split("-o|a|nodes|-o|b|list|-o|c", "|"))
	Complete(r, strings.Split("-o a nodes -o b list", " "), "-")
	if after := fmt.Sprintf("%+v", *r.Commands[0].Commands[0]); after != before {
		t.Errorf("tree changed:\n%s\n%s", before, after)
	}
	if len(r.Flags) != 3 || cap(r.Flags) != 3 {
		t.Error("root flags grew")
	}
}

// TestStdlibOnly: the core imports nothing outside Go's standard library (D25).
func TestStdlibOnly(t *testing.T) {
	out, err := exec.Command("go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").Output()
	if err != nil {
		t.Fatal("go list must run for this guard (D25):", err)
	}
	if deps := strings.Fields(string(out)); !slices.Equal(deps, []string{"spike/cmdline"}) {
		t.Errorf("non-standard imports: %v", deps)
	}
}

// FuzzParse: no panic; every positional is a word of argv, in order; the
// Match survives a round trip through its canonical line; Complete never
// panics on the same words.
func FuzzParse(f *testing.F) {
	f.Add("nodes|delete|12|--force|--|-x")
	f.Add("-o|json|nodes|list|--sort=-id")
	f.Add("nodes|list|--sort|--|--name=")
	f.Fuzz(func(t *testing.T, line string) {
		argv := strings.Split(line, "|")
		Complete(tree(), argv, "")
		Complete(tree(), argv[:len(argv)-1], argv[len(argv)-1])
		m, err := Parse(tree(), argv)
		for i, g := range m.Flags { // in the order typed, each at a flag word before any error
			if g.At < 0 || g.At >= len(argv) || !strings.HasPrefix(argv[g.At], "-") || i > 0 && g.At <= m.Flags[i-1].At {
				t.Fatalf("%q: flag %+v out of place", argv, g)
			}
		}
		if err != nil {
			e, ok := err.(*Error)
			if !ok || e.At < 0 || e.At >= len(argv) || len(m.Flags) > 0 && m.Flags[len(m.Flags)-1].At >= e.At {
				t.Fatalf("%q: error %v at %d after flags %+v", argv, err, e.At, m.Flags)
			}
			return
		}
		i := 0
		for _, a := range m.Args {
			for i < len(argv) && argv[i] != a {
				i++
			}
			if i == len(argv) {
				t.Fatalf("%q: positional %q is not in argv in order", argv, a)
			}
			i++
		}
		canon := slices.Clone(m.Path)
		for _, g := range m.Flags {
			canon = append(canon, "--"+g.Name+"="+g.Value)
		}
		if len(m.Command.Commands) == 0 {
			canon = append(append(canon, "--"), m.Args...)
		}
		if m2, err := Parse(tree(), canon); err != nil || show(m2, nil) != show(m, nil) {
			t.Fatalf("%q: round trip through %q: %s / %v", argv, canon, show(m, nil), err)
		}
	})
}

// TestContract pins what the library does with a tree that breaks the
// caller's contract (rules.md W8, C2, C6) and with a failing writer (S5).
func TestContract(t *testing.T) {
	odd := &Command{Name: "prog", Flags: []Flag{{Name: "x", Short: 'x'}}, Commands: []*Command{
		{Name: "a", Flags: []Flag{{Name: "x", Short: 'x', Bool: true}}},               // W8: -x is a value flag above, a bool here
		{Name: "a", Flags: []Flag{{Name: "y"}}},                                       // C2: the same name twice
		{Name: "g", Args: []Completer{Words("1")}, Commands: []*Command{{Name: "b"}}}, // C6: a group with Args
	}}
	for _, tc := range []struct{ id, argv, want string }{
		{"W8", "-x|v|a", `[a] {x=["true"]} []`},
		{"C2", "a|--y", `ERR 2 [a] "--y" @1`},
		{"C6", "g|1", `ERR 1 [g] "1" @1`},
	} {
		if got := show(Parse(odd, strings.Split(tc.argv, "|"))); got != tc.want {
			t.Errorf("%s: got %s, want %s", tc.id, got, tc.want)
		}
	}
	if w, _ := Complete(odd, []string{"g"}, ""); !slices.Equal(w, []string{"b"}) {
		t.Errorf("C6: Tab at a group with Args: %q", w)
	}
	if !Serve(failing{}, tree(), []string{"__complete", ""}) {
		t.Error("S5: Serve must answer even when the writer fails")
	}
	nl := &Command{Name: "prog", Args: []Completer{Words("a\nb")}}
	var b bytes.Buffer
	if Serve(&b, nl, []string{"__complete", ""}); b.String() != "a\nb\n:4\n" {
		t.Errorf("S6: a newline in a candidate is written as is: %q", b.String())
	}
}

type failing struct{}

func (failing) Write([]byte) (int, error) { return 0, fmt.Errorf("closed") }

// TestOrder: flags come in the order typed with the index of their word,
// positionals with theirs, and next to an error Parse returns what it read
// before the word it refused (rules.md M2, M3, M5; D35).
func TestOrder(t *testing.T) {
	for _, tc := range []struct{ id, argv, want string }{
		{"O1", "-o|a|nodes|-c|x|list|--sort|s|7", `[{output a 0} {config x 3} {sort s 6}] [7]@[8] <nil>`},
		{"O2", "nodes|delete|12|--force|--|x", `[{force true 3}] [12 x]@[2 5] <nil>`},
		{"O3", "-o|a|nodes|-o|b|lst", `[{output a 0} {output b 3}] []@[] unknown command "lst" for "nodes"@5`},
		{"O4", "nodes|list|-o|a|-o|b|--sort", `[{output a 2} {output b 4}] []@[] flag --sort needs a value@6`},
		{"O5", "-c|a|-o|j|-c|b|policy|check", `[{config a 0}] []@[] unknown flag -o for "policy check"@2`},
		{"O6", "nodes|delete|-o=x|12|--bogus|13", `[{output x 2}] [12]@[3] unknown flag --bogus for "nodes delete"@4`},
	} {
		m, err := Parse(tree(), strings.Split(tc.argv, "|"))
		got := fmt.Sprintf("%v %v@%v %v", m.Flags, m.Args, m.ArgAt, err)
		if e, ok := err.(*Error); ok {
			got += fmt.Sprintf("@%d", e.At)
		}
		if got != tc.want {
			t.Errorf("%s %q:\n got %s\nwant %s", tc.id, tc.argv, got, tc.want)
		}
	}
	if m, _ := Parse(tree(), strings.Split("-o|a|nodes|list|--output=b", "|")); !slices.Equal(m.Values("output"), []string{"a", "b"}) || m.Values("sort") != nil {
		t.Errorf("Values: %v", m.Values("output"))
	}
}

// TestCheck: Check refuses what Parse would read ambiguously (rules.md K1–K8).
// A want of "" is a tree Check accepts: "__completeNoDesc" below the root is
// a word Serve never sees.
func TestCheck(t *testing.T) {
	ok := func() *Command {
		h := Flag{Name: "help", Short: 'h', Bool: true}
		return &Command{Name: "prog", Flags: []Flag{h, {Name: "output", Short: 'o'}}, Commands: []*Command{
			{Name: "nodes", Flags: []Flag{h}, Commands: []*Command{
				{Name: "list", Aliases: []string{"ls"}, Flags: []Flag{h, {Name: "output", Short: 'o'}}, Args: []Completer{nil}},
			}},
		}}
	}
	if err := Check(ok()); err != nil {
		t.Fatalf("K0: a good tree: %v", err)
	}
	for _, tc := range []struct {
		id   string
		edit func(r *Command)
		want string
	}{
		{"K1", func(r *Command) {
			r.Commands = append(r.Commands, &Command{Name: "ls"}, &Command{Name: "x", Aliases: []string{"ls"}})
		}, `"ls" names two commands`},
		{"K1", func(r *Command) { r.Commands[0].Commands[0].Aliases = []string{"list"} }, `"list" names two commands`},
		{"K2", func(r *Command) { r.Commands[0].Args = []Completer{nil} }, "a group takes no positionals"},
		{"K3", func(r *Command) { r.Commands[0].Name = "-n" }, "cannot be typed as a command word"},
		{"K3", func(r *Command) { r.Commands[0].Commands[0].Aliases = []string{""} }, "cannot be typed as a command word"},
		{"K4", func(r *Command) { r.Flags = append(r.Flags, Flag{Name: "a=b"}) }, "cannot be typed"},
		{"K4", func(r *Command) { r.Flags = append(r.Flags, Flag{Name: "--x"}) }, "cannot be typed"},
		{"K4", func(r *Command) { r.Flags = append(r.Flags, Flag{Name: "x", Short: 'ø'}) }, "not one printable ASCII"},
		{"K4", func(r *Command) { r.Flags = append(r.Flags, Flag{Name: "x", Short: '='}) }, "not one printable ASCII"},
		{"K5", func(r *Command) { r.Flags = append(r.Flags, Flag{Name: "help", Bool: true}) }, "declared twice"},
		{"K6", func(r *Command) { r.Commands[0].Commands[0].Flags[1].Short = 'p' }, "one spelling, two flags"},
		{"K6", func(r *Command) { r.Commands[0].Commands[0].Flags[1].Bool = true }, "one spelling, two flags"},
		{"K6", func(r *Command) { r.Commands[0].Flags = append(r.Commands[0].Flags, Flag{Name: "other", Short: 'o'}) }, "one spelling, two flags"},
		{"K7", func(r *Command) { r.Commands = append(r.Commands, &Command{Name: "__complete"}) }, "Serve's entry point"},
		{"K7", func(r *Command) { r.Commands[0].Commands[0].Aliases = []string{"__completeNoDesc"} }, ""},
		{"K8", func(r *Command) { r.Commands[0].Help = "Manage\nnodes" }, "line break"},
		{"K8", func(r *Command) { r.Flags[1].Help = "Output\r" }, "line break"},
	} {
		r := ok()
		tc.edit(r)
		if err := Check(r); tc.want == "" && err != nil || tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)) {
			t.Errorf("%s: got %v, want %q", tc.id, err, tc.want)
		}
	}
	if Check(tree()) == nil {
		t.Error("K4: the test tree's -ø is no ASCII short")
	}
}
