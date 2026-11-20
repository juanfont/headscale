package cmdline

import (
	"bytes"
	"fmt"
	"maps"
	"slices"
	"strings"
	"testing"
)

// tree is a small tree with the shapes that matter: a flag on the root
// that some commands also take, a group two deep, aliases, a bool, a value
// flag with a completer, positionals with and without one.
func tree() *Command {
	out := Flag{Name: "output", Short: 'o', Complete: Words("json", "yaml")}
	help := Flag{Name: "help", Short: 'h', Bool: true}
	return &Command{Name: "prog", Flags: []Flag{help, out}, Commands: []*Command{
		{Name: "nodes", Flags: []Flag{help}, Commands: []*Command{
			{Name: "list", Aliases: []string{"ls"}, Flags: []Flag{help, out, {Name: "sort", Complete: Words("id", "name")}}},
			{Name: "delete", Aliases: []string{"rm"}, Flags: []Flag{help, out, {Name: "force", Bool: true}}, Args: []Completer{Words("12", "13")}},
			{Name: "routes", Flags: []Flag{help}, Commands: []*Command{
				{Name: "set", Aliases: []string{"approve"}, Flags: []Flag{help, out}},
			}},
		}},
		{Name: "policy", Flags: []Flag{help}, Commands: []*Command{
			{Name: "check", Flags: []Flag{help}, Args: []Completer{Files}},
		}},
	}}
}

func show(m *Match, err error) string {
	if err != nil {
		e := err.(*Error)
		return fmt.Sprintf("ERR %d [%s] %q", e.Kind, strings.Join(e.Path, " "), e.Word)
	}
	var kv []string
	for _, k := range slices.Sorted(maps.Keys(m.Flags)) {
		kv = append(kv, fmt.Sprintf("%s=%q", k, m.Flags[k]))
	}
	return fmt.Sprintf("[%s] {%s} %q", strings.Join(m.Path, " "), strings.Join(kv, " "), m.Args)
}

func TestParse(t *testing.T) {
	for _, tc := range []struct{ argv, want string }{ // argv split on "|" so "" survives
		{"", `[] {} []`},
		{"nodes", `[nodes] {} []`},
		{"-o|json|nodes", `[nodes] {output=["json"]} []`},
		{"nodes|ls", `[nodes list] {} []`},
		{"nodes|routes|approve|1|2", `[nodes routes set] {} ["1" "2"]`},
		{"node|ls", `ERR 1 [] "node"`},
		{"nodes|help", `ERR 1 [nodes] "help"`},
		{"--|nodes", `ERR 1 [] "--"`},
		{"nodes|delete|12|--force|13", `[nodes delete] {force=["true"]} ["12" "13"]`},
		{"nodes|delete|12|--force=false|--force", `[nodes delete] {force=["false" "true"]} ["12"]`},
		{"nodes|delete|12|--force=maybe", `[nodes delete] {force=["maybe"]} ["12"]`},
		{"nodes|list|--force", `ERR 2 [nodes list] "--force"`},
		{"nodes|list|--sor", `ERR 2 [nodes list] "--sor"`},
		{"nodes|list|-ojson", `ERR 2 [nodes list] "-ojson"`},
		{"nodes|list|-ho|json", `ERR 2 [nodes list] "-ho"`},
		{"nodes|list|-output|json", `ERR 2 [nodes list] "-output"`},
		{"nodes|list|---sort|x", `ERR 2 [nodes list] "---sort"`},
		{"nodes|list|--=x", `ERR 2 [nodes list] "--"`},
		{"nodes|list|--sort", `ERR 3 [nodes list] "--sort"`},
		{"-o", `ERR 3 [] "-o"`},
		{"nodes|list|--sort|-name", `[nodes list] {sort=["-name"]} []`},
		{"nodes|list|--sort|--output|x", `[nodes list] {sort=["--output"]} ["x"]`},
		{"nodes|list|--sort=a=b|--sort=", `[nodes list] {sort=["a=b" ""]} []`},
		{"nodes|list|-o=json|--output|yaml", `[nodes list] {output=["json" "yaml"]} []`},
		{"-o|json|nodes|list|-o|yaml", `[nodes list] {output=["json" "yaml"]} []`},
		{"nodes|-o|json|list", `[nodes list] {output=["json"]} []`},
		{"-o|json|policy|check", `ERR 2 [policy check] "-o"`},
		{"policy|check|-o|json", `ERR 2 [policy check] "-o"`},
		{"nodes|--force|delete|12", `ERR 2 [nodes] "--force"`},
		{"nodes|delete|--|--force|-|", `[nodes delete] {} ["--force" "-" ""]`},
		{"nodes|delete|12|--|--", `[nodes delete] {} ["12" "--"]`},
		{"nodes|delete|-5", `ERR 2 [nodes delete] "-5"`},
		{"nodes|delete|-ø", `ERR 2 [nodes delete] "-ø"`},
		{"nodes|delete|tést|-h", `[nodes delete] {help=["true"]} ["tést"]`},
	} {
		argv := strings.Split(tc.argv, "|")
		if tc.argv == "" {
			argv = nil
		}
		if got := show(Parse(tree(), argv)); got != tc.want {
			t.Errorf("%q:\n got %s\nwant %s", tc.argv, got, tc.want)
		}
	}
}

func TestComplete(t *testing.T) {
	for _, tc := range []struct {
		line string // the last word is under the cursor; a trailing space starts a new one
		want string
	}{
		{"", "nodes policy :4"},
		{"no", "nodes :4"},
		{"nodes ", "list delete routes :4"},
		{"nodes r", "routes :4"}, // rm fits too, but a name fits
		{"nodes routes ap", "approve :4"},
		{"-o json nodes l", "list :4"},
		{"-o ", "json yaml :4"},
		{"nodes list --", "--help --output --sort :4"},
		{"nodes list -o", "-o :4"},
		{"nodes list -o ", "json yaml :4"},
		{"nodes list --output=j", "json :4"},
		{"nodes list --sort i", "id :4"},
		{"nodes list --force ", ":4"},
		{"nodes delete ", "12 13 :4"},
		{"nodes delete 12 ", ":4"},
		{"nodes delete o ", ":4"}, // "o" is the positional, not -o: no json
		{"nodes delete --force ", "12 13 :4"},
		{"nodes delete 12 -- --", ":4"},
		{"policy check ", ":0"},
		{"nodez ", ":4"},
	} {
		words := strings.Split(tc.line, " ")
		var b bytes.Buffer
		if !Serve(&b, tree(), append([]string{"__complete"}, words...)) {
			t.Fatal("Serve refused __complete")
		}
		if got := strings.ReplaceAll(strings.TrimSpace(b.String()), "\n", " "); got != tc.want {
			t.Errorf("%q: got %q, want %q", tc.line, got, tc.want)
		}
	}
	var b bytes.Buffer
	if Serve(&b, tree(), []string{"nodes"}) || b.Len() != 0 {
		t.Error("Serve answered a line that is no completion request")
	}
}

// FuzzParse: no panic, and every positional is a word of argv, in order.
func FuzzParse(f *testing.F) {
	f.Add("nodes|delete|12|--force|--|-x")
	f.Add("-o|json|nodes|list|--sort=-id")
	f.Fuzz(func(t *testing.T, line string) {
		argv := strings.Split(line, "|")
		m, err := Parse(tree(), argv)
		if err != nil {
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
		Complete(tree(), argv, "")
	})
}
