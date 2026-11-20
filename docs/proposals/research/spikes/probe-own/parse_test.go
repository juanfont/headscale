package own

import (
	"fmt"
	"sort"
	"strings"
	"testing"
)

func render(p *Parsed, err error) string {
	if err != nil {
		switch e := err.(type) {
		case *UnknownCommandError:
			return fmt.Sprintf("ERR unknown-command %q at [%s]", e.Word, pathString(e.Path))
		case *UnknownFlagError:
			return fmt.Sprintf("ERR unknown-flag %s at [%s]", e.Flag, pathString(e.Path))
		case *MissingValueError:
			return fmt.Sprintf("ERR missing-value %s at [%s]", e.Flag, pathString(e.Path))
		case *BadValueError:
			return fmt.Sprintf("ERR bad-value %s=%q at [%s]", e.Flag, e.Value, pathString(e.Path))
		}
		return "ERR untyped " + err.Error()
	}
	var keys []string
	for k := range p.Values {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var kv []string
	for _, k := range keys {
		kv = append(kv, fmt.Sprintf("%s=%q", k, p.Values[k]))
	}
	kind := ""
	if !p.Node.Leaf() {
		kind = " (group)"
	}
	return fmt.Sprintf("[%s]%s {%s} args=%q", pathString(p.Path), kind, strings.Join(kv, " "), p.Args)
}

// want "" means: no assertion, print both (an edge case to compare).
var cases = []struct {
	argv string // split on "|" so "" and spaces survive
	want string
}{
	{"nodes|list", `[nodes list] {} args=[]`},
	{"nodes|routes|approve|12|10.0.0.0/8", `[nodes routes set] {} args=["12" "10.0.0.0/8"]`},
	{"nodes|rm|12", `[nodes delete] {} args=["12"]`},
	{"node|ls", `ERR unknown-command "node" at []`},
	{"auth|keys|approve", `ERR unknown-command "approve" at [auth keys]`},
	{"nodes|delete|12|--force", `[nodes delete] {force=["true"]} args=["12"]`},
	{"nodes|delete|--force|12", `[nodes delete] {force=["true"]} args=["12"]`},
	{"nodes|delete|12|--force|13", `[nodes delete] {force=["true"]} args=["12" "13"]`},
	{"nodes|list|--force", `ERR unknown-flag --force at [nodes list]`},
	{"nodes|delete|12|--forc", `ERR unknown-flag --forc at [nodes delete]`},
	{"nodes|list|--sort|-last-seen", `[nodes list] {sort=["-last-seen"]} args=[]`},
	{"nodes|list|--columns|-ip,-os", `[nodes list] {columns=["-ip,-os"]} args=[]`},
	{"nodes|list|--filter=owner=tag:ci|--filter|last-seen>30d", `[nodes list] {filter=["owner=tag:ci" "last-seen>30d"]} args=[]`},
	{"nodes|list|--columns|id|--columns|name", `[nodes list] {columns=["id" "name"]} args=[]`},
	{"nodes|set|12|--name|", `[nodes set] {name=[""]} args=["12"]`},
	{"nodes|set|12|--name=", `[nodes set] {name=[""]} args=["12"]`},
	{"nodes|set|12|--name=a=b", `[nodes set] {name=["a=b"]} args=["12"]`},
	{"nodes|set|12", `[nodes set] {} args=["12"]`},
	{"nodes|set|12|--name|-h", `[nodes set] {name=["-h"]} args=["12"]`},
	{"nodes|set|12|--name|--", `[nodes set] {name=["--"]} args=["12"]`},
	{"policy|set|-", `[policy set] {} args=["-"]`},
	{"nodes|routes|set|12|", `[nodes routes set] {} args=["12" ""]`},
	{"nodes|delete|--|-12", `[nodes delete] {} args=["-12"]`},
	{"version|-o|json", `[version] {output=["json"]} args=[]`},
	{"version|-ojson", ""}, // D11: own refuses, pflag accepts
	{"version|-o=json", `[version] {output=["json"]} args=[]`},
	{"version|--output=json", `[version] {output=["json"]} args=[]`},
	{"-o|json|version", `[version] {output=["json"]} args=[]`},
	{"-c|x|nodes|list", `[nodes list] {config=["x"]} args=[]`},
	{"nodes|-c|x|list", `[nodes list] {config=["x"]} args=[]`},
	{"nodes|list|-c|x", `[nodes list] {config=["x"]} args=[]`},
	{"-o|json|check|config", `ERR unknown-flag -o at [check config]`},
	{"check|config|-o|json", `ERR unknown-flag -o at [check config]`},
	{"auth|keys|create|alice|-r", `ERR unknown-flag -r at [auth keys create]`},
	{"auth|keys|create|alice|-e|90d|--reusable|--tags|tag:ci,tag:build", `[auth keys create] {expiry=["90d"] reusable=["true"] tags=["tag:ci,tag:build"]} args=["alice"]`},
	{"debug|create-node|--name|a|-u|alice|-k|K|-r|10.0.0.0/8|-r|10.1.0.0/16", `[debug create-node] {key=["K"] name=["a"] route=["10.0.0.0/8" "10.1.0.0/16"] user=["alice"]} args=[]`},
	{"nodes|delete|12|--force=false", `[nodes delete] {force=["false"]} args=["12"]`},
	{"nodes|delete|12|--force=maybe", `ERR bad-value --force="maybe" at [nodes delete]`},
	{"nodes|list|--sort", `ERR missing-value --sort at [nodes list]`},
	{"nodes|list|-o", `ERR missing-value -o at [nodes list]`},
	{"nodes|delete|--help", `[nodes delete] {help=["true"]} args=[]`},
	{"nodes", `[nodes] (group) {} args=[]`},
	{"", `[] (group) {} args=[]`},
	{"-h", `[] (group) {help=["true"]} args=[]`},
	{"version|-o|json|-o|json", `[version] {output=["json" "json"]} args=[]`},
	// Edges: print both, no single right answer.
	{"nodes|delete|12|-hf", ""},
	{"nodes|list|-ho|json", ""},
	{"nodes|delete|-ø", ""},
	{"nodes|delete|---force", ""},
	{"nodes|delete|-5", ""},
	{"nodes|--force|delete|12", ""},
	{"--|nodes|list", ""},
	{"nodes|delete|12|--force=", ""},
	{"nodes|delete|12|-h=true", ""},
	{"nodes|delete|--=x", ""},
	{"nodes|list|--sort=", ""},
	{"nodes|delete|12|--force|--force", ""},
	{"nodes|set|12|--name|tést|-o|jsön", ""},
}

func TestParsers(t *testing.T) {
	for _, tc := range cases {
		var argv []string
		if tc.argv != "" {
			argv = strings.Split(tc.argv, "|")
		}
		ownGot := render(Dispatch(Tree(), argv, OwnParse))
		pfGot := render(Dispatch(Tree(), argv, PflagParse))
		if tc.want == "" {
			t.Logf("EDGE %-40q\n\town:   %s\n\tpflag: %s", tc.argv, ownGot, pfGot)
			continue
		}
		if ownGot != tc.want {
			t.Errorf("own   %q\n got %s\nwant %s", tc.argv, ownGot, tc.want)
		}
		if pfGot != tc.want {
			t.Errorf("pflag %q\n got %s\nwant %s", tc.argv, pfGot, tc.want)
		}
	}
}
