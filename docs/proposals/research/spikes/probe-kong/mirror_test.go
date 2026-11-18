package probekong

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/alecthomas/kong"
)

func tree() *Node {
	list := func() *Node {
		return &Node{Name: "list", Aliases: []string{"ls"}, Flags: []FlagSpec{
			{Name: "columns", Kind: String}, {Name: "sort", Kind: String},
			{Name: "filter", Kind: Repeat}, {Name: "list-columns", Kind: Bool},
		}}
	}
	return &Node{
		Name: "headscale",
		Flags: []FlagSpec{
			{Name: "output", Short: "o", Kind: String}, {Name: "config", Short: "c", Kind: String},
			{Name: "help", Short: "h", Kind: Bool}, {Name: "version", Kind: Bool},
		},
		Children: []*Node{
			{Name: "nodes", Children: []*Node{
				list(),
				{Name: "delete", Aliases: []string{"rm"}, Args: 1, Flags: []FlagSpec{{Name: "force", Kind: Bool}}},
				{Name: "set", Args: 1, Flags: []FlagSpec{{Name: "name", Kind: String}, {Name: "expiry", Short: "e", Kind: String}, {Name: "tags", Kind: String}}},
				{Name: "routes", Children: []*Node{
					{Name: "set", Aliases: []string{"approve"}, Args: 2, Flags: []FlagSpec{{Name: "force", Kind: Bool}}},
					{Name: "list", Aliases: []string{"ls"}, Args: 1},
				}},
			}},
			{Name: "api", Children: []*Node{{Name: "oauth-clients", Children: []*Node{
				{Name: "delete", Aliases: []string{"rm"}, Args: 1, Flags: []FlagSpec{{Name: "force", Kind: Bool}}},
			}}}},
			{Name: "auth", Children: []*Node{{Name: "keys", Children: []*Node{
				list(),
				{Name: "get", Args: 1},
				{Name: "create", Args: 1, Flags: []FlagSpec{{Name: "expiry", Short: "e", Kind: String}, {Name: "reusable", Kind: Bool}, {Name: "tags", Kind: String}}},
			}}}},
			{Name: "policy", Children: []*Node{{Name: "set", Args: 1}}},
			{Name: "check", Children: []*Node{{Name: "extra-records", Args: 1}}},
			{Name: "debug", Children: []*Node{{Name: "create-node", Flags: []FlagSpec{{Name: "route", Short: "r", Kind: Repeat}, {Name: "user", Short: "u", Kind: String}}}}},
		},
	}
}

func run(args ...string) string {
	r, err := Parse(tree(), args)
	if err != nil {
		var pe *ParseErr
		if errors.As(err, &pe) {
			return fmt.Sprintf("ERR %s word=%q path=%v flags=%q | kong: %v", pe.Kind, pe.Word, pe.Path, pe.Flags, pe.Cause)
		}
		return "ERR " + err.Error()
	}
	return fmt.Sprintf("leaf=%v args=%q flags=%q", r.Leaf, r.Args, r.Flags)
}

func TestContract(t *testing.T) {
	cases := [][]string{
		// R01/R04/R05/R06
		{"api", "oauth-clients", "delete", "c9f2", "--force"},
		{"api", "oauth-clients", "rm", "c9f2"},
		{"nodes", "rm", "12"},
		{"nodes", "routes", "approve", "12", "10.0.0.0/8"},
		{"auth", "keys", "ls"},
		{"check", "extra-records", "r.json"},
		{"node", "ls"},
		{"auth", "keys", "approve"},
		{"nodes", "authorize", "12"},
		{"configtest"},
		// R12
		{"policy", "set", "-"},
		{"auth", "keys", "get", "hskey-auth-ab12cd-***"},
		// R15/R16
		{"nodes", "set", "12", "--expiry", "24h"},
		{"nodes", "set", "12", "--expiry=24h"},
		{"nodes", "list", "-o", "json"},
		{"nodes", "list", "-ojson"},
		{"nodes", "list", "-o=json"},
		{"auth", "keys", "create", "alice", "-e90d"},
		// R17 unknown short
		{"auth", "keys", "create", "alice", "-r"},
		// R18
		{"nodes", "list", "--force"},
		// R19 / D3: global before and after
		{"-c", "x", "nodes", "list"},
		{"nodes", "list", "-c", "x"},
		{"-o", "json", "nodes", "list"},
		{"check", "extra-records", "f", "-o", "json"}, // kong accepts; our layer must refuse
		// R20 interspersed
		{"nodes", "delete", "--force", "12"},
		{"nodes", "delete", "12", "--force"},
		{"nodes", "routes", "set", "12", "--force", "10.0.0.0/8"},
		// R21
		{"nodes", "list", "--sort", "-last-seen"},
		{"nodes", "list", "--columns", "-ip,-os"},
		{"nodes", "list", "--columns=-ip"},
		// R22
		{"nodes", "list", "--filter", "owner=tag:ci"},
		{"nodes", "list", "--filter=owner=alice"},
		{"nodes", "list", "--filter", "last-seen>30d", "--filter", "name:web,online=true"},
		// R23/R24
		{"nodes", "set", "12", "--name", ""},
		{"nodes", "set", "12", "--name="},
		{"nodes", "set", "12"},
		// R25/G06
		{"nodes", "delete", "12", "--force=false"},
		{"nodes", "delete", "12", "--force=true"},
		{"nodes", "delete", "12", "--no-force"},
		// R26
		{"nodes", "routes", "set", "12", ""},
		// D6 repeated
		{"nodes", "set", "12", "--tags", "a", "--tags", "b"},
		{"nodes", "list", "-o", "json", "-o", "json"},
		// R28
		{"nodes", "set", "12", "-e", "1d12h"},
		// R32 count is ours
		{"nodes", "routes", "set", "12"},
		{"nodes", "delete", "12", "13"},
		{"nodes", "delete", "12", "13", "14"},
		{"nodes", "routes", "list", "12", "13"},
		{"nodes", "delete", "12", "13", "--force", "14"},
		// G05
		{"nodes", "delete", "--", "-x"},
		{"nodes", "delete", "--force", "--", "--force"},
		// G08/D7, G14/D8, G15, R52/R53
		{"--version"},
		{"help"},
		{},
		{"nodes"},
		{"nodes", "routes"},
		{"nodes", "--help"},
		{"nodes", "delete", "--help"},
		{"nodes", "delete", "-h", "12", "13"},
		// missing value
		{"nodes", "list", "--sort"},
		{"nodes", "set", "12", "--name"},
		{"nodes", "set", "12", "--name", "--force"},
		{"nodes", "set", "12", "-e="},
		{"nodes", "list", "--filter", "-x", "--filter"},
		{"nodes", "set", "12", "-e"},
		// G20 abbreviations, G21 grouping
		{"nodes", "set", "12", "--exp", "1h"},
		{"debug", "create-node", "-u", "alice", "-r", "10.0.0.0/8", "-r", "10.1.0.0/16"},
		{"nodes", "delete", "12", "-fo", "json"},
		// typo in flag
		{"nodes", "delete", "12", "--forse"},
		{"nodes", "lst"},
	}
	for _, c := range cases {
		t.Logf("%-55s -> %s", strings.Join(quote(c), " "), run(c...))
	}
}

func quote(a []string) []string {
	out := make([]string, len(a))
	for i, s := range a {
		if s == "" || strings.ContainsAny(s, " *<>") {
			s = fmt.Sprintf("%q", s)
		}
		out[i] = s
	}
	return out
}

// R49/R56/G26: fresh tree per run, parallel, no global state.
func TestParallel(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 200 {
		wg.Go(func() {
			r, err := Parse(tree(), []string{"nodes", "set", fmt.Sprint(i), "--name", fmt.Sprint(i)})
			if err != nil || r.Args[0] != fmt.Sprint(i) || r.Flags["name"][0] != fmt.Sprint(i) {
				t.Errorf("run %d: %v %v", i, r, err)
			}
		})
	}
	wg.Wait()
}

// R63: no env binding unless asked.
func TestNoEnv(t *testing.T) {
	t.Setenv("HEADSCALE_FORCE", "1")
	t.Setenv("FORCE", "1")
	t.Log(run("nodes", "delete", "12"))
}

// Writers: what does kong write on its own?
func TestNothingWritten(t *testing.T) {
	var out, errb strings.Builder
	_, _ = Parse(tree(), []string{"nodes", "bogus"}, kong.Writers(&out, &errb))
	_, _ = Parse(tree(), []string{"nodes", "list", "--bogus"}, kong.Writers(&out, &errb))
	t.Logf("stdout=%q stderr=%q", out.String(), errb.String())
}

// Raw kong error text and exit code, for the record.
func TestKongErrorShape(t *testing.T) {
	k, _ := Build(tree())
	_, err := k.Parse([]string{"nodes", "lst"})
	var pe *kong.ParseError
	errors.As(err, &pe)
	t.Logf("type=%T msg=%q exit=%d unwrap=%T", err, err, pe.ExitCode(), errors.Unwrap(err))
	_, err = k.Parse([]string{"nodes", "list", "--forse"})
	errors.As(err, &pe)
	t.Logf("type=%T msg=%q exit=%d unwrap=%T", err, err, pe.ExitCode(), errors.Unwrap(err))
}
