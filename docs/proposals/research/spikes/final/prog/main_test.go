package main

import (
	"bytes"
	"fmt"
	"slices"
	"strings"
	"testing"

	"spike/cmdline"
)

// TestTree: the tree is one Parse reads unambiguously.
func TestTree(t *testing.T) {
	if err := cmdline.Check(tree()); err != nil {
		t.Fatal(err)
	}
}

// TestParse: one row per command line; the program's own checks run on
// top of these in tests of their own.
func TestParse(t *testing.T) {
	for _, tc := range []struct {
		argv []string
		path string
		args []string
		err  string
	}{
		{argv: []string{"items", "rm", "12", "--force"}, path: "items delete", args: []string{"12"}},
		{argv: []string{"-c", "x.yaml", "items", "ls", "--sort=-id"}, path: "items list"},
		{argv: []string{"items", "delete", "--", "-12"}, path: "items delete", args: []string{"-12"}},
		{argv: []string{"items", "lst"}, err: `unknown command "lst" for "items"`},
	} {
		m, err := cmdline.Parse(tree(), tc.argv)
		if tc.err != "" {
			if err == nil || err.Error() != tc.err {
				t.Errorf("%q: got %v, want %s", tc.argv, err, tc.err)
			}
			continue
		}
		if err != nil || strings.Join(m.Path, " ") != tc.path || !slices.Equal(m.Args, tc.args) {
			t.Errorf("%q: got %v %q %v", tc.argv, m.Path, m.Args, err)
		}
	}
}

// TestTab: the answer the shell script reads, line by line.
func TestTab(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"items ", "list\tList items\ndelete\tDelete an item\n:4\n"},
		{"items list --sort ", "id\nname\n:4\n"},
		{"-c other.yaml items rm ", "21\n22\n:4\n"},
	} {
		var b bytes.Buffer
		cmdline.Serve(&b, tree(), append([]string{"__complete"}, strings.Split(tc.line, " ")...))
		if b.String() != tc.want {
			t.Errorf("%q: got %q", tc.line, b.String())
		}
	}
}

// TestProbe prints what the document quotes; run with -v.
func TestProbe(t *testing.T) {
	r := tree()
	for _, l := range []string{
		"items|list|--sort|-name",
		"items|list|--sort=-name",
		"items|list|-o|json",
		"items|list|-o=json",
		"items|list|--output=json",
		"items|list|-ojson",
		"items|list|--o|json",
		"items|list|-output|json",
		"items|list|--sor|id",
		"items|list|---sort|id",
		"items|delete|12|--force",
		"items|delete|--force|maybe",
		"items|delete|12|--force=maybe",
		"items|delete|12|--force=false",
		"items|delete|12|--no-force",
		"items|delete|12|-",
		"items|delete|12|",
		"items|delete|--|--force|-h",
		"items|delete|12|--",
		"items|delete|-5",
		"items|delete|-h",
		"items|list|-o|a|-o|b",
		"items|list|--filter|id=1|--filter|name=x",
		"-c|x.yaml|items|list",
		"items|-c|x.yaml|list",
		"items|list|-c|x.yaml",
		"-c|x.yaml|check|a.yaml",
		"-o|json|check|a.yaml",
		"items|--sort|id|list",
		"--force|items|delete|12",
		"items",
		"",
		"<nil>",
		"-h|items",
		"-h|items|list",
		"items|lst",
		"items|help",
		"help",
		"Items",
		"--|items",
		"items|--|list",
		"prog|items",
		"items|delete|list",
		"items|list|--sort",
		"-o",
		"items|-c",
		"items|list|--bogus|-h",
		"items|list|-h|--bogus",
		"-o|a|items|-o|b|lst",
		"items|list|-o|a|-o|b|--sort",
		"-c|a|-o|j|-c|b|check",
		"items|delete|-o=x|12|--bogus|13",
		"-c|nodes|items|list",
		"items|list|--sort|--filter|x",
		"items|list|--sort=a=b|--filter=",
		"items|list|-o=",
		"-",
		"items|delete|-\xff",
	} {
		var argv []string
		if l != "<nil>" {
			argv = strings.Split(l, "|")
		}
		m, err := cmdline.Parse(r, argv)
		s := fmt.Sprintf("Path=%q Flags=%v Args=%q ArgAt=%v", m.Path, m.Flags, m.Args, m.ArgAt)
		if e, ok := err.(*cmdline.Error); ok {
			s += fmt.Sprintf(" ERR Kind=%d Path=%q Word=%q At=%d text=%q", e.Kind, e.Path, e.Word, e.At, e.Error())
		}
		t.Logf("PARSE %q => %s", argv, s)
	}
	for _, l := range []string{
		"",
		"it",
		"items ",
		"items l",
		"items r",
		"items rm",
		"items list -",
		"items list --",
		"items list -o",
		"items list -s",
		"items list -o ",
		"items list --output=j",
		"items list --sort ",
		"items list --sort -",
		"items list --sort -o ",
		"items list --sort id --",
		"items list --filter id --f",
		"items list --filter id --filter ",
		"items list -o json -o ",
		"items list -o= --output=",
		"items list --config=",
		"items list --force=",
		"items delete --force=",
		"items list --bogus=x",
		"items delete ",
		"items delete 12 ",
		"items delete -- ",
		"items delete -- --",
		"items delete 12 -- --",
		"items list --sort -- --",
		"items list --sort -- -",
		"-c other.yaml items rm ",
		"-c ",
		"check ",
		"check a.yaml ",
		"itemz ",
		"items lst ",
		"-- items ",
		"items list --bogus --s",
		"items list --bogus ",
		"items list -h --",
		"-h it",
		"items --",
		"--",
		"I",
		"completion ",
		"items delete o ",
		"items list --sort=\"",
	} {
		var b bytes.Buffer
		cmdline.Serve(&b, r, append([]string{"__complete"}, strings.Split(l, " ")...))
		t.Logf("TAB %q => %q", l, b.String())
	}
	var b bytes.Buffer
	cmdline.Serve(&b, r, []string{"__completeNoDesc", "items", ""})
	t.Logf("NODESC => %q", b.String())
	b.Reset()
	cmdline.Serve(&b, r, []string{"__complete"})
	t.Logf("BARE => %q", b.String())
	t.Logf("SERVE other => %v", cmdline.Serve(&b, r, []string{"items"}))

	bad := []struct {
		name string
		edit func(*cmdline.Command)
	}{
		{"dup child", func(c *cmdline.Command) { c.Commands[0].Commands[1].Aliases = []string{"ls"} }},
		{"group args", func(c *cmdline.Command) { c.Commands[0].Args = []cmdline.Completer{nil} }},
		{"dash name", func(c *cmdline.Command) { c.Commands[1].Name = "-x" }},
		{"space name", func(c *cmdline.Command) { c.Commands[1].Name = "check it" }},
		{"flag =", func(c *cmdline.Command) { c.Flags = append(c.Flags, cmdline.Flag{Name: "a=b"}) }},
		{"short ø", func(c *cmdline.Command) { c.Flags = append(c.Flags, cmdline.Flag{Name: "x", Short: 'ø'}) }},
		{"flag twice", func(c *cmdline.Command) { c.Flags = append(c.Flags, cmdline.Flag{Name: "help", Bool: true}) }},
		{"two shorts", func(c *cmdline.Command) { c.Commands[0].Commands[0].Flags[1].Short = 'p' }},
		{"bool here value there", func(c *cmdline.Command) { c.Commands[0].Commands[0].Flags[1].Bool = true }},
		{"one short two flags", func(c *cmdline.Command) {
			c.Commands[0].Commands[1].Flags = append(c.Commands[0].Commands[1].Flags, cmdline.Flag{Name: "count", Short: 'c'})
		}},
	}
	for _, x := range bad {
		r := tree()
		x.edit(r)
		t.Logf("CHECK %s => %v", x.name, cmdline.Check(r))
	}
}
