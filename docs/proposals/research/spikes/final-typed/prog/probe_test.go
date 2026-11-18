package main

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"spike/cmdline"
)

// The probes print the tables that 003 quotes; run with -v.

var kinds = [...]string{"", "unknown command", "unknown flag", "missing value", "repeated", "bad value", "argument count", "unresolved"}

func words(line string) []string {
	if line == "" {
		return nil
	}
	w := strings.Split(line, " ")
	for i := range w {
		if w[i] == `""` {
			w[i] = ""
		}
	}
	return w
}

func q(s string) string {
	if s == "" {
		return "`\"\"`"
	}
	return "`" + s + "`"
}

// lineText is a Line as the document writes it; at adds the positions of the arguments.
func lineText(l *cmdline.Line, at bool) string {
	s := "`[" + strings.Join(l.Command.Path, " ") + "]`"
	for _, g := range l.Flags {
		s += fmt.Sprintf(", `%s=%s@%d`", g.Name, g.Value, g.At)
	}
	for i, a := range l.Args {
		s += ", argument " + q(a)
		if at {
			s += fmt.Sprintf(" @%d", l.ArgAt[i])
		}
	}
	return s
}

// mistake is a UsageError as the document writes it.
func mistake(err error) string {
	var e *cmdline.UsageError
	if !errors.As(err, &e) {
		return fmt.Sprint(err)
	}
	s := fmt.Sprintf("%s `[%s]`", kinds[e.Kind], strings.Join(e.Path, " "))
	if e.Kind != cmdline.ArgCount {
		s += " " + q(e.Word)
	}
	s += fmt.Sprintf(" @%d", e.At)
	if e.Err != nil {
		s += fmt.Sprintf(": `%v`", e.Err)
	}
	return s
}

type row struct {
	argv string
	note string
	show func(*cmdline.Line) string
}

func list3(l *cmdline.Line) listIn { in, _ := cmdline.Get[listIn](l); return in }

var tables = []struct {
	name string
	rows []row
}{
	{"one-word", []row{
		{argv: "check -"}, {argv: `check ""`}, {argv: "check -- -h"}, {argv: "check a.yaml --"}, {argv: "check -5"}, {argv: "-"}, {argv: `""`},
		{argv: "items -- list"}, {argv: "Items"}, {argv: "items list ---sort id"}, {argv: "items list --sor id"}, {argv: "items list -ojson"},
		{argv: "items list -output json"}, {argv: "items list --o json"},
	}},
	{"flag-values", []row{
		{argv: "items list -o json"}, {argv: "items list -o=json"}, {argv: "items list --sort -name"}, {argv: "items list --filter --sort"},
		{argv: "items list --name=a=b --filter=", note: "`filter` is given and empty"}, {argv: "-c items items list"}, {argv: "items list --sort"}, {argv: "-o"},
	}},
	{"bools", []row{
		{argv: "items delete --force maybe"}, {argv: "items delete 12 --force=false"}, {argv: "items delete 12 --force=maybe"},
		{argv: "items delete 12 --force=TRUE"}, {argv: "items delete 12 --no-force"}, {argv: "items delete 12 -hf"},
	}},
	{"repeat", []row{
		{argv: "items list -o json -o yaml"}, {argv: "-o json items list --output=yaml"}, {argv: "items delete 12 --force --force=false"},
		{argv: "items list --columns id --columns name", note: "a list is one value"},
		{argv: "items list --filter a --filter b,c", note: "a `Repeat[string]`", show: func(l *cmdline.Line) string { return fmt.Sprintf("`Filter` is `%q`", []string(list3(l).Filter)) }},
	}},
	{"where", []row{
		{argv: "-c x.yaml items list"}, {argv: "items -c x.yaml list"}, {argv: "items list -c x.yaml"}, {argv: "items delete --force -h 12"},
		{argv: "-h items -o json"}, {argv: "-o json check a.yaml", note: "`check` does not take `-o`"}, {argv: "items --sort id list"}, {argv: "--force items delete 12"},
	}},
	{"walk", []row{
		{argv: "", note: "the root"}, {argv: "items", note: "the group"}, {argv: "items ls"}, {argv: "items rm 12"}, {argv: "items delete list"},
		{argv: "items lst"}, {argv: "help"}, {argv: "items help"}, {argv: "prog items"},
	}},
	{"count", []row{
		{argv: "items delete"}, {argv: "items delete 12 13"}, {argv: "items list x"}, {argv: "check", note: "`file` is optional"}, {argv: "check a b"},
		{argv: "items delete --bogus", note: "the count is not reported"}, {argv: "items delete 12 13 --force=x", note: "the count is not reported"},
	}},
}

// values rows show the field that was filled.
var values = []row{
	{argv: "items list --limit 10", show: func(l *cmdline.Line) string { return fmt.Sprintf("`Limit` is `%d`", list3(l).Limit) }},
	{argv: "items list", show: func(l *cmdline.Line) string { return fmt.Sprintf("`Limit` is `%d`, the default", list3(l).Limit) }},
	{argv: "items list --limit 0x10"}, {argv: "items list --limit 1.5"}, {argv: "items list --limit="},
	{argv: "items list -o yaml", show: func(l *cmdline.Line) string {
		o, _ := cmdline.Get[outputFlags](l)
		return fmt.Sprintf("`Output` is `%q`", o.Output)
	}},
	{argv: "items list -o xml"},
	{argv: "items list --sort -name", show: func(l *cmdline.Line) string { return fmt.Sprintf("`Sort` is `%q`", list3(l).Sort) }},
	{argv: "items list --since 90m", show: func(l *cmdline.Line) string {
		d, ok := list3(l).Since.Get()
		return fmt.Sprintf("`Since.Get()` is `%v`, `%v`", d, ok)
	}},
	{argv: "items list --since 5"},
	{argv: "items list --columns id,-name", show: func(l *cmdline.Line) string { return fmt.Sprintf("`Columns` is `%q`", list3(l).Columns) }},
	{argv: "items list --columns="}, {argv: "items list --columns id,,name"}, {argv: "items list --columns id,"}, {argv: "items list --columns id,size"},
	{argv: "items list --name=", show: func(l *cmdline.Line) string {
		n, ok := list3(l).Name.Get()
		return fmt.Sprintf("`Name.Get()` is `%q`, `%v`", n, ok)
	}},
	{argv: "items list", show: func(l *cmdline.Line) string {
		n, ok := list3(l).Name.Get()
		return fmt.Sprintf("`Name.Get()` is `%q`, `%v`", n, ok)
	}},
	{argv: "check a.yaml", show: func(l *cmdline.Line) string {
		in, _ := cmdline.Get[checkIn](l)
		f, ok := in.File.Get()
		return fmt.Sprintf("`File.Get()` is `%q`, `%v`", f, ok)
	}},
	{argv: "check", show: func(l *cmdline.Line) string {
		in, _ := cmdline.Get[checkIn](l)
		f, ok := in.File.Get()
		return fmt.Sprintf("`File.Get()` is `%q`, `%v`", f, ok)
	}},
	{argv: "-c x.yaml items delete 12", show: func(l *cmdline.Line) string {
		in, _ := cmdline.Get[deleteIn](l)
		c, _ := cmdline.Get[configFlags](l)
		return fmt.Sprintf("`Config` is `%q`; `Item` is `%+v` until `Run`", c.Config, in.Item)
	}},
}

func show(argv string) string {
	if argv == "" {
		return "(none)"
	}
	return "`" + argv + "`"
}

// TestProbe prints the Parse tables.
func TestProbe(t *testing.T) {
	tr := tree()
	for _, tb := range tables {
		fmt.Printf("### TABLE %s\n", tb.name)
		for _, r := range tb.rows {
			line, err := tr.Parse(words(r.argv))
			res := lineText(line, false)
			if err != nil {
				res = mistake(err)
			}
			if r.show != nil {
				res += "; " + r.show(line)
			}
			if r.note != "" {
				res += " (" + r.note + ")"
			}
			fmt.Printf("| %s | %s |\n", show(r.argv), res)
		}
	}
	fmt.Println("### TABLE values")
	for _, r := range values {
		line, err := tr.Parse(words(r.argv))
		res, field := lineText(line, false), ""
		if err != nil {
			res = mistake(err)
		}
		if r.show != nil {
			field = r.show(line)
		}
		fmt.Printf("| %s | %s | %s |\n", show(r.argv), res, field)
	}
	fmt.Println("### TABLE returns")
	for _, argv := range []string{
		"-o json items -c x lst", "items list -o json --columns id --sort", "-c a -o json -c b check", "items delete -o=json 12 --bogus 13",
		"items list --limit x --sort id", "items delete -h",
	} {
		line, err := tr.Parse(words(argv))
		_, ok := cmdline.Get[helpFlags](line)
		fmt.Printf("| %s | %s | %s | %s |\n", show(argv), lineText(line, true), mistake(err), map[bool]string{true: "yes", false: "no"}[ok])
	}
	fmt.Println("### TABLE several")
	for _, r := range []row{
		{argv: "items list --limit x --bogus", note: "an unknown flag at 4"},
		{argv: "items list --bogus --limit x", note: "a bad value at 3; it is never read"},
		{argv: "items list --sort id --sort name --since", note: "a missing value at 6"},
		{argv: "-h=x items lst", note: "an unknown command at 2"},
		{argv: "items list -o xml -o yaml", note: "a repeat at 4"},
		{argv: "items delete 12 --force --force=x", note: "a bad value in the same word"},
		{argv: "items delete 12 13 --bogus", note: "a wrong count"},
		{argv: "items delete --bogus -h", note: "`-h`, and a wrong count"},
	} {
		_, err := tr.Parse(words(r.argv))
		fmt.Printf("| %s | %s | %s |\n", show(r.argv), mistake(err), r.note)
	}
	fmt.Println("### TEXT default")
	ctx := context.WithValue(context.Background(), storeKey{}, load("prog.yaml"))
	for _, argv := range []string{
		"lst", "items lst", "items list --bogus", "items list --sort", "items list -o json -o yaml", "items list --limit ten",
		"completion", "items delete 12 13", "items delete 99",
	} {
		line, err := tr.Parse(words(argv))
		if err == nil {
			err = line.Run(ctx)
		}
		fmt.Println(err)
	}
	fmt.Println("### TEXT unresolved")
	line, _ := tr.Parse(words("items delete 99 --force"))
	var e *cmdline.UsageError
	errors.As(line.Run(ctx), &e)
	fmt.Printf("%s; flag=%q arg=%q value=%q\n", mistake(e), e.Flag, e.Arg, e.Value)
}

var tabLines = []row{
	{argv: ""}, {argv: "items "}, {argv: "items l"}, {argv: "items r", note: "no name fits, so the alias"}, {argv: "items list -"}, {argv: "items list -o"},
	{argv: "items list -s", note: "`--sort` has no short"}, {argv: "items list -o "}, {argv: "items list --output=j"}, {argv: "items list -o=y"},
	{argv: "items list --sort -", note: "the `-` is the value of `--sort`"}, {argv: "items list --sort id --"}, {argv: "items list --filter id --f", note: "a `Repeat`"},
	{argv: "items list -o json -o ", note: "`-o` is given already"}, {argv: "-o json items list --"}, {argv: "items list --config=", note: "files"},
	{argv: "items delete --force=", note: "a bool"}, {argv: "items --", note: "the group's own flags"}, {argv: "items delete "},
	{argv: "items delete 12 ", note: "`delete` has one argument"}, {argv: "items delete -- --", note: "an argument, completed by the type of argument 0"},
	{argv: "items delete o ", note: "`o` is an argument, not `-o`"}, {argv: "check ", note: "files"}, {argv: "items list --columns "},
	{argv: "items list --columns id,", note: "a list"}, {argv: "items list --columns=id,n", note: "a list"}, {argv: "items list --limit ", note: "an `int` offers nothing"},
	{argv: "itemz "}, {argv: "items lst "}, {argv: "items list --bogus --so"}, {argv: "items list -h --"},
}

// TestProbeTab prints the Tab table.
func TestProbeTab(t *testing.T) {
	tr := tree()
	fmt.Println("### TABLE tab")
	for _, r := range tabLines {
		w := strings.Split(r.argv, " ")
		pre, cur := w[:len(w)-1], w[len(w)-1]
		got, dir := tr.Complete(pre, cur)
		for i := range got {
			got[i], _, _ = strings.Cut(got[i], "\t")
			got[i] = "`" + got[i] + "`"
		}
		p, c, out := show(strings.Join(pre, " ")), q(cur), strings.Join(got, ", ")
		if out == "" {
			out = "none"
		}
		if r.note != "" {
			if out == "none" {
				out += ": " + r.note
			} else {
				out += " (" + r.note + ")"
			}
		}
		fmt.Printf("| %s | %s | %s | %d |\n", p, c, out, dir)
	}
}

// TestProbeNew prints what New says about a wrong tree.
func TestProbeNew(t *testing.T) {
	type badIn struct {
		Wait time.Duration `flag:"wait" json:"wait"`
		Name string
	}
	_, err := cmdline.New(cmdline.Group{Name: "prog", Commands: []cmdline.Node{
		cmdline.Group{Name: "items", Commands: []cmdline.Node{
			cmdline.Command[badIn]{Name: "list", Aliases: []string{"list"}},
		}},
	}})
	fmt.Printf("### TEXT new\n%v\n", err)
}

// TestProbeInfo prints the tree as data.
func TestProbeInfo(t *testing.T) {
	var walk func(c *cmdline.Info, depth int)
	walk = func(c *cmdline.Info, depth int) {
		fmt.Printf("%s%q path=%v aliases=%v usage=%q help=%q\n", strings.Repeat("  ", depth), c.Name, c.Path, c.Aliases, c.Usage, c.Help)
		for _, f := range c.Flags {
			fmt.Printf("%s  flag %+v\n", strings.Repeat("  ", depth), f)
		}
		for _, a := range c.Args {
			fmt.Printf("%s  arg %+v\n", strings.Repeat("  ", depth), a)
		}
		for _, s := range c.Commands {
			walk(s, depth+1)
		}
	}
	walk(tree().Root(), 0)
}
