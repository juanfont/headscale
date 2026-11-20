// Probe: how creachadair/command v0.2.13 parses Headscale-shaped command lines.
// Mode "native" = SetFlags + MergeFlags(true), the way an adapter would use it.
package main

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"

	"github.com/creachadair/command"
	"github.com/creachadair/flax"
)

// sval records every Set so we can see "given", "given twice" and "given empty".
type sval struct{ v []string }

func (s *sval) Set(x string) error { s.v = append(s.v, x); return nil }
func (s *sval) String() string {
	if s == nil || len(s.v) == 0 {
		return ""
	}
	return s.v[len(s.v)-1]
}

type bval struct{ v []bool }

func (b *bval) Set(x string) error {
	p, err := strconv.ParseBool(x)
	if err != nil {
		return err
	}
	b.v = append(b.v, p)
	return nil
}
func (b *bval) String() string   { return fmt.Sprint(b != nil && len(b.v) > 0 && b.v[len(b.v)-1]) }
func (b *bval) IsBoolFlag() bool { return true }

type flagDef struct {
	long, short string
	isBool      bool
}

type result struct {
	leaf  string
	args  []string
	flags map[string]string
}

type tree struct {
	vals map[string]fmt.Stringer // "path/long" -> value
	res  *result
}

func (t *tree) bind(path string, defs []flagDef) func(*command.Env, *flag.FlagSet) {
	return func(_ *command.Env, fs *flag.FlagSet) {
		for _, d := range defs {
			var v flag.Value
			if d.isBool {
				v = &bval{}
			} else {
				v = &sval{}
			}
			t.vals[path+"/"+d.long] = v
			fs.Var(v, d.long, "")
			if d.short != "" {
				fs.Var(v, d.short, "")
			}
		}
	}
}

func (t *tree) run(path string) func(*command.Env) error {
	return func(env *command.Env) error {
		r := &result{leaf: path, args: env.Args, flags: map[string]string{}}
		for k, v := range t.vals {
			switch x := v.(type) {
			case *sval:
				if len(x.v) > 0 {
					r.flags[k] = fmt.Sprintf("%q", x.v)
				}
			case *bval:
				if len(x.v) > 0 {
					r.flags[k] = fmt.Sprint(x.v)
				}
			}
		}
		t.res = r
		return nil
	}
}

var global = []flagDef{{"config", "c", false}, {"output", "o", false}, {"help", "h", true}}

func build(groupsRunnable bool) (*command.C, *tree) {
	t := &tree{vals: map[string]fmt.Stringer{}}
	leaf := func(path, name string, defs ...flagDef) *command.C {
		p := path + " " + name
		return &command.C{Name: name, SetFlags: t.bind(p, defs), Run: t.run(p)}
	}
	group := func(name string, subs ...*command.C) *command.C {
		c := &command.C{Name: name, Commands: subs}
		if groupsRunnable {
			c.Run = t.run("GROUP " + name)
		}
		return c
	}
	list := leaf("nodes", "list", flagDef{"sort", "", false}, flagDef{"columns", "", false}, flagDef{"filter", "", false}, flagDef{"list-columns", "", true})
	ls := *list // alias as a copy, the #2647 way
	ls.Name, ls.Unlisted = "ls", true
	del := leaf("nodes", "delete", flagDef{"force", "", true})
	root := &command.C{
		Name:     "headscale",
		SetFlags: t.bind("root", global),
		Run:      t.run("ROOT"),
		Commands: []*command.C{
			group("nodes", list, &ls, del, leaf("nodes", "set", flagDef{"name", "", false}), leaf("nodes", "get"),
				group("routes", leaf("nodes routes", "set"))),
			group("auth", group("keys", leaf("auth keys", "create", flagDef{"expiry", "e", false}, flagDef{"reusable", "", true}))),
			group("check", leaf("check", "config")),
			group("policy", leaf("policy", "set")),
			leaf("", "t", flagDef{"aa", "a", true}, flagDef{"bb", "b", true}, flagDef{"xx", "x", false}),
		},
	}
	return root, t
}

func runCase(groupsRunnable bool, line []string) string {
	root, t := build(groupsRunnable)
	var log bytes.Buffer
	env := root.NewEnv(nil).MergeFlags(true)
	env.Log = &log
	err := command.Run(env, line)
	var b strings.Builder
	if t.res != nil {
		keys := make([]string, 0, len(t.res.flags))
		for k := range t.res.flags {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		fmt.Fprintf(&b, "-> %s args=%q", strings.TrimSpace(t.res.leaf), t.res.args)
		for _, k := range keys {
			fmt.Fprintf(&b, " %s=%s", strings.TrimPrefix(k, "root/"), t.res.flags[k])
		}
	}
	if err != nil {
		var ue command.UsageError
		typ := fmt.Sprintf("%T", err)
		if errors.As(err, &ue) {
			typ += fmt.Sprintf("{Env.Command=%s}", ue.Env.Command.Name)
		}
		if errors.Is(err, command.ErrRequestHelp) {
			typ += "(ErrRequestHelp)"
		}
		fmt.Fprintf(&b, " ERR %s: %q", typ, err.Error())
	}
	if log.Len() > 0 {
		s := log.String()
		if len(s) > 160 {
			s = s[:160] + "..."
		}
		fmt.Fprintf(&b, " LOG=%q", s)
	}
	return b.String()
}

var cases = []string{
	// short / long / attached
	"nodes list -o json", "nodes list -ojson", "nodes list -o=json", "nodes list --output=json",
	"nodes list --output json", "nodes list -output json", "nodes list --o json", "nodes list ---output json",
	// given twice, two names
	"nodes list -o json --output yaml",
	// D3 before / after
	"-c x nodes list", "nodes list -c x", "-o json nodes list", "nodes -o json list", "check config -o json",
	// interspersed and bools
	"nodes delete 12 --force", "nodes delete --force 12", "nodes delete --force=false 12", "nodes delete --force true 12",
	"nodes delete 12 --force=yes",
	// values starting with -
	"nodes list --sort -last-seen", "nodes list --columns -ip,-os", "nodes list --sort=-last-seen",
	// empty values
	`nodes set 12 --name ""`, "nodes set 12 --name=", "nodes set 12", "nodes set 12 --name",
	// verbatim values
	"nodes list --filter=owner=tag:ci --filter last-seen>30d", "nodes list --filter name:web,online=true",
	// positionals that look odd
	"policy set -", "nodes get hskey-auth-ab12cd-***", "nodes get -x", "nodes get -- -x",
	// -- semantics
	"t x -- -a", "t -- -a x", "nodes delete 12 -- --force", "nodes get -- -o", "nodes get 12 -- y",
	"-- nodes list", "nodes -- list",
	// grouped shorts
	"t -ab", "t -a -b", "t -ax1", "t -x1",
	// unknown flags
	"nodes list --bogus", "nodes delete 12 --bogus", "nodes delete --bogus 12", "nodes list -r", "--bogus nodes list",
	// unknown commands
	"frob", "nodes frob", "node ls", "nodes routes approve 1 2",
	// alias as copy
	"nodes ls --sort id",
	// help
	"", "nodes", "nodes routes", "nodes delete --help", "nodes delete -h", "nodes delete 12 -h", "-h nodes", "help",
	"nodes delete -- -h",
	// missing value at end
	"nodes list -o", "nodes list --sort",
	// auth keys create with -e attached
	"auth keys create alice -e24h --reusable", "auth keys create -e 90d alice",
}

func split(s string) []string {
	if s == "" {
		return nil
	}
	f := strings.Fields(s)
	for i, w := range f {
		if w == `""` {
			f[i] = ""
		}
	}
	return f
}

func main() {
	mode := "runnable-groups"
	if len(os.Args) > 1 {
		mode = os.Args[1]
	}
	switch mode {
	case "runnable-groups", "plain-groups":
		for _, c := range cases {
			fmt.Printf("%-48s %s\n", "`"+c+"`", runCase(mode == "runnable-groups", split(c)))
		}
	case "reuse":
		reuse()
	case "flax":
		flaxTag()
	case "patched":
		for _, c := range []string{"nodes delete 12 -- --force", "nodes get -- -o", "t x -- -a", "nodes get 12 -- y",
			"nodes delete 12 --bogus", "nodes list --bogus", "auth keys create --bogus alice", "nodes set 12 --name"} {
			fmt.Printf("%-36s %s\n", "`"+c+"`", patched(split(c)))
		}
	}
}

// patched shows two adapter-side fixes: split argv at the first "--" so the
// library never sees the tail, and recover the failing command's path from
// the last SetFlags call (parse errors carry no Env).
func patched(line []string) string {
	head, tail := line, []string(nil)
	for i, w := range line {
		if w == "--" {
			head, tail = line[:i], line[i+1:]
			break
		}
	}
	root, t := build(true)
	var last []string
	var walk func(c *command.C, path []string)
	walk = func(c *command.C, path []string) {
		p := append(append([]string(nil), path...), c.Name)
		if sf := c.SetFlags; sf != nil {
			c.SetFlags = func(env *command.Env, fs *flag.FlagSet) { last = p; sf(env, fs) }
		} else {
			c.SetFlags = func(*command.Env, *flag.FlagSet) { last = p }
		}
		for _, s := range c.Commands {
			walk(s, p)
		}
	}
	walk(root, nil)
	env := root.NewEnv(nil).MergeFlags(true)
	env.Log = new(bytes.Buffer)
	err := command.Run(env, head)
	if err != nil {
		return fmt.Sprintf("ERR at %q: %v", last, err)
	}
	args := append(t.res.args, tail...)
	for _, a := range t.res.args {
		if len(a) > 1 && a[0] == '-' {
			return fmt.Sprintf("ERR at %q: unknown flag %s (left as positional by the library)", last, a)
		}
	}
	return fmt.Sprintf("-> %s args=%q flags=%v", t.res.leaf, args, t.res.flags)
}

// reuse runs one tree twice: does state from the first run leak into the second?
func reuse() {
	root, t := build(true)
	for _, line := range []string{"nodes delete 12 --force", "nodes delete 13"} {
		env := root.NewEnv(nil).MergeFlags(true)
		err := command.Run(env, split(line))
		fmt.Printf("%-28s -> args=%q flags=%v err=%v isFlagSet(force) via leaf=%v\n", line, t.res.args, t.res.flags, err,
			root.Commands[0].Commands[2].Flags.Lookup("force") != nil)
	}
}

// flaxTag: does `flag:"config,c,Config file path"` (PR #2647) define -c?
func flaxTag() {
	var g struct {
		Config string `flag:"config,c,Config file path"`
	}
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	fs.SetOutput(new(bytes.Buffer))
	flax.MustBind(fs, &g)
	fs.VisitAll(func(f *flag.Flag) { fmt.Printf("flag name=%q usage=%q\n", f.Name, f.Usage) })
	fmt.Println("parse -c x:", fs.Parse([]string{"-c", "x"}))
	var spec struct {
		Expiry string `flag:"expiry" short:"e" help:"When the key ends"`
	}
	_, err := flax.Check(&spec)
	fmt.Println("flax.Check on a 001-style tag:", err)
}
