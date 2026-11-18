// Package kit is the shared test kit for the Headscale CLI framework
// bake-off: a cut-down, framework-free copy of 001's command layer, a tree
// of specs, the one interface an adapter implements, and a conformance suite.
package kit

import (
	"context"
	"errors"
	"fmt"
	"io"
	"maps"
	"reflect"
	"slices"
	"strconv"
	"strings"
)

// Program is the name of the binary in argv[0], help and completion scripts.
const Program = "headscale"

// Kind says how a flag reads its value.
type Kind int

const (
	Bool    Kind = iota // "--x" means true; "--x=true" and "--x=false" are accepted (D9)
	String              // exactly one value; it may be "" or start with "-"
	Strings             // may repeat; every value is kept, in order (only --filter, D6)
)

func (k Kind) String() string { return [...]string{"bool", "string", "strings"}[k] }

// Flag is one flag of one command, as the adapter registers it.
type Flag struct {
	Name   string   // long name, without dashes
	Short  string   // one letter, or ""
	Kind   Kind     //
	Global bool     // may also be given before the subcommand (D3); listed on the root and on each leaf that takes it
	Values []string // what Tab offers for the value; nil means nothing
}

// Arg is one positional of a leaf.
type Arg struct {
	Name     string
	Optional bool     // [x] in Use
	Values   []string // what Tab offers; nil means nothing
	File     bool     // Tab offers file names
}

// Command is one node of the tree. The root has an empty Path.
type Command struct {
	Path    []string // canonical names from the root
	Aliases []string // other names for the last word of Path
	Leaf    bool     // false: a group, which never runs
	Flags   []Flag
	Args    []Arg // leaves only
}

// Tree is the flat, framework-neutral description an adapter reads.
// Commands holds the root first, then every group before its children, in
// spec order. Build a fresh one with NewTree for every run.
type Tree struct {
	Commands []Command
	defs     map[string]Def    // leaf path joined by " " -> spec
	shorts   map[string]string // letter -> long name, one meaning in the tree
}

// Stdio is the three streams of one run.
type Stdio struct {
	In       io.Reader
	Out, Err io.Writer
}

// Call is what the adapter hands to Tree.Exec once the framework has parsed argv.
type Call struct {
	Path  []string            // the command reached; names or aliases
	Flags map[string][]string // flags that were given, by long name (or letter): every value, in order; bools "true"/"false"
	Args  []string            // positionals, in order, after "--" resolution
}

// ErrKind names a usage error. The kit writes the text for every kind (D4).
type ErrKind string

const (
	UnknownCommand ErrKind = "unknown-command" // Word: the word that is no command under Path
	UnknownFlag    ErrKind = "unknown-flag"    // Word: the flag as typed ("--exp", "-r")
	MissingValue   ErrKind = "missing-value"   // Word: the flag that has no value
	FlagRepeated   ErrKind = "flag-repeated"   // Word: the flag given more than once (D6)
	BadValue       ErrKind = "bad-value"       // Word: the flag whose value is wrong ("--force=maybe")
	ArgCount       ErrKind = "arg-count"       // raised by the kit only; Word: the count sentence
)

// UsageError is the one error type for a command line the kit cannot run.
// Adapters return it for parse errors; Exec returns it for the checks it owns.
type UsageError struct {
	Kind ErrKind
	Path []string // the command reached when parsing stopped (names or aliases)
	Word string
}

func (e *UsageError) Error() string {
	cmd := strings.TrimSpace(Program + " " + strings.Join(e.Path, " "))
	switch e.Kind {
	case UnknownCommand:
		return fmt.Sprintf("unknown command %q for %q", e.Word, cmd)
	case UnknownFlag:
		return fmt.Sprintf("unknown flag %s for %q", e.Word, cmd)
	case MissingValue:
		return fmt.Sprintf("flag %s needs a value", e.Word)
	case FlagRepeated:
		return fmt.Sprintf("flag %s is given more than once; give a list as one comma-separated value", e.Word)
	case BadValue:
		return fmt.Sprintf("flag %s has a value it cannot take", e.Word)
	}
	return fmt.Sprintf("`%s` %s.", strings.Join(e.Path, " "), e.Word)
}

// Completion is the answer to one Tab press.
type Completion struct {
	Words []string // candidates for the last word; a "\t" and what follows are ignored
	Files bool     // the shell should also offer file names
}

// Adapter is the one thing each framework spike writes. It must be safe for
// concurrent use: the suite calls it from many goroutines at once.
type Adapter interface {
	// Run parses argv (without the program name) against t. When the framework
	// reaches a command (a leaf, a group, help or --version) the adapter calls
	// t.Exec exactly once, with ctx and std, and returns what Exec returned.
	// When the framework refuses argv, it returns a *UsageError and calls
	// nothing. The framework itself writes nothing to std and never exits.
	Run(ctx context.Context, t *Tree, argv []string, std Stdio) error
	// Complete answers Tab (D1): argv is the words after the program name; the
	// last one is the word being completed ("" for a new word). It must be the
	// code path the completion script reaches through the binary, and it must
	// not run a command.
	Complete(ctx context.Context, t *Tree, argv []string) (Completion, error)
	// Script writes the completion script for "bash", "zsh", "fish" or "powershell".
	Script(t *Tree, shell string, w io.Writer) error
}

// Spec is a cut-down command.Spec of 001: data only, no framework type.
// In is the input struct. Its fields carry `arg:"name"` (a positional, in
// Use order) or `flag:"name"` with an optional `short:"x"`, and an optional
// `complete:"file"` or `complete:"a b c"` for Tab. Field types:
//
//	string    reads the value
//	*string   nil when the flag is not given, so --name "" differs from no --name
//	bool      "--x", "--x=true", "--x=false"
//	[]string  one comma-separated value (never repeated, D6)
type Spec[In any] struct {
	Use     string   // path words, then <arg> or [arg]: "nodes routes set <node> <routes>"
	Aliases []string // only ls, rm, approve in 001
	Confirm string   // the prompt; when set the builder adds --force
	Output  bool     // the builder adds --output/-o (001 has no field for this, C6)
	Config  bool     // the builder adds --config/-c (C6)
	Columns []string // set on a list: the builder adds --columns, --sort, --filter, --list-columns
	Run     func(context.Context, In) error
}

// Def is a Spec with its input type erased, ready for NewTree.
type Def struct {
	use, aliases   []string
	confirm        bool
	output, config bool
	columns        []string
	in             reflect.Type
	run            func(context.Context, any) error
}

// New checks nothing at compile time that 001's command.New checks at start;
// NewTree does the checks.
func New[In any](s Spec[In]) Def {
	return Def{
		use: strings.Fields(s.Use), aliases: s.Aliases, confirm: s.Confirm != "",
		output: s.Output, config: s.Config, columns: s.Columns,
		in:  reflect.TypeFor[In](),
		run: func(ctx context.Context, in any) error { return s.Run(ctx, in.(In)) },
	}
}

var (
	helpFlag    = Flag{Name: "help", Short: "h", Kind: Bool}
	outputFlag  = Flag{Name: "output", Short: "o", Kind: String, Global: true, Values: []string{"json"}}
	configFlag  = Flag{Name: "config", Short: "c", Kind: String, Global: true}
	versionFlag = Flag{Name: "version", Kind: Bool}
)

// NewTree builds the kit's tree from its specs. It panics on a wrong spec,
// as 001's command.New stops the program.
func NewTree() *Tree { return build(defs) }

func build(defs []Def) *Tree {
	t := &Tree{defs: map[string]Def{}, shorts: map[string]string{}}
	t.Commands = []Command{{Flags: []Flag{helpFlag, versionFlag, outputFlag, configFlag}}}
	for _, d := range defs {
		i := slices.IndexFunc(d.use, func(w string) bool { return w[0] == '<' || w[0] == '[' })
		if i < 0 {
			i = len(d.use)
		}
		path, use := d.use[:i], d.use[i:]
		for n := 1; n < len(path); n++ {
			if _, ok := t.cmd(path[:n]); !ok {
				t.Commands = append(t.Commands, Command{Path: path[:n], Flags: []Flag{helpFlag}})
			}
		}
		c := Command{Path: path, Aliases: d.aliases, Leaf: true}
		for f := range d.in.Fields() {
			if name, ok := f.Tag.Lookup("arg"); ok {
				if len(c.Args) >= len(use) || strings.Trim(use[len(c.Args)], "<>[]") != name {
					panic(fmt.Sprintf("%v: field %s is not the next argument in Use", path, f.Name))
				}
				a := Arg{Name: name, Optional: use[len(c.Args)][0] == '['}
				a.File, a.Values = complete(f.Tag)
				c.Args = append(c.Args, a)
			} else if name, ok := f.Tag.Lookup("flag"); ok {
				fl := Flag{Name: name, Short: f.Tag.Get("short"), Kind: String}
				if f.Type.Kind() == reflect.Bool {
					fl.Kind = Bool
				}
				_, fl.Values = complete(f.Tag)
				c.Flags = append(c.Flags, fl)
			} else {
				panic(fmt.Sprintf("%v: field %s has no arg or flag tag", path, f.Name))
			}
		}
		if len(c.Args) != len(use) {
			panic(fmt.Sprintf("%v: Use names %d arguments, the input struct %d", path, len(use), len(c.Args)))
		}
		if d.confirm {
			c.Flags = append(c.Flags, Flag{Name: "force", Kind: Bool})
		}
		if d.columns != nil {
			c.Flags = append(c.Flags,
				Flag{Name: "columns", Kind: String, Values: d.columns},
				Flag{Name: "sort", Kind: String, Values: d.columns},
				Flag{Name: "filter", Kind: Strings, Values: d.columns},
				Flag{Name: "list-columns", Kind: Bool})
		}
		if d.output {
			c.Flags = append(c.Flags, outputFlag)
		}
		if d.config {
			c.Flags = append(c.Flags, configFlag)
		}
		c.Flags = append(c.Flags, helpFlag)
		t.Commands = append(t.Commands, c)
		t.defs[strings.Join(path, " ")] = d
	}
	for _, c := range t.Commands {
		for _, f := range c.Flags {
			if f.Short == "" {
				continue
			}
			if long, ok := t.shorts[f.Short]; ok && long != f.Name {
				panic(fmt.Sprintf("short -%s means --%s and --%s", f.Short, long, f.Name))
			}
			t.shorts[f.Short] = f.Name
		}
	}
	return t
}

func complete(tag reflect.StructTag) (file bool, values []string) {
	v := tag.Get("complete")
	if v == "file" {
		return true, nil
	}
	return false, strings.Fields(v)
}

func (t *Tree) cmd(path []string) (*Command, bool) {
	for i := range t.Commands {
		if slices.Equal(t.Commands[i].Path, path) {
			return &t.Commands[i], true
		}
	}
	return nil, false
}

// find resolves names and aliases, word by word, to a command.
func (t *Tree) find(words []string) (*Command, bool) {
	var cur []string
	for _, w := range words {
		next := ""
		for _, c := range t.Commands {
			if len(c.Path) == len(cur)+1 && slices.Equal(c.Path[:len(cur)], cur) &&
				(c.Path[len(cur)] == w || slices.Contains(c.Aliases, w)) {
				next = c.Path[len(cur)]
			}
		}
		if next == "" {
			return nil, false
		}
		cur = append(slices.Clone(cur), next)
	}
	return t.cmd(cur)
}

// long turns "--exp=1", "-o", "o" or "output" into a long name.
func (t *Tree) long(word string) string {
	name, _, _ := strings.Cut(strings.TrimLeft(word, "-"), "=")
	if l, ok := t.shorts[name]; ok && len(name) == 1 {
		return l
	}
	return name
}

func flagOf(c *Command, name string) (Flag, bool) {
	i := slices.IndexFunc(c.Flags, func(f Flag) bool { return f.Name == name })
	if i < 0 {
		return Flag{}, false
	}
	return c.Flags[i], true
}

// Exec is the builder of 001, cut down: the adapter calls it once per run
// from the framework's action. It refuses flags the command does not take
// (so a global -o on `check config` fails here, D3), repeated flags (D6) and
// bad bools, then answers help and --version, checks the argument count,
// fills the input struct and calls Run.
func (t *Tree) Exec(ctx context.Context, std Stdio, c Call) error {
	rec, _ := ctx.Value(recKey{}).(*recorder)
	if rec == nil {
		return errors.New("kit: Exec got a context without the kit's value: pass the caller's context through")
	}
	rec.mu.Lock()
	rec.calls++
	rec.mu.Unlock()
	cmd, ok := t.find(c.Path)
	if !ok {
		return fmt.Errorf("kit: Exec got a path that is not in the tree: %q", c.Path)
	}
	o := Outcome{Kind: "run", Path: cmd.Path, Args: c.Args, Flags: map[string][]string{}}
	for k, vs := range c.Flags {
		if t.long(k) == "help" && slices.Contains(vs, "true") {
			c.Flags = nil // -h wins over every check below (R53)
			o = Outcome{Kind: "help", Path: cmd.Path}
		}
	}
	for _, k := range slices.Sorted(maps.Keys(c.Flags)) {
		vs := c.Flags[k]
		name := t.long(k)
		f, ok := flagOf(cmd, name)
		if !ok {
			if g, _ := flagOf(&t.Commands[0], name); g.Global && !cmd.Leaf {
				continue // a global flag before the subcommand of a group: nothing to run it
			}
			return &UsageError{UnknownFlag, cmd.Path, "--" + name}
		}
		if len(vs) > 1 && f.Kind != Strings {
			return &UsageError{FlagRepeated, cmd.Path, "--" + name}
		}
		if f.Kind == Bool {
			b, err := strconv.ParseBool(vs[0])
			if err != nil {
				return &UsageError{BadValue, cmd.Path, "--" + name}
			}
			vs = []string{strconv.FormatBool(b)}
		}
		o.Flags[name] = slices.Clone(vs)
	}
	asked := func(name string) bool { return slices.Equal(o.Flags[name], []string{"true"}) }
	switch {
	case o.Kind == "help":
	case asked("version"):
		o = Outcome{Kind: "version"}
	case !cmd.Leaf && len(c.Args) == 0:
		o = Outcome{Kind: "help", Path: cmd.Path} // D10: a group alone is help, as the root alone
	case !cmd.Leaf:
		w := ""
		if len(c.Args) > 0 {
			w = c.Args[0]
		}
		return &UsageError{UnknownCommand, cmd.Path, w}
	default:
		if err := argCount(cmd, len(c.Args)); err != nil {
			return err
		}
		d := t.defs[strings.Join(cmd.Path, " ")]
		in := reflect.New(d.in).Elem()
		arg := 0
		for i := range d.in.NumField() {
			f := d.in.Field(i)
			if _, ok := f.Tag.Lookup("arg"); ok {
				if arg < len(c.Args) {
					set(in.Field(i), c.Args[arg])
				}
				arg++
			} else if vs := o.Flags[f.Tag.Get("flag")]; vs != nil {
				set(in.Field(i), vs[0])
			}
		}
		if err := d.run(ctx, in.Interface()); err != nil {
			return err
		}
	}
	rec.mu.Lock()
	rec.outcome = o.String()
	rec.mu.Unlock()
	_, err := fmt.Fprintln(std.Out, o.String())
	return err
}

func argCount(c *Command, n int) error {
	minN := 0
	for _, a := range c.Args {
		if !a.Optional {
			minN++
		}
	}
	maxN := len(c.Args)
	plural := func(n int) string {
		if n == 1 {
			return "1 argument"
		}
		return strconv.Itoa(n) + " arguments"
	}
	switch {
	case n >= minN && n <= maxN:
		return nil
	case maxN == 0:
		return &UsageError{ArgCount, c.Path, fmt.Sprintf("takes no arguments, got %d", n)}
	case minN == maxN:
		return &UsageError{ArgCount, c.Path, fmt.Sprintf("needs %s, got %d", plural(minN), n)}
	case n > maxN:
		return &UsageError{ArgCount, c.Path, fmt.Sprintf("takes at most %s, got %d", plural(maxN), n)}
	}
	return &UsageError{ArgCount, c.Path, fmt.Sprintf("needs at least %s, got %d", plural(minN), n)}
}

func set(v reflect.Value, s string) {
	switch v.Kind() {
	case reflect.Bool:
		v.SetBool(s == "true")
	case reflect.Pointer:
		v.Set(reflect.ValueOf(&s))
	case reflect.Slice:
		v.Set(reflect.ValueOf(strings.Split(s, ",")))
	default:
		v.SetString(s)
	}
}
