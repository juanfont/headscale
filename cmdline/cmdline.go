// Package cmdline reads a command line into the typed input struct of a
// command, and answers shell completion for the tree of commands.
//
// A command declares what it takes as a struct. Each field is one argument
// or one flag, named by a struct tag:
//
//	type setIn struct {
//		Node   string                     `arg:"node"`
//		Routes []netip.Prefix             `arg:"routes"`
//		Expiry cmdline.Opt[time.Duration] `flag:"expiry" short:"e" help:"When it ends"`
//		Force  bool                       `flag:"force" help:"Do not ask"`
//	}
//
// The tags are arg, flag, short, help and default. The type of the field
// says how its word is read:
//
//	string, bool, int…, uint…, float…   read by the library
//	a type with UnmarshalText           reads itself (encoding.TextUnmarshaler)
//	a type given to Reader              read by that function; it wins over the method
//	a type given to LateReader          read when the command runs, after the whole line is right
//	[]T                                 one word, a comma list of T
//	Opt[T]                              T, and whether it was given; as an argument it is optional
//	Repeat[T]                           a flag that may be given more than once
//
// A flag whose value is a bool takes no value word: --force, --force=true
// and --force=false. Every other flag is given once.
//
// The grammar: --name, --name=value, --name value, -x, -x=value, -x value.
// The word after a value flag is its value, whatever it looks like. Flags
// and arguments mix in any order; "--" ends the flags. Attached short values
// (-ovalue), grouped shorts (-ab) and abbreviations are unknown flags.
//
// The library has no help, no usage text and no meaning for any flag name.
// Parse reports the first mistake on the line as a *UsageError; the caller
// writes the sentence. The tree is readable as data through Info.
package cmdline

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline/reader"
)

// Node is one command of a tree: a Group or a Command[In].
type Node interface{ decl() decl }

// Group is a command that only leads to other commands. The root's Name is
// the program name.
type Group struct {
	Name     string
	Aliases  []string
	Help     string // one line; Tab shows it next to the name
	Flags    []any  // structs of flags that may be typed here, and below before the command; only the types are read
	Commands []Node
}

// Command is a command that runs. In is its input struct: the arguments, in
// field order, and the flags.
type Command[In any] struct {
	Name    string
	Aliases []string
	Help    string // one line; Tab shows it next to the name
	Flags   []any  // further structs of flags, for a layer above the command; only the types are read
	Run     func(ctx context.Context, in In) error
}

// decl is a Group or a Command with its input type erased.
type decl struct {
	name     string
	aliases  []string
	help     string
	flags    []any
	in       reflect.Type // nil for a group
	run      func(context.Context, any) error
	commands []Node
}

func (g Group) decl() decl {
	return decl{
		name:     g.Name,
		aliases:  g.Aliases,
		help:     g.Help,
		flags:    g.Flags,
		commands: g.Commands,
	}
}

func (c Command[In]) decl() decl {
	d := decl{
		name:    c.Name,
		aliases: c.Aliases,
		help:    c.Help,
		flags:   c.Flags,
		in:      reflect.TypeFor[In](),
	}
	if c.Run != nil {
		//nolint:forcetypeassert // the node of c builds only an In
		d.run = func(ctx context.Context, in any) error { return c.Run(ctx, in.(In)) }
	}

	return d
}

// Info describes one command as data: what a help text, a reference page
// or a did-you-mean needs.
type Info struct {
	Name     string
	Aliases  []string
	Help     string
	Path     []string // names from the root, the root's own left out
	Usage    string   // the root's name, Path, then <x> per argument and [x] per optional one
	Flags    []Flag   // the flags declared on this command, in field order
	Args     []Arg    // in field order
	Commands []*Info  // the commands of a group; none for a command that runs
}

// Flag describes one flag of a command.
type Flag struct {
	Name     string // the long name, without dashes
	Short    string // one letter, or ""
	Help     string
	Type     reflect.Type // what one value is read as: T for T, []T, Opt[T] and Repeat[T]
	Bool     bool         // takes no value word
	List     bool         // one value is a comma list
	Repeat   bool         // may be given more than once
	Optional bool         // an Opt[T]: the command sees whether it was given
	Late     bool         // read by a LateReader
	Default  string       // the default tag
}

// Arg describes one argument of a command.
type Arg struct {
	Name     string
	Help     string
	Type     reflect.Type // as Flag.Type
	List     bool         // a comma list
	Optional bool         // an Opt[T]: may be left out
	Late     bool         // read by a LateReader
}

// Tree is a checked tree of commands. It is read-only: Parse, Complete and
// Serve may run at the same time.
type Tree struct {
	root  *node
	nodes map[*reader.Command]*node
}

// node is one command, ready to read a line.
type node struct {
	info  *Info
	low   *reader.Command
	parts []reflect.Type    // the structs a line that ends here fills
	flags map[string]*field // by long name: every flag a line that ends here may hold
	spell map[string]string // "--name" and "-x" to the long name
	args  []*field
	in    reflect.Type
	run   func(context.Context, any) error
}

type builder struct {
	readers map[reflect.Type]readFn
	late    map[reflect.Type]lateFn
	nodes   map[*reader.Command]*node
	errs    []error
}

// bad adds one problem of New: a sentence that no caller matches.
//
//nolint:err113,goprintffuncname
func (b *builder) bad(
	format string,
	a ...any,
) {
	b.errs = append(b.errs, fmt.Errorf(format, a...))
}

// New checks the tree and makes it ready. The error names every problem:
// a struct that cannot be read (a field with no tag or an unknown one, a
// type with no reader, a default that does not read), a name, alias, flag or
// short that is used twice or cannot be typed, a group with no command, a
// command with no Run. A program stops on it at start; a test that builds
// the tree finds it before that.
func New(root Node, opts ...Option) (*Tree, error) {
	b := &builder{
		readers: map[reflect.Type]readFn{},
		late:    map[reflect.Type]lateFn{},
		nodes:   map[*reader.Command]*node{},
	}

	for _, o := range opts {
		if o.apply != nil {
			o.apply(b)
		}
	}

	if null(root) {
		return nil, errNoRoot
	}

	t := &Tree{root: b.build(root, nil, nil), nodes: b.nodes}
	if t.root.info.Name == "" {
		b.bad("the root has no name")
	}

	err := reader.Check(t.root.low)
	if err != nil {
		b.errs = append(b.errs, err)
	}

	if len(b.errs) > 0 {
		return nil, errors.Join(b.errs...)
	}

	return t, nil
}

// Root returns the description of the root; its Commands lead to the rest.
func (t *Tree) Root() *Info { return t.root.info }

// null: a nil Node, or a nil *Group or *Command in one, whose decl would
// panic.
func null(n Node) bool {
	v := reflect.ValueOf(n)
	return n == nil || v.Kind() == reflect.Pointer && v.IsNil()
}

// build makes the node of n. above holds the names down to its parent;
// scope the flags of the groups above, which may be typed before n is
// reached.
func (b *builder) build(n Node, above []string, scope []*field) *node {
	d := n.decl()
	names := append(slices.Clip(above), d.name)
	at := strings.Join(names, " ")
	nd := &node{
		info: &Info{
			Name:    d.name,
			Aliases: slices.Clone(d.aliases),
			Help:    d.help,
			Path:    names[1:],
			Usage:   at,
		},
		low: &reader.Command{
			Name:    d.name,
			Aliases: slices.Clone(d.aliases),
			Help:    d.help,
		},
		flags: map[string]*field{},
		spell: map[string]string{},
		in:    d.in,
		run:   d.run,
	}
	b.nodes[nd.low] = nd

	var own []*field

	if d.in != nil {
		var flags []*field

		flags, nd.args = b.fields(at, d.in, true)
		own = append(own, flags...)
		nd.parts = append(nd.parts, d.in)
	}

	for _, s := range d.flags {
		t := reflect.TypeOf(s)
		if t == nil || t.Kind() != reflect.Struct {
			b.bad("%s: Flags holds %v, which is no struct", at, t)
			continue
		}

		flags, _ := b.fields(at, t, false)
		own = append(own, flags...)
		nd.parts = append(nd.parts, t)
	}

	for _, f := range own {
		nd.info.Flags = append(nd.info.Flags, f.flag())
		nd.low.Flags = append(nd.low.Flags, f.low(b.nodes))
	}

	for _, a := range nd.args {
		nd.info.Args = append(
			nd.info.Args,
			Arg{
				Name:     a.name,
				Help:     a.help,
				Type:     a.elem,
				List:     a.list,
				Optional: a.opt,
				Late:     a.late != nil,
			},
		)

		nd.low.Args = append(nd.low.Args, a.completer(b.nodes))
		if a.opt {
			nd.info.Usage += " [" + a.name + "]"
		} else {
			nd.info.Usage += " <" + a.name + ">"
		}
	}

	all := own
	if d.in == nil { // a line may end at a group: it then holds the flags of the groups above too
		all = slices.Clone(scope)
		for _, f := range own {
			i := slices.IndexFunc(
				scope,
				func(s *field) bool { return s.name == f.name },
			)
			switch {
			case i < 0:
				all = append(all, f)
			case scope[i].part != f.part:
				b.bad(
					"%s: --%s is declared by %s here and by %s above",
					at,
					f.name,
					f.part,
					scope[i].part,
				)
			}
		}

		nd.parts = nil
		for _, f := range all {
			if !slices.Contains(nd.parts, f.part) {
				nd.parts = append(nd.parts, f.part)
			}
		}
	}

	for _, f := range all {
		nd.flags[f.name] = f

		nd.spell["--"+f.name] = f.name
		if f.short != "" {
			nd.spell["-"+f.short] = f.name
		}
	}

	switch {
	case d.in != nil && d.run == nil:
		b.bad("%s: Run is missing", at)
	case d.in == nil && len(d.commands) == 0:
		b.bad("%s: a group needs a command", at)
	}

	for _, c := range d.commands {
		if null(c) {
			b.bad("%s: a command is nil", at)
			continue
		}

		ch := b.build(c, names, all)
		nd.info.Commands = append(nd.info.Commands, ch.info)
		nd.low.Commands = append(nd.low.Commands, ch.low)
	}

	return nd
}
