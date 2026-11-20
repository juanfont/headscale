// Package headscale is Headscale's layer over the typed cmdline library, as
// far as the kit models it: 001's command spec and builder, cut down. A
// spec names its input struct; the builder adds the flags that 001 derives
// (--output, --config, --help, --force, the list flags), places Headscale's
// own mistakes on the line, answers help and --version, writes the argument
// count sentence and runs the command. Reading values, lists, bool words,
// the repeat rule and the count itself are the library's.
package headscale

import (
	"context"
	"errors"
	"strings"

	"spike/cmdline"
)

// Spec is 001's command.Spec, cut down. The usage line is not written: the
// library makes it from In (D47).
type Spec[In any] struct {
	Path    string   // the command words: "nodes routes set"
	Short   string   // one line
	Aliases []string //
	Confirm string   // the prompt; when set the builder adds --force
	Output  bool     // the builder adds --output/-o
	Config  bool     // the builder adds --config/-c
	Run     func(context.Context, In) error
}

// Def is a spec ready for a tree.
type Def struct {
	path []string
	node cmdline.Node
}

// New makes the command of a spec, with the flags its spec derives.
func New[In any](s Spec[In]) Def { return def(s) }

// NewList is New for a list command, 001's ListSpec: the builder adds
// --columns, --sort, --filter and --list-columns for the columns of R.
func NewList[In any, R Row](s Spec[In]) Def { return def(s, listFlags[R]{}) }

func def[In any](s Spec[In], flags ...any) Def {
	path := strings.Fields(s.Path)
	if s.Confirm != "" {
		flags = append([]any{forceFlags{}}, flags...)
	}
	if s.Output {
		flags = append(flags, outputFlags{})
	}
	if s.Config {
		flags = append(flags, configFlags{})
	}
	flags = append(flags, helpFlags{})
	return Def{path, cmdline.Command[In]{Name: path[len(path)-1], Aliases: s.Aliases, Help: s.Short, Flags: flags, Run: s.Run}}
}

// The flags of the builder. Each is a struct of its own, so a command takes
// the ones its spec gives it and the builder reads them with cmdline.Get.
type (
	helpFlags struct {
		Help bool `flag:"help" short:"h" help:"Show help"`
	}
	versionFlags struct {
		Version bool `flag:"version" help:"Print the version"`
	}
	outputFlags struct {
		Output Format `flag:"output" short:"o" help:"Output format: json"`
	}
	configFlags struct {
		Config cmdline.Path `flag:"config" short:"c" help:"Config file to use"`
	}
	forceFlags struct {
		Force bool `flag:"force" help:"Do not ask"`
	}
	listFlags[R Row] struct {
		Columns     []Column[R]               `flag:"columns" help:"Columns to show"`
		Sort        Column[R]                 `flag:"sort" help:"Column to sort by"`
		Filter      cmdline.Repeat[[]Cond[R]] `flag:"filter" help:"Rows to keep"`
		ListColumns bool                      `flag:"list-columns" help:"List the columns"`
	}
)

// Format is the value of --output. It takes only json, so a wrong format
// is a mistake of the line, with its place on it, like any other value.
type Format string

func (f *Format) UnmarshalText(b []byte) error {
	if string(b) != "json" {
		return errors.New("is not json")
	}
	*f = Format(b)
	return nil
}

func (Format) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, "json"), cmdline.NoFiles
}

// Row is the row type of a list: it names its columns, as 001's
// table.Columns[Row] does.
type Row interface{ Columns() []string }

// Column is one column of R, as --columns and --sort take it: it may carry
// a + or - sign.
type Column[R Row] string

func (c *Column[R]) UnmarshalText(b []byte) error { *c = Column[R](b); return nil }

func (Column[R]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	sign := ""
	if prefix != "" && (prefix[0] == '+' || prefix[0] == '-') {
		sign, prefix = prefix[:1], prefix[1:]
	}
	var r R
	words := cmdline.Words(prefix, r.Columns()...)
	for i := range words {
		words[i] = sign + words[i]
	}
	return words, cmdline.NoFiles
}

// Cond is one condition of --filter: a column of R, an operator, a value.
// Tab completes the column and leaves no space, because the operator follows.
type Cond[R Row] string

func (c *Cond[R]) UnmarshalText(b []byte) error { *c = Cond[R](b); return nil }

func (Cond[R]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	var r R
	return cmdline.Words(prefix, r.Columns()...), cmdline.NoFiles | cmdline.NoSpace
}

// WordList names the words of a Text.
type WordList interface{ Words() []string }

// Text is free text that offers the words of W on Tab.
type Text[W WordList] string

func (t *Text[W]) UnmarshalText(b []byte) error { *t = Text[W](b); return nil }

func (Text[W]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	var w W
	return cmdline.Words(prefix, w.Words()...), cmdline.NoFiles
}

// Tree is a tree of specs, built once and read-only.
type Tree struct {
	*cmdline.Tree
}

// Build makes the tree of defs under the root: the groups come from the
// paths, the root takes -h, --version, -o and -c (D3, D7).
func Build(program string, shorts map[string]string, defs ...Def) (*Tree, error) {
	type group struct {
		g    *cmdline.Group
		subs map[string]*group
		kids []any // *group or cmdline.Node, in spec order
	}
	root := &group{g: &cmdline.Group{Name: program, Help: shorts[""], Flags: []any{helpFlags{}, versionFlags{}, outputFlags{}, configFlags{}}}, subs: map[string]*group{}}
	for _, d := range defs {
		at := root
		for i, w := range d.path[:len(d.path)-1] {
			sub := at.subs[w]
			if sub == nil {
				sub = &group{g: &cmdline.Group{Name: w, Help: shorts[strings.Join(d.path[:i+1], " ")], Flags: []any{helpFlags{}}}, subs: map[string]*group{}}
				at.subs[w] = sub
				at.kids = append(at.kids, sub)
			}
			at = sub
		}
		at.kids = append(at.kids, d.node)
	}
	var node func(*group) cmdline.Node
	node = func(g *group) cmdline.Node {
		for _, k := range g.kids {
			if sub, ok := k.(*group); ok {
				k = node(sub)
			}
			g.g.Commands = append(g.g.Commands, k.(cmdline.Node))
		}
		return *g.g
	}
	t, err := cmdline.New(node(root))
	return &Tree{t}, err
}
