package command

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
)

// Node is one entry of the tree: a [Group], or a command made by [New] or
// [NewList].
type Node interface{ isNode() }

// Group is a command that only leads to other commands.
type Group struct {
	Name  string
	Short string
	// OldNames are the paths this group had before the redesign, such as
	// "preauthkeys".
	OldNames []string
	Commands []Node
}

func (Group) isNode() {}

// leaf is a command as the builder keeps it, with its types erased into
// closures.
type leaf struct {
	name, short, long          string
	example, aliases, oldNames []string

	local, output, config bool
	// own is a result that is the CLI's own object, not one of the API.
	own bool
	// server reports whether this line talks to the server.
	server func(*cmdline.Line) bool
	check  func() error
	cmd    func(flags []any) cmdline.Node
}

func (*leaf) isNode() {}

// The flags of the builder, each a struct of its own, so a command takes
// the ones its spec gives it and the builder reads them with cmdline.Get.
type (
	helpFlags struct {
		Help bool `flag:"help" help:"Show this help" short:"h"`
	}
	versionFlags struct {
		Version bool `flag:"version" help:"Print the version line"`
	}
	outputFlags struct {
		Output format `flag:"output" help:"Output format: json (the API object)" short:"o"`
	}
	ownOutputFlags struct {
		Output format `flag:"output" help:"Output format: json" short:"o"`
	}
	configFlags struct {
		Config Path `flag:"config" help:"Config file" short:"c"`
	}
)

var (
	errFormat    = errors.New("the only format is json")
	errNoRun     = errors.New("no Run")
	errNoShow    = errors.New("a result and neither Columns nor Done to show it")
	errNoColumns = errors.New("a list with no columns")
	errBoth      = errors.New("both Columns and Done; Done is printed in place of the sheet")
	errNoDefault = errors.New("a list with no Default column")
)

// specError is a spec that is wrong, named by its path.
type specError string

func (e specError) Error() string { return string(e) }

// format is the value of --output. It takes only json, so a wrong format
// is a mistake of the line, with its place on it.
type format string

func (f *format) UnmarshalText(b []byte) error {
	if string(b) != "json" {
		return errFormat
	}

	*f = format(b)

	return nil
}

func (format) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, "json"), cmdline.NoFiles
}

// New makes the command of a spec.
func New[In, Out any](s Spec[In, Out]) Node {
	noOut := reflect.TypeFor[Out]() == reflect.TypeFor[NoOutput]()

	l := common(s.Name, s.Short, s.Long, s.Example, s.Aliases, s.OldNames, s.Local, s.NeedsServer, s.ReadsConfig)
	l.output = !noOut || !s.Local || s.NeedsServer != nil
	l.own = !noOut && s.Local && s.NeedsServer == nil
	l.check = func() error {
		var errs []error

		if s.Run == nil {
			errs = append(errs, errNoRun)
		}

		switch {
		case !noOut && s.Columns == nil && s.Done == nil:
			errs = append(errs, errNoShow)
		case s.Columns != nil && s.Done != nil:
			errs = append(errs, errBoth)
		}

		return errors.Join(append(errs, s.Columns.Check())...)
	}
	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{Name: s.Name, Aliases: s.Aliases, Help: s.Short, Flags: flags, Run: func(ctx context.Context, in In) error {
			c := ctxOf(ctx)

			out, err := s.Run(c, in)
			if err != nil {
				return flagsOf[In](err)
			}

			return printOne(c, out, s.Columns, func() string {
				if s.Done == nil {
					return ""
				}

				return s.Done(in, out, c.Now())
			})
		}}
	}

	return l
}

// NewList makes the command of a list spec.
func NewList[In, Row any](s ListSpec[In, Row]) Node {
	l := common(s.Name, s.Short, s.Long, s.Example, s.Aliases, s.OldNames, s.Local, s.NeedsServer, s.ReadsConfig)
	l.output = true
	l.check = func() error {
		var errs []error

		if s.Run == nil {
			errs = append(errs, errNoRun)
		}

		switch {
		case len(s.Columns) == 0:
			errs = append(errs, errNoColumns)
		case !slices.ContainsFunc(s.Columns, func(c table.Column[Row]) bool { return c.Default }):
			errs = append(errs, errNoDefault)
		}

		return errors.Join(append(errs, s.Columns.Check())...)
	}
	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{Name: s.Name, Aliases: s.Aliases, Help: s.Short, Flags: flags, Run: func(ctx context.Context, in In) error {
			c := ctxOf(ctx)

			rows, err := s.Run(c, in)
			if err != nil {
				return err
			}

			return printList(c, rows, s.Columns.Pick(nil))
		}}
	}

	return l
}

func common[In any](name, short, long string, example, aliases, oldNames []string, local bool, needs func(In) bool, readsConfig bool) *leaf {
	return &leaf{
		name: name, short: short, long: long, example: example, aliases: aliases, oldNames: oldNames,
		local:  local,
		config: !local || needs != nil || readsConfig,
		server: func(line *cmdline.Line) bool {
			if !local {
				return true
			}

			if needs == nil {
				return false
			}

			in, _ := cmdline.Get[In](line)

			return needs(in)
		},
	}
}

// flags are the structs of flags the builder gives the command: --output
// and --config as its spec derives them, and --help.
func (l *leaf) flags() []any {
	var f []any

	switch {
	case l.output && l.own:
		f = append(f, ownOutputFlags{})
	case l.output:
		f = append(f, outputFlags{})
	}

	if l.config {
		f = append(f, configFlags{})
	}

	return append(f, helpFlags{})
}

// Tree is a checked tree of commands. It is read-only, so runs in parallel
// may share one, but tests build one per case.
type Tree struct {
	parser *cmdline.Tree
	name   string
	short  string
	leaves map[string]*leaf
	groups map[string]Group
	// oldNames leads an old path to the path of today.
	oldNames map[string]string
	// spellings leads every flag of the tree, as it can be typed ("--force",
	// "-o"), to its long name, which messages use. --version is not one:
	// on a command line it is an unknown flag.
	spellings map[string]string
}

// rootOnly is the flag that only the root takes.
const rootOnly = "version"

var allowedAliases = []string{"ls", "rm", "approve"}

// Build checks every spec and makes the tree. The error names every
// command and field that is wrong.
func Build(name, short string, nodes ...Node) (*Tree, error) {
	return build(name, short, allowedAliases, lookups, nodes...)
}

// build is Build with the aliases a tree may use and the parser's options
// (the lookups): the tests of the grammar need trees with other aliases
// than Headscale's.
func build(name, short string, aliases []string, opts []cmdline.Option, nodes ...Node) (*Tree, error) {
	t := &Tree{
		name: name, short: short,
		leaves: map[string]*leaf{}, groups: map[string]Group{},
		oldNames: map[string]string{}, spellings: map[string]string{},
	}

	var errs []error

	var build func(path []string, n Node) cmdline.Node

	build = func(path []string, n Node) cmdline.Node {
		at := strings.Join(path, " ")
		bad := func(format string, a ...any) {
			errs = append(errs, specError(at+": "+fmt.Sprintf(format, a...)))
		}

		for _, old := range oldNamesOf(n) {
			if other, ok := t.oldNames[old]; ok {
				bad("old name %q is also the old name of %s", old, other)
			}

			t.oldNames[old] = at
		}

		switch n := n.(type) {
		case Group:
			if n.Short == "" {
				bad("no Short")
			}

			t.groups[at] = n

			g := cmdline.Group{Name: n.Name, Help: n.Short, Flags: []any{helpFlags{}}}
			for _, c := range n.Commands {
				g.Commands = append(g.Commands, build(append(slices.Clip(path), nameOf(c)), c))
			}

			return g
		case *leaf:
			for _, f := range [][2]string{{"Name", n.name}, {"Short", n.short}, {"Long", n.long}} {
				if f[1] == "" {
					bad("no %s", f[0])
				}
			}

			if len(n.example) == 0 {
				bad("no Example")
			}

			for _, a := range n.aliases {
				if !slices.Contains(aliases, a) {
					bad("alias %q is none of %v", a, aliases)
				}
			}

			err := n.check()
			if err != nil {
				bad("%v", err)
			}

			t.leaves[at] = n

			return n.cmd(n.flags())
		}

		bad("%T is no node", n)

		return nil
	}

	root := cmdline.Group{Name: name, Help: short, Flags: []any{helpFlags{}, versionFlags{}, outputFlags{}, configFlags{}}}
	for _, n := range nodes {
		root.Commands = append(root.Commands, build([]string{nameOf(n)}, n))
	}

	parser, err := cmdline.New(root, opts...)
	if err != nil {
		return nil, errors.Join(append(errs, err)...)
	}

	t.parser = parser

	for old, at := range t.oldNames {
		_, leaf := t.leaves[old]
		if _, group := t.groups[old]; leaf || group {
			errs = append(errs, specError(fmt.Sprintf("%s: old name %q is a command", at, old)))
		}
	}

	errs = append(errs, t.checkFlags()...)

	for _, c := range candidates {
		err := c.Check()
		if err != nil {
			errs = append(errs, specError("the candidates of a lookup: "+err.Error()))
		}
	}

	if len(errs) > 0 {
		return nil, errors.Join(errs...)
	}

	return t, nil
}

// checkFlags holds the flag rules over the whole tree: every flag has a
// help text, and a short letter has one meaning.
func (t *Tree) checkFlags() []error {
	var errs []error

	shorts := map[string]string{}

	var walk func(*cmdline.Info)

	walk = func(c *cmdline.Info) {
		for _, f := range c.Flags {
			if f.Name == rootOnly {
				if len(c.Path) > 0 {
					errs = append(errs, specError(strings.Join(c.Path, " ")+": flag --version is the root's"))
				}

				continue
			}

			t.spellings["--"+f.Name] = "--" + f.Name

			if f.Help == "" {
				errs = append(errs, specError(fmt.Sprintf("%s: flag --%s has no help", strings.Join(c.Path, " "), f.Name)))
			}

			if f.Short == "" {
				continue
			}

			t.spellings["-"+f.Short] = "--" + f.Name

			if other, ok := shorts[f.Short]; ok && other != f.Name {
				errs = append(errs, specError(fmt.Sprintf("%s: -%s is --%s here and --%s elsewhere", strings.Join(c.Path, " "), f.Short, f.Name, other)))
			}

			shorts[f.Short] = f.Name
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return errs
}

func nameOf(n Node) string {
	switch n := n.(type) {
	case Group:
		return n.Name
	case *leaf:
		return n.name
	}

	return ""
}

func oldNamesOf(n Node) []string {
	switch n := n.(type) {
	case Group:
		return n.OldNames
	case *leaf:
		return n.oldNames
	}

	return nil
}

// Command is a command that runs, as tests and the reference see it.
type Command struct {
	// Path is the command words from the root: "api whoami".
	Path    string
	Example []string
	Aliases []string
}

// Commands lists every command that runs, in the order of the tree.
func (t *Tree) Commands() []Command {
	var out []Command

	var walk func(*cmdline.Info)

	walk = func(c *cmdline.Info) {
		if l, ok := t.leaves[strings.Join(c.Path, " ")]; ok && len(c.Commands) == 0 {
			out = append(out, Command{Path: strings.Join(c.Path, " "), Example: l.example, Aliases: l.aliases})
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return out
}

// Reached is the path of the command that argv reaches, whatever else is
// wrong with the line.
func (t *Tree) Reached(argv []string) string {
	line, _ := t.parser.Parse(argv)

	return strings.Join(line.Command.Path, " ")
}
