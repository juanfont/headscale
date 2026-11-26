package command

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/table"
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
	// list is a list: it takes the list flags. info is its columns, and
	// checkList checks the values of the list flags against them.
	list      bool
	info      []table.ColumnInfo
	checkList func(line *cmdline.Line, command string) (int, error)
	// noRows is what a list with no rows says on a terminal; filter is an
	// example of --filter for its help.
	noRows, filter string
	// set is a command that changes the fields its Opt flags name, so a
	// line gives at least one of them: NeedsChange.
	set bool
	// force is a command that can ask, and so takes --force.
	force bool
	// hint follows a wrong argument count or an empty list argument;
	// emptyList follows the sentence of an empty list argument.
	hint      func(args []string) string
	emptyList string
	// valid checks the line, read but not looked up, before any call.
	valid func(*cmdline.Line) error
	// session is the S of its spec, the session it runs with.
	session reflect.Type
	// target is the type of the command's target: the first argument that
	// is an entity; nil for none.
	target reflect.Type
	// server reports whether this line talks to the server.
	server func(*cmdline.Line) bool
	check  func(*program) error
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
		Config configFile `flag:"config" help:"Config file" short:"c"`
	}
	forceFlags struct {
		Force bool `flag:"force" help:"Do not ask"`
	}
)

var (
	errFormat    = errors.New("the only format is json")
	errNoRun     = errors.New("no Run")
	errNoShow    = errors.New("a result and neither Columns nor Done to show it")
	errNoColumns = errors.New("a list with no columns")
	errBoth      = errors.New(
		"both Columns and Done; Done is printed in place of the sheet",
	)
	errNoDefault = errors.New("a list with no Default column")
	errNoRows    = errors.New("a list with no NoRows sentence")
	errBlocks    = errors.New(
		"blocks and no Columns: a block follows the lines of a sheet",
	)
	errNoAsk  = errors.New("a delete with no Confirm: every delete asks first")
	errNoRead = errors.New(
		"has a revision and no read: a write the server refuses because the target changed would not run again",
	)
	errNoSay = errors.New(
		"is cut to the width of the terminal, and Long does not say so",
	)
)

// specError is a spec that is wrong, named by its path.
type specError string

func (e specError) Error() string { return string(e) }

// configFile is the value of --config. "" is a mistake: it would fall back
// to HEADSCALE_CONFIG, a file the line did not name.
type configFile Path

var errConfigEmpty = errors.New("it takes a path")

func (p *configFile) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		return errConfigEmpty
	}

	*p = configFile(b)

	return nil
}

// Complete lets the shell offer file names, as for a Path.
func (configFile) Complete(
	*cmdline.Line,
	string,
) ([]string, cmdline.Directive) {
	return nil, 0
}

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

// cloneColumns is a copy of a declaration the tree keeps, so that a
// caller's later change of it does not change the tree.
func cloneColumns[R any](cols table.Columns[R]) table.Columns[R] {
	cols = slices.Clone(cols)
	for i, c := range cols {
		if c.Fold == nil {
			continue
		}

		cols[i].Fold = make(map[string][]string, len(c.Fold))
		for key, values := range c.Fold {
			cols[i].Fold[key] = slices.Clone(values)
		}
	}

	return cols
}

// New makes the command of a spec.
func New[S, In, Out any](s Spec[S, In, Out]) Node {
	noOut := reflect.TypeFor[Out]() == reflect.TypeFor[NoOutput]()

	s.Columns, s.Blocks = cloneColumns(s.Columns), slices.Clone(s.Blocks)
	l := common(
		s.Name,
		s.Short,
		s.Long,
		s.Example,
		s.Aliases,
		s.OldNames,
		s.Local,
		s.NeedsServer,
		s.ReadsConfig,
	)
	l.output = !noOut || !s.Local || s.NeedsServer != nil
	l.own = !noOut && s.Local && s.NeedsServer == nil
	l.session = reflect.TypeFor[S]()
	l.check = func(p *program) error { return checkSpec(p, s) }
	l.set = s.NeedsChange
	l.force = s.Confirm != nil
	l.hint = s.Hint
	l.emptyList = s.EmptyList
	l.target, _ = targetType(reflect.TypeFor[In]())

	if s.Valid != nil {
		l.valid = func(line *cmdline.Line) error {
			in, _ := cmdline.Get[In](line)

			return s.Valid(in)
		}
	}

	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{
			Name:    s.Name,
			Aliases: s.Aliases,
			Help:    s.Short,
			Flags:   flags,
			Run: func(ctx context.Context, in In) error {
				c := ctxOf[S](ctx)

				in, out, err := runGuarded(c, s, in)

				done := func() string {
					if s.Done == nil {
						return ""
					}

					return s.Done(in, out, c.Now())
				}

				if err != nil {
					return c.fields(c.about(err, in), reflect.TypeFor[In]())
				}

				return printOne(c.run, out, s.Columns, s.Blocks, done)
			},
		}
	}

	return l
}

// checkSpec reports what is wrong with a spec, for the tree to name.
func checkSpec[S, In, Out any](_ *program, s Spec[S, In, Out]) error {
	noOut := reflect.TypeFor[Out]() == reflect.TypeFor[NoOutput]()

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

	if s.Blocks != nil && s.Columns == nil {
		errs = append(errs, errBlocks)
	}

	return errors.Join(append(errs, s.Columns.Check(), s.Blocks.Check())...)
}

// NewList makes the command of a list spec.
func NewList[S, In, Row any](s ListSpec[S, In, Row]) Node {
	s.Columns = cloneColumns(s.Columns)
	l := common(
		s.Name,
		s.Short,
		s.Long,
		s.Example,
		s.Aliases,
		s.OldNames,
		s.Local,
		s.NeedsServer,
		s.ReadsConfig,
	)
	l.output = true
	l.list = true
	l.info = s.Columns.Info()
	l.noRows = s.NoRows
	l.filter = filterExample(s.Example)
	l.checkList = func(line *cmdline.Line, command string) (int, error) { return listCheck(s.Columns, line, command) }
	l.session = reflect.TypeFor[S]()
	l.check = func(p *program) error {
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

		if s.NoRows == "" {
			errs = append(errs, errNoRows)
		}

		// A list cut to the terminal says so, and how to read all of it.
		for _, c := range s.Columns {
			if says := c.Heading() + " is truncated to fit your terminal"; c.List == table.Cut &&
				!strings.Contains(s.Long, says) {
				errs = append(
					errs,
					fmt.Errorf(
						"column %q %w: %q, with the way to read all of it",
						c.Name,
						errNoSay,
						says,
					),
				)
			}
		}

		return errors.Join(append(errs, s.Columns.Check())...)
	}
	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{
			Name:    s.Name,
			Aliases: s.Aliases,
			Help:    s.Short,
			Flags:   flags,
			Run: func(ctx context.Context, in In) error {
				c := ctxOf[S](ctx)
				f, _ := cmdline.Get[listFlags](c.line)

				conds, err := filters(c.run, ctx, s.Columns, f)
				if err != nil {
					return err
				}

				rows, err := s.Run(c, in)
				if err != nil {
					return c.fields(c.errorOf(err), reflect.TypeFor[In]())
				}

				rows, err = listOf(c.run, s.Columns, rows, conds, f.Sort)
				if err != nil {
					return err
				}

				return printList(c.run, rows, s.Columns.Pick(f.words()), s.NoRows)
			},
		}
	}

	return l
}

func common[In any](
	name, short, long string,
	example, aliases, oldNames []string,
	local bool,
	needs func(In) bool,
	readsConfig bool,
) *leaf {
	return &leaf{
		name:     name,
		short:    short,
		long:     long,
		example:  slices.Clone(example),
		aliases:  slices.Clone(aliases),
		oldNames: oldNames,
		local:    local,
		config:   !local || needs != nil || readsConfig,
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

// flags are the structs of flags the builder gives the command: the list
// flags of a list, --output and --config as its spec derives them, and
// --help.
func (l *leaf) flags() []any {
	var f []any

	if l.list {
		f = append(f, listFlags{})
	}

	switch {
	case l.output && l.own:
		f = append(f, ownOutputFlags{})
	case l.output:
		f = append(f, outputFlags{})
	}

	if l.config {
		f = append(f, configFlags{})
	}

	if l.force {
		f = append(f, forceFlags{})
	}

	return append(f, helpFlags{})
}

// Tree is a checked tree of commands. It is read-only, so runs in parallel
// may share one, but tests build one per case.
type Tree struct {
	prog   program
	parser *cmdline.Tree
	name   string
	short  string
	leaves map[string]*leaf
	groups map[string]Group
	// oldNames leads an old path to the path of today.
	oldNames map[string]string
	// entities are the types of target the tree looks up, by type.
	entities map[reflect.Type]Entity
	// spellings leads every flag of the tree, as it can be typed ("--force",
	// "-o"), to its long name, which messages use. --version is not one:
	// on a command line it is an unknown flag.
	spellings map[string]string
}

// rootOnly is the flag that only the root takes.
const rootOnly = "version"

// Build checks every spec and makes the tree of the program p. The error
// names every command and field that is wrong.
func Build[S any](p Program[S], nodes ...Node) (*Tree, error) {
	return buildOf(erase(p), nodes...)
}

func buildOf(p program, nodes ...Node) (*Tree, error) {
	t := &Tree{
		prog: p,
		name: p.Name, short: p.Short,
		leaves: map[string]*leaf{}, groups: map[string]Group{},
		oldNames: map[string]string{}, spellings: map[string]string{},
		entities: map[reflect.Type]Entity{},
	}

	var errs []error

	opts := make([]cmdline.Option, 0, len(p.Entities))

	for _, e := range p.Entities {
		t.entities[e.t] = e
		opts = append(opts, e.lookup)

		err := e.check()
		if err != nil {
			errs = append(errs, specError("the candidates of a lookup: "+err.Error()))
		}
	}

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

			// The tree keeps the group: a caller's later change of its
			// slice must not change the tree.
			n.Commands = slices.Clone(n.Commands)
			t.groups[at] = n

			g := cmdline.Group{Name: n.Name, Help: n.Short, Flags: []any{helpFlags{}}}
			for _, c := range n.Commands {
				g.Commands = append(
					g.Commands,
					build(append(slices.Clip(path), nameOf(c)), c),
				)
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

			// A spec of another session would run with its zero value.
			if p.sessionType != nil && n.session != p.sessionType {
				bad(
					"a spec of session %v in a program of session %v",
					n.session,
					p.sessionType,
				)
			}

			for _, a := range n.aliases {
				if !slices.Contains(p.Aliases, a) {
					bad("alias %q is none of %v", a, p.Aliases)
				}
			}

			err := n.check(&p)
			if err != nil {
				bad("%v", err)
			}

			if n.name == "delete" && !n.force {
				bad("%v", errNoAsk)
			}

			err = checkTarget(n, t.entities)
			if err != nil {
				bad("%v", err)
			}

			t.leaves[at] = n

			return n.cmd(n.flags())
		}

		bad("%T is no node", n)

		return nil
	}

	// A program with no Version has no --version: it has no line to print.
	rootFlags := []any{helpFlags{}, versionFlags{}, outputFlags{}, configFlags{}}
	if p.Version == nil {
		rootFlags = []any{helpFlags{}, outputFlags{}, configFlags{}}
	}

	root := cmdline.Group{Name: p.Name, Help: p.Short, Flags: rootFlags}
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
			errs = append(
				errs,
				specError(fmt.Sprintf("%s: old name %q is a command", at, old)),
			)
		}
	}

	errs = append(errs, t.checkFlags()...)

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
		if l, ok := t.leaves[strings.Join(c.Path, " ")]; ok && l.set &&
			!slices.ContainsFunc(
				c.Flags,
				func(f cmdline.Flag) bool { return f.Optional },
			) {
			errs = append(
				errs,
				specError(
					strings.Join(
						c.Path,
						" ",
					)+": NeedsChange and no Opt flag that changes a field",
				),
			)
		}

		for _, f := range c.Flags {
			if f.Name == rootOnly {
				if len(c.Path) > 0 {
					errs = append(
						errs,
						specError(
							strings.Join(c.Path, " ")+": flag --version is the root's",
						),
					)
				}

				continue
			}

			t.spellings["--"+f.Name] = "--" + f.Name

			if f.Help == "" {
				errs = append(
					errs,
					specError(
						fmt.Sprintf(
							"%s: flag --%s has no help",
							strings.Join(c.Path, " "),
							f.Name,
						),
					),
				)
			}

			if f.Short == "" {
				continue
			}

			t.spellings["-"+f.Short] = "--" + f.Name

			if other, ok := shorts[f.Short]; ok && other != f.Name {
				errs = append(
					errs,
					specError(
						fmt.Sprintf(
							"%s: -%s is --%s here and --%s elsewhere",
							strings.Join(c.Path, " "),
							f.Short,
							f.Name,
							other,
						),
					),
				)
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
			out = append(
				out,
				Command{
					Path:    strings.Join(c.Path, " "),
					Example: l.example,
					Aliases: l.aliases,
				},
			)
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

// checkTarget reports what the target of n lacks for the guard of its
// writes.
func checkTarget(n *leaf, ents map[reflect.Type]Entity) error {
	e, known := ents[n.target]
	if n.target != nil && hasJSON(n.target, "revision") && (!known || e.read == nil) {
		return fmt.Errorf("target %v %w", n.target, errNoRead)
	}

	return nil
}
