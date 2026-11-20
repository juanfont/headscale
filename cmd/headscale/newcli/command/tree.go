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
	// list is a list: it takes the list flags. info is its columns, and
	// checkList checks the values of the list flags against them.
	list      bool
	info      []table.ColumnInfo
	checkList func(line *cmdline.Line, command string) (int, error)
	// noRows is what a list with no rows says on a terminal; filter is an
	// example of --filter for its help; only is the filter that --all
	// removes, "" for a list that hides nothing.
	noRows, filter, only string
	// set is a command that changes the fields its Opt flags name, so a
	// line gives at least one of them: NeedsChange.
	set bool
	// force is a command that can ask, and so takes --force.
	force bool
	// changed is a command whose question hands a guard to the write:
	// Spec.Changed.
	changed bool
	// secret is a command that prints a secret once: Spec.Secret.
	secret bool
	// noJSON is a test tool with no --output: Spec.NoJSON.
	noJSON bool
	// end is the delete of a credential, made by NewEnd.
	end bool
	// hint follows a wrong argument count or an empty list argument;
	// emptyList follows the sentence of an empty list argument.
	hint      func(args []string) string
	emptyList string
	// valid checks the line, read but not looked up, before any call: the
	// rule on the way in, then Spec.Valid.
	valid func(*cmdline.Line) error
	// whole are the words of a checked line that it takes as secrets typed
	// whole, which no output of the run may repeat.
	whole func(*cmdline.Line) []wholeWord
	// target is the type of the command's target: the first argument that
	// is an entity; nil for none.
	target reflect.Type
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
	forceFlags struct {
		Force bool `flag:"force" help:"Do not ask"`
	}
)

var (
	errFormat    = errors.New("the only format is json")
	errNoRun     = errors.New("no Run")
	errNoShow    = errors.New("a result and neither Columns nor Done to show it")
	errNoColumns = errors.New("a list with no columns")
	errBoth      = errors.New("both Columns and Done; Done is printed in place of the sheet")
	errNoDefault = errors.New("a list with no Default column")
	errNoRows    = errors.New("a list with no NoRows sentence")
	errBlocks    = errors.New("blocks and no Columns: a block follows the lines of a sheet")
	errNoAsk     = errors.New("a delete with no Confirm: every delete asks first")
	errNoRead    = errors.New("has a revision and no read: a write the server refuses because the target changed would not run again")
	// errNoQuestion: a refusal that a question answers again needs the
	// question, which makes what the write sends anew.
	errNoQuestion = errors.New("a refusal named in Changed and no Confirm: the write would run again on what it sent before")
	// errNoGuardTarget, errGuardMix: the token of a question is kept for
	// the target, in the one place its revision would be.
	errNoGuardTarget = errors.New("a refusal named in Changed and no target that is an entity: the guard of the question would reach no write")
	errGuardMix      = errors.New("a refusal named in Changed on a target with a revision: the write takes one guard, and the token would drop the revision")
	errNoSay         = errors.New("is cut to the width of the terminal, and Long does not say so")
	errSaid          = errors.New("a result Said needs Done, which prints it, and no Columns")
	errNoJSON        = errors.New("NoJSON is a test tool that prints one sentence: it needs Done and no Columns")
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
	noOut := isNoOutput[Out]()

	l := common(s.Name, s.Short, s.Long, s.Example, s.Aliases, s.OldNames, s.Local, s.NeedsServer, s.ReadsConfig)
	l.output = (!noOut || !s.Local || s.NeedsServer != nil) && !s.NoJSON
	l.own = !noOut && s.Local && s.NeedsServer == nil
	rule, whole, ruleErr := inputRule[In]()
	l.valid = rule
	l.whole = whole
	l.check = func() error { return errors.Join(checkSpec(s), ruleErr) }
	l.set = s.NeedsChange
	l.force = s.Confirm != nil
	l.changed = s.Changed != ""
	l.secret = s.Secret != nil
	l.noJSON = s.NoJSON
	l.hint = s.Hint
	l.emptyList = s.EmptyList
	l.target, _ = targetType(reflect.TypeFor[In]())

	if s.Valid != nil {
		l.valid = func(line *cmdline.Line) error {
			err := rule(line)
			if err != nil {
				return err
			}

			in, _ := cmdline.Get[In](line)

			return s.Valid(in)
		}
	}

	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{Name: s.Name, Aliases: s.Aliases, Help: s.Short, Flags: flags, Run: func(ctx context.Context, in In) error {
			c := ctxOf(ctx)

			in, out, err := runGuarded(c, s, in)

			notRead := errors.Is(err, ErrNotRead)

			switch {
			case err != nil && !notRead && s.Secret != nil:
				return c.lostAnswer(flagsOf[In](c.about(err, in)))
			case err != nil && !notRead:
				return flagsOf[In](c.about(err, in))
			case s.Secret != nil:
				return printSecret(c, out, s.Secret(out), func() string { return s.Done(in, out, c.Now()) })
			}

			done := func() string {
				if s.Done == nil {
					return ""
				}

				return s.Done(in, out, c.Now())
			}

			// The change is made and there is no object: JSON has nothing
			// to print.
			if notRead {
				if c.json {
					return nil
				}

				return writeText(c.stdout, done())
			}

			return printOne(c, out, s.Columns, s.Blocks, done)
		}}
	}

	return l
}

// checkTarget reports what the target of n lacks for the guard of its
// writes.
func checkTarget(n *leaf, ents map[reflect.Type]entity) error {
	e, known := ents[n.target]
	revised := n.target != nil && hasJSON(n.target, "revision")

	switch {
	case revised && (!known || e.read == nil):
		return fmt.Errorf("target %v %w", n.target, errNoRead)
	case n.changed && !known:
		return errNoGuardTarget
	case n.changed && revised:
		return errGuardMix
	}

	return nil
}

// isNoOutput reports whether Out prints no object: NoOutput, or Said, whose
// text only Done prints.
func isNoOutput[Out any]() bool {
	t := reflect.TypeFor[Out]()

	return t == reflect.TypeFor[NoOutput]() || t == reflect.TypeFor[Said]()
}

// checkSpec reports what is wrong with a spec, for the tree to name.
func checkSpec[In, Out any](s Spec[In, Out]) error {
	noOut := isNoOutput[Out]()

	var errs []error

	if s.Run == nil {
		errs = append(errs, errNoRun)
	}

	// What it said is printed by Done or not at all; a test tool prints its
	// one sentence.
	if reflect.TypeFor[Out]() == reflect.TypeFor[Said]() && (s.Done == nil || s.Columns != nil) {
		errs = append(errs, errSaid)
	}

	if s.NoJSON && (s.Done == nil || s.Columns != nil) {
		errs = append(errs, errNoJSON)
	}

	switch {
	case !noOut && s.Columns == nil && s.Done == nil:
		errs = append(errs, errNoShow)
	case s.Columns != nil && s.Done != nil:
		errs = append(errs, errBoth)
	}

	errs = append(errs, checkSecret(reflect.TypeFor[Out](), s.Secret != nil, s.Done != nil, s.Columns != nil)...)

	if s.Blocks != nil && s.Columns == nil {
		errs = append(errs, errBlocks)
	}

	if s.Changed != "" && s.Confirm == nil {
		errs = append(errs, errNoQuestion)
	}

	return errors.Join(append(errs, s.Columns.Check(), s.Blocks.Check())...)
}

// NewList makes the command of a list spec.
func NewList[In, Row any](s ListSpec[In, Row]) Node {
	l := common(s.Name, s.Short, s.Long, s.Example, s.Aliases, s.OldNames, s.Local, s.NeedsServer, s.ReadsConfig)
	l.output = true
	l.list = true
	l.info = onlyInfo(s.Columns, s.Only)
	l.noRows = s.NoRows
	l.only = s.Only
	l.filter = filterExample(s.Example)
	l.checkList = func(line *cmdline.Line, command string) (int, error) { return listCheck(s.Columns, line, command) }
	rule, whole, ruleErr := inputRule[In]()
	l.valid = rule
	l.whole = whole
	l.check = func() error {
		errs := []error{ruleErr}

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
			if says := c.Heading() + " is truncated to fit your terminal"; c.List == table.Cut && !strings.Contains(s.Long, says) {
				errs = append(errs, fmt.Errorf("column %q %w: %q, with the way to read all of it", c.Name, errNoSay, says))
			}
		}

		errs = append(errs, checkOnly(s.Columns, s.Only, s.Long)...)
		errs = append(errs, checkRows(reflect.TypeFor[Row]())...)

		return errors.Join(append(errs, s.Columns.Check())...)
	}
	l.cmd = func(flags []any) cmdline.Node {
		return cmdline.Command[In]{Name: s.Name, Aliases: s.Aliases, Help: s.Short, Flags: flags, Run: func(ctx context.Context, in In) error {
			c := ctxOf(ctx)
			f, _ := cmdline.Get[listFlags](c.line)
			all, _ := cmdline.Get[allFlags](c.line)

			conds, err := filters(c, s.Columns, f)
			if err != nil {
				return err
			}

			cols, only := applyOnly(s.Columns, s.Only, all.All, conds)

			rows, err := s.Run(c, in)
			if err != nil {
				return flagsOf[In](err)
			}

			rows, err = listOf(c, s.Columns, rows, conds, f.Sort)
			if err != nil {
				return err
			}

			shown, err := listOf(c, s.Columns, rows, only, "")
			if err != nil {
				return err
			}

			return printList(c, shown, cols.Pick(f.words()), moreRows(s.NoRows, len(rows)-len(shown)))
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

// flags are the structs of flags the builder gives the command: the list
// flags of a list, --output and --config as its spec derives them, and
// --help.
func (l *leaf) flags() []any {
	var f []any

	if l.list {
		f = append(f, listFlags{})
	}

	if l.only != "" {
		f = append(f, allFlags{})
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
	parser *cmdline.Tree
	name   string
	short  string
	leaves map[string]*leaf
	groups map[string]Group
	// oldNames leads an old path to the path of today.
	oldNames map[string]string
	// entities are the types of target the tree looks up, by type.
	entities map[reflect.Type]entity
	// spellings leads every flag of the tree, as it can be typed ("--force",
	// "-o"), to its long name, which messages use. --version is not one:
	// on a command line it is an unknown flag.
	spellings map[string]string
}

// rootOnly is the flag that only the root takes.
const rootOnly = "version"

// allowedAliases are the aliases a command may have.
func allowedAliases() []string { return []string{"ls", "rm", "approve"} }

// Build checks every spec and makes the tree. The error names every
// command and field that is wrong.
func Build(name, short string, nodes ...Node) (*Tree, error) {
	return build(name, short, allowedAliases(), entities(), nodes...)
}

// build is Build with the aliases a tree may use and the entities it looks
// up: the tests of the grammar need trees with other aliases than
// Headscale's, and a test of the retry a type of its own. A test tree is
// checked as the real one is.
func build(name, short string, aliases []string, ents []entity, nodes ...Node) (*Tree, error) {
	t := &Tree{
		name: name, short: short,
		leaves: map[string]*leaf{}, groups: map[string]Group{},
		oldNames: map[string]string{}, spellings: map[string]string{},
		entities: map[reflect.Type]entity{},
	}

	var errs []error

	// An owner is no entity, so it has no candidates and no read; it has a
	// lookup all the same.
	opts := append(make([]cmdline.Option, 0, len(ents)+1), cmdline.LateReader(findOwner))

	for _, e := range ents {
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

			t.groups[at] = n

			g := cmdline.Group{Name: n.Name, Help: n.Short, Flags: []any{helpFlags{}}}
			for _, c := range n.Commands {
				g.Commands = append(g.Commands, build(append(slices.Clip(path), nameOf(c)), c))
			}

			errs = append(errs, secretEnds(path, n.Commands)...)

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

			if n.name == "delete" && !n.force {
				bad("%v", errNoAsk)
			}

			if n.name == "delete" && revokable(n.target) && !n.end {
				bad("%v", errNotEnd)
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

	root := cmdline.Group{Name: name, Help: short, Flags: []any{helpFlags{}, versionFlags{}, outputFlags{}, configFlags{}}}
	for _, n := range nodes {
		root.Commands = append(root.Commands, build([]string{nameOf(n)}, n))
	}

	errs = append(errs, secretEnds(nil, nodes)...)

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
		if l, ok := t.leaves[strings.Join(c.Path, " ")]; ok && l.set && !slices.ContainsFunc(c.Flags, func(f cmdline.Flag) bool { return f.Optional }) {
			errs = append(errs, specError(strings.Join(c.Path, " ")+": NeedsChange and no Opt flag that changes a field"))
		}

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
	// Secret prints a secret once: it makes a credential, whose group the
	// tests of every kind of credential run on.
	Secret bool
	// NoJSON is a test tool that takes no --output: a test lists each, with
	// why.
	NoJSON bool
	// Whole are the arguments and flags that take a secret typed whole, such
	// as <auth-id>: the tests that it leaves in one request and comes back
	// in nothing run on each.
	Whole []string
}

// Commands lists every command that runs, in the order of the tree.
func (t *Tree) Commands() []Command {
	var out []Command

	var walk func(*cmdline.Info)

	walk = func(c *cmdline.Info) {
		if l, ok := t.leaves[strings.Join(c.Path, " ")]; ok && len(c.Commands) == 0 {
			out = append(out, Command{Path: strings.Join(c.Path, " "), Example: l.example, Aliases: l.aliases, Secret: l.secret, NoJSON: l.noJSON, Whole: wholeArgs(c)})
		}

		for _, s := range c.Commands {
			walk(s)
		}
	}
	walk(t.parser.Root())

	return out
}

// wholeArgs are the arguments and flags of c whose type, or the type of
// whose items, is a [TakesWhole].
func wholeArgs(c *cmdline.Info) []string {
	var out []string

	takes := func(t reflect.Type) bool {
		if t.Kind() == reflect.Slice {
			t = t.Elem()
		}

		_, ok := reflect.TypeAssert[TakesWhole](reflect.Zero(t))

		return ok
	}

	for _, a := range c.Args {
		if takes(a.Type) {
			out = append(out, "<"+a.Name+">")
		}
	}

	for _, f := range c.Flags {
		if takes(f.Type) {
			out = append(out, "--"+f.Name)
		}
	}

	return out
}

// Reached is the path of the command that argv reaches, whatever else is
// wrong with the line.
func (t *Tree) Reached(argv []string) string {
	line, _ := t.parser.Parse(argv)

	return strings.Join(line.Command.Path, " ")
}
