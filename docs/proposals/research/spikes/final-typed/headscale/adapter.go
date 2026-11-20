package headscale

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math"
	"slices"
	"strconv"
	"strings"

	"spike/cmdline"
	"spike/cmdline/script"
	"spike/kit"
)

// Adapter runs the kit's cases through a tree of specs: the zero value
// through the kit's own tree (specs.go), For(tree) through another.
type Adapter struct{ tree *Tree }

// For is the Adapter of a tree that is the typed twin of another kit tree.
func For(t *Tree) Adapter { return Adapter{t} }

func (a Adapter) specs() *Tree {
	if a.tree != nil {
		return a.tree
	}
	return KitTree()
}

// Run is 001's builder, cut down. The library reads the line and reports
// its first mistake; the builder places Headscale's own mistakes against it
// and reports the leftmost (D35). Then help, --version, a group alone
// (D10), the argument count, and the command.
func (a Adapter) Run(ctx context.Context, _ *kit.Tree, argv []string, std kit.Stdio) error {
	line, err := a.specs().Parse(argv)
	ue, _ := errors.AsType[*cmdline.UsageError](err)
	if err != nil && ue == nil {
		return err
	}
	o := kit.Outcome{Kind: "run", Path: line.Command.Path, Args: line.Args, Flags: map[string][]string{}}
	for _, g := range line.Flags {
		o.Flags[g.Name] = append(o.Flags[g.Name], g.Value)
	}
	if ue == nil || ue.Kind >= cmdline.Repeated && a.whole(line, argv) {
		kit.Raw(ctx, kit.Call{Path: o.Path, Flags: o.Flags, Args: o.Args})
	}
	if e := mistake(line, ue); e != nil {
		return e
	}
	help, _ := cmdline.Get[helpFlags](line)
	version, _ := cmdline.Get[versionFlags](line)
	switch {
	case help.Help, len(line.Command.Commands) > 0 && !version.Version:
		o = kit.Outcome{Kind: "help", Path: o.Path}
	case version.Version:
		o = kit.Outcome{Kind: "version"}
	case ue != nil:
		return &kit.UsageError{Kind: kit.ArgCount, Path: o.Path, Word: count(line)}
	default:
		if err := line.Run(ctx); err != nil {
			return err
		}
	}
	return kit.Done(ctx, std, o)
}

// whole reports whether every word of argv was read: as a command word, a
// flag, its value, an argument or the "--" that ends the flags. Next to a
// mistake of a value the reader may have stopped at a later word of its own;
// the differential harness wants the line "as the parser read it" only when
// it read all of it, as kit v3's Exec did. Nothing else needs this.
func (a Adapter) whole(line *cmdline.Line, argv []string) bool {
	bools := map[string]bool{}
	c := a.specs().Root()
	for i := 0; ; i++ {
		for _, f := range c.Flags {
			bools[f.Name] = f.Bool
		}
		if i == len(line.Command.Path) {
			break
		}
		c = c.Commands[slices.IndexFunc(c.Commands, func(s *cmdline.Info) bool { return s.Name == line.Command.Path[i] })]
	}
	used := make([]bool, len(argv))
	for _, g := range line.Flags {
		used[g.At] = true
		if !bools[g.Name] && !strings.Contains(argv[g.At], "=") {
			used[g.At+1] = true
		}
	}
	for _, at := range line.ArgAt {
		used[at] = true
	}
	var rest []string // the command words, and the "--" of a command that runs
	for i, w := range argv {
		if !used[i] {
			rest = append(rest, w)
		}
	}
	n := len(line.Command.Path)
	return len(rest) == n || len(rest) == n+1 && len(c.Commands) == 0 && rest[n] == "--"
}

// global names the flags that may stand before the subcommand also when the
// line ends at a group that does not list them (D3).
var global = []string{"output", "config"}

// mistake returns the leftmost mistake on the line: the library's, or one
// of Headscale's own. Its own are a flag that the group reached does not
// take, and --version with another flag, at the second of the two (D7). In
// one word a flag that is not taken comes before the library's mistake, and
// --version not alone after it. A wrong argument count is no mistake here:
// it yields to help, so Run reports it.
func mistake(line *cmdline.Line, ue *cmdline.UsageError) error {
	var first error
	at := math.MaxInt
	if ue != nil && ue.Kind != cmdline.ArgCount {
		first, at = usage(ue), ue.At
	}
	found := func(k kit.ErrKind, word string, pos int, wins bool) {
		if pos < at || pos == at && wins {
			first, at = &kit.UsageError{Kind: k, Path: line.Command.Path, Word: word}, pos
		}
	}
	group := len(line.Command.Commands) > 0
	version, others := -1, 0
	for _, g := range line.Flags {
		own := slices.ContainsFunc(line.Command.Flags, func(f cmdline.Flag) bool { return f.Name == g.Name })
		switch {
		case group && !own && !slices.Contains(global, g.Name):
			found(kit.UnknownFlag, "--"+g.Name, g.At, true)
		case g.Name == "version" && g.Value == "true" && others > 0, g.Name != "version" && version >= 0:
			found(kit.NotAlone, "--version", g.At, false)
		}
		if g.Name == "version" && g.Value == "true" {
			version = g.At
		} else if g.Name != "version" {
			others++
		}
	}
	return first
}

// usage turns the library's mistake into the kit's: the kind, the command
// and the word. Headscale writes its sentences from the same fields.
func usage(e *cmdline.UsageError) error {
	kind := map[cmdline.Kind]kit.ErrKind{
		cmdline.UnknownCommand: kit.UnknownCommand,
		cmdline.UnknownFlag:    kit.UnknownFlag,
		cmdline.MissingValue:   kit.MissingValue,
		cmdline.Repeated:       kit.FlagRepeated,
		cmdline.BadValue:       kit.BadValue,
		cmdline.Unresolved:     kit.BadValue,
	}[e.Kind]
	word := e.Word
	switch {
	case e.Flag != "":
		word = "--" + e.Flag
	case e.Arg != "":
		word = e.Arg
	}
	return &kit.UsageError{Kind: kind, Path: e.Path, Word: word}
}

// count is the sentence for a wrong argument count, from the command's
// arguments as data.
func count(line *cmdline.Line) string {
	args, n := line.Command.Args, len(line.Args)
	minN := slices.IndexFunc(args, func(a cmdline.Arg) bool { return a.Optional })
	if minN < 0 {
		minN = len(args)
	}
	plural := func(n int) string {
		if n == 1 {
			return "1 argument"
		}
		return strconv.Itoa(n) + " arguments"
	}
	switch {
	case len(args) == 0:
		return fmt.Sprintf("takes no arguments, got %d", n)
	case minN == len(args):
		return fmt.Sprintf("needs %s, got %d", plural(minN), n)
	case n > len(args):
		return fmt.Sprintf("takes at most %s, got %d", plural(len(args)), n)
	}
	return fmt.Sprintf("needs at least %s, got %d", plural(minN), n)
}

func (a Adapter) Complete(_ context.Context, _ *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	words, dir := a.specs().Complete(argv[:len(argv)-1], argv[len(argv)-1])
	return kit.Completion{Words: words, Files: dir&cmdline.NoFiles == 0}, nil
}

func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	return script.Write(w, shell, kit.Program)
}
