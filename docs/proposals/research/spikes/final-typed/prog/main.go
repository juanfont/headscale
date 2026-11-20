// Command prog is the example program of 003: every example in the
// document is run against it.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"spike/cmdline"
	"spike/cmdline/script"
)

// Format is the value of --output. It reads itself.
type Format string

var formats = []string{"json", "yaml"}

func (f *Format) UnmarshalText(b []byte) error {
	if !slices.Contains(formats, string(b)) {
		return errors.New("want json or yaml")
	}
	*f = Format(b)
	return nil
}

// Complete offers the formats on Tab.
func (Format) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, formats...), cmdline.NoFiles
}

// Column is a column of the list. A leading "-" turns the order.
type Column string

func (c *Column) UnmarshalText(b []byte) error {
	if name := strings.TrimPrefix(string(b), "-"); name != "id" && name != "name" {
		return errors.New("want id or name")
	}
	*c = Column(b)
	return nil
}

func (Column) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	return cmdline.Words(prefix, "id", "name"), cmdline.NoFiles
}

// Item is looked up in the store when the command runs.
type Item struct {
	ID   int
	Name string
}

type storeKey struct{}

// findItem is the late reader of Item. Line.Run calls it; the store is in ctx.
func findItem(ctx context.Context, word string) (Item, error) {
	store, _ := ctx.Value(storeKey{}).([]Item)
	for _, it := range store {
		if strconv.Itoa(it.ID) == word {
			return it, nil
		}
	}
	return Item{}, errors.New("no such item")
}

// Complete offers the IDs in the store that -c names on the line so far.
func (Item) Complete(line *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	file := "prog.yaml"
	for _, g := range line.Flags {
		if g.Name == "config" {
			file = g.Value
		}
	}
	var ids []string
	for _, it := range load(file) {
		ids = append(ids, strconv.Itoa(it.ID))
	}
	return cmdline.Words(prefix, ids...), cmdline.NoFiles
}

func load(file string) []Item {
	if file == "other.yaml" {
		return []Item{{21, "pear"}, {22, "plum"}}
	}
	return []Item{{12, "apple"}, {13, "fig"}}
}

// The flags that more than one command takes. Each set is a struct of its own.
type (
	helpFlags struct {
		Help bool `flag:"help" short:"h" help:"Show help"`
	}
	outputFlags struct {
		Output Format `flag:"output" short:"o" help:"Output format"`
	}
	configFlags struct {
		Config cmdline.Path `flag:"config" short:"c" default:"prog.yaml" help:"Config file"`
	}
)

type listIn struct {
	Sort    Column                     `flag:"sort" help:"Sort by"`
	Columns []Column                   `flag:"columns" help:"Columns to show"`
	Filter  cmdline.Repeat[string]     `flag:"filter" help:"Keep matching rows"`
	Limit   int                        `flag:"limit" default:"50" help:"Most rows to show"`
	Name    cmdline.Opt[string]        `flag:"name" help:"Keep items with this name"`
	Since   cmdline.Opt[time.Duration] `flag:"since" help:"Keep items changed in this time"`
}

type deleteIn struct {
	Item  Item `arg:"item" help:"The item to delete"`
	Force bool `flag:"force" help:"Do not ask"`
}

type checkIn struct {
	File cmdline.Opt[cmdline.Path] `arg:"file" help:"The file to check"`
}

type completionIn struct {
	Shell string `arg:"shell" help:"bash, zsh, fish or powershell"`
}

func tree() *cmdline.Tree {
	common := []any{helpFlags{}, outputFlags{}, configFlags{}}
	t, err := cmdline.New(
		cmdline.Group{Name: "prog", Flags: common, Commands: []cmdline.Node{
			cmdline.Group{Name: "items", Help: "Manage items", Flags: []any{helpFlags{}}, Commands: []cmdline.Node{
				cmdline.Command[listIn]{Name: "list", Aliases: []string{"ls"}, Help: "List items", Flags: common, Run: list},
				cmdline.Command[deleteIn]{Name: "delete", Aliases: []string{"rm"}, Help: "Delete an item", Flags: common, Run: del},
			}},
			cmdline.Command[checkIn]{Name: "check", Help: "Check a file", Flags: []any{helpFlags{}, configFlags{}}, Run: check},
			cmdline.Command[completionIn]{Name: "completion", Help: "Write a completion script", Flags: []any{helpFlags{}}, Run: completion},
		}},
		cmdline.Reader(time.ParseDuration), // time.Duration has no UnmarshalText
		cmdline.LateReader(findItem),       // an Item is looked up when the command runs
	)
	if err != nil {
		panic(err) // a wrong tree is a fault in the program; TestTree finds it first
	}
	return t
}

func list(_ context.Context, in listIn) error {
	name, named := in.Name.Get()
	since, _ := in.Since.Get()
	fmt.Printf("list sort=%q columns=%q filter=%q limit=%d name=%q/%v since=%s\n",
		in.Sort, in.Columns, []string(in.Filter), in.Limit, name, named, since)
	return nil
}

func del(_ context.Context, in deleteIn) error {
	fmt.Printf("delete %d (%s) force=%v\n", in.Item.ID, in.Item.Name, in.Force)
	return nil
}

func check(_ context.Context, in checkIn) error {
	file, given := in.File.Get()
	fmt.Printf("check %q given=%v\n", file, given)
	return nil
}

func completion(_ context.Context, in completionIn) error {
	return script.Write(os.Stdout, in.Shell, "prog")
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	t := tree()
	if t.Serve(os.Stdout, args) {
		return 0
	}
	line, err := t.Parse(args)
	if h, _ := cmdline.Get[helpFlags](line); h.Help || err == nil && len(line.Command.Commands) > 0 {
		fmt.Println("usage:", line.Command.Usage)
		return 0
	}
	if err == nil {
		c, _ := cmdline.Get[configFlags](line)
		ctx := context.WithValue(context.Background(), storeKey{}, load(string(c.Config)))
		err = line.Run(ctx) // the late readers, then the command
	}
	if e := (*cmdline.UsageError)(nil); errors.As(err, &e) {
		fmt.Fprintf(os.Stderr, "Error: %s.\n", sentence(line.Command, e))
		return 1
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v.\n", err)
		return 1
	}
	return 0
}

// sentence writes the program's own text from the fields of the mistake.
func sentence(c *cmdline.Info, e *cmdline.UsageError) string {
	where := strings.Join(append([]string{"prog"}, e.Path...), " ")
	what := "<" + e.Arg + ">"
	if e.Flag != "" {
		what = "--" + e.Flag
	}
	switch e.Kind {
	case cmdline.UnknownCommand:
		return fmt.Sprintf("%q is not a command of `%s`", e.Word, where)
	case cmdline.UnknownFlag:
		return fmt.Sprintf("`%s` has no flag %s", where, e.Word)
	case cmdline.MissingValue:
		return fmt.Sprintf("%s needs a value", e.Word)
	case cmdline.Repeated:
		return fmt.Sprintf("%s is given twice", what)
	case cmdline.ArgCount:
		return fmt.Sprintf("usage: %s", c.Usage)
	default: // cmdline.BadValue, cmdline.Unresolved
		return fmt.Sprintf("%s: %q: %v", what, e.Value, e.Err)
	}
}
