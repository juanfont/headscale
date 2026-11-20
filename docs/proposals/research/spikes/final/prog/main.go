// Command prog is the example program of 003: every example in the
// document is run against it.
package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"spike/cmdline"
	"spike/cmdline/script"
)

func tree() *cmdline.Command {
	help := cmdline.Flag{Name: "help", Short: 'h', Bool: true, Help: "Show help"}
	output := cmdline.Flag{Name: "output", Short: 'o', Help: "Output format", Complete: cmdline.Words("json", "yaml")}
	config := cmdline.Flag{Name: "config", Short: 'c', Help: "Config file", Complete: cmdline.Files}

	return &cmdline.Command{
		Name:  "prog",
		Flags: []cmdline.Flag{help, output, config},
		Commands: []*cmdline.Command{
			{Name: "items", Help: "Manage items", Flags: []cmdline.Flag{help}, Commands: []*cmdline.Command{
				{Name: "list", Aliases: []string{"ls"}, Help: "List items", Flags: []cmdline.Flag{help, output, config,
					{Name: "sort", Help: "Sort by", Complete: cmdline.Words("id", "name")},
					{Name: "filter", Repeat: true, Help: "Keep matching rows", Complete: cmdline.Words("id", "name")},
				}},
				{Name: "delete", Aliases: []string{"rm"}, Help: "Delete an item", Flags: []cmdline.Flag{help, output, config,
					{Name: "force", Bool: true, Help: "Do not ask"},
				}, Args: []cmdline.Completer{itemIDs}},
			}},
			{Name: "check", Help: "Check a file", Flags: []cmdline.Flag{help, config},
				Args: []cmdline.Completer{cmdline.Files}},
			{Name: "completion", Help: "Write a completion script", Flags: []cmdline.Flag{help},
				Args: []cmdline.Completer{cmdline.Words("bash", "zsh", "fish", "powershell")}},
		},
	}
}

// itemIDs offers the IDs from the config file named on the line so far.
func itemIDs(line *cmdline.Match, prefix string) ([]string, cmdline.Directive) {
	file := "prog.yaml"
	if v := line.Values("config"); v != nil {
		file = v[len(v)-1]
	}
	var out []string
	for _, id := range loadIDs(file) {
		if strings.HasPrefix(id, prefix) {
			out = append(out, id)
		}
	}
	return out, cmdline.NoFiles
}

func loadIDs(file string) []string {
	if file == "other.yaml" {
		return []string{"21", "22"}
	}
	return []string{"12", "13"}
}

func main() {
	os.Exit(run(os.Args[1:]))
}

func run(args []string) int {
	root := tree()
	if cmdline.Serve(os.Stdout, root, args) {
		return 0
	}
	m, err := cmdline.Parse(root, args)
	if e := (*cmdline.Error)(nil); errors.As(err, &e) {
		fmt.Fprintf(os.Stderr, "Error: %s.\n", usage(e))
		return 1
	}
	if m.Values("help") != nil || len(m.Command.Commands) > 0 {
		fmt.Printf("help of %q\n", strings.Join(m.Path, " "))
		return 0
	}
	switch strings.Join(m.Path, " ") {
	case "completion":
		if len(m.Args) != 1 || script.Write(os.Stdout, m.Args[0], root.Name) != nil {
			fmt.Fprintln(os.Stderr, "Error: completion takes bash, zsh, fish or powershell.")
			return 1
		}
	default:
		fmt.Printf("run %q flags=%v args=%q\n", strings.Join(m.Path, " "), m.Flags, m.Args)
	}
	return 0
}

// usage writes the program's own sentence from the error's fields.
func usage(e *cmdline.Error) string {
	where := strings.Join(append([]string{"prog"}, e.Path...), " ")
	switch e.Kind {
	case cmdline.UnknownCommand:
		return fmt.Sprintf("%q is not a command of `%s`", e.Word, where)
	case cmdline.UnknownFlag:
		return fmt.Sprintf("`%s` has no flag %s", where, e.Word)
	default: // cmdline.MissingValue
		return fmt.Sprintf("%s needs a value", e.Word)
	}
}
