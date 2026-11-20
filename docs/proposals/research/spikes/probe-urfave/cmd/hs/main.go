// Real binary for shell completion probes: stock urfave scripts plus a
// small per-flag value completer of ours on top of ShellComplete.
package main

import (
	"context"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
)

// values per flag name: what our specs would supply.
var values = map[string][]string{
	"output":  {"json"},
	"sort":    {"id", "name", "owner", "last-seen"},
	"columns": {"id", "name", "owner", "last-seen"},
}

// ours: complete the value of the flag that ends the line, else defer to
// the framework's default (subcommands or flag names).
func complete(ctx context.Context, c *cli.Command) {
	args := c.Args().Slice()
	if n := len(args); n > 0 && strings.HasPrefix(args[n-1], "-") {
		name := strings.TrimLeft(args[n-1], "-")
		for _, f := range c.Lineage() {
			for _, fl := range f.Flags {
				if slices.Contains(fl.Names(), name) {
					if vs, ok := values[fl.Names()[0]]; ok {
						for _, v := range vs {
							fmt.Fprintf(c.Root().Writer, "%s:value of --%s\n", v, fl.Names()[0])
						}
						return
					}
				}
			}
		}
	}
	cli.DefaultCompleteWithFlags(ctx, c)
}

func main() {
	leaf := func(name, usage string, fl ...cli.Flag) *cli.Command {
		return &cli.Command{Name: name, Usage: usage, Flags: fl, ShellComplete: complete,
			Action: func(ctx context.Context, c *cli.Command) error {
				fmt.Println("RAN", c.FullName(), c.Args().Slice())
				return nil
			}}
	}
	group := func(name, usage string, subs ...*cli.Command) *cli.Command {
		return &cli.Command{Name: name, Usage: usage, Commands: subs, ShellComplete: complete}
	}
	root := &cli.Command{
		Name:                  "hs",
		HideHelp:              true,
		EnableShellCompletion: true,
		ShellComplete:         complete,
		Flags: []cli.Flag{
			&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Usage: "config file"},
			&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Usage: "output format"},
		},
		Commands: []*cli.Command{
			group("nodes", "manage nodes",
				leaf("list", "list nodes",
					&cli.StringFlag{Name: "sort", Usage: "sort column"},
					&cli.StringFlag{Name: "columns", Usage: "columns to show"},
					&cli.StringSliceFlag{Name: "filter", Usage: "filter rows"}),
				leaf("delete", "delete a node", &cli.BoolFlag{Name: "force", Usage: "do not ask"}),
			),
			group("check", "local checks", leaf("config", "check a config file")),
		},
	}
	if err := root.Run(context.Background(), os.Args); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
