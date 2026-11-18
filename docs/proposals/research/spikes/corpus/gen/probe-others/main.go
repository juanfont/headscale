// Probe: argv -> outcome for kong, urfave/cli v3, ff v4 on a pf-like tree.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/alecthomas/kong"
	ff "github.com/peterbourgon/ff/v4"
	cli "github.com/urfave/cli/v3"
)

type kongCLI struct {
	Config string `short:"c"`
	Run    struct {
		Bool    bool     `short:"b"`
		Verbose bool     `short:"v"`
		String  string   `short:"s"`
		File    *string  `short:"f"`
		List    []string `short:"l"`
		Args    []string `arg:"" optional:""`
	} `cmd:"" aliases:"r"`
	Grp struct {
		Sub struct {
			A string `arg:"" optional:""`
		} `cmd:"" aliases:"s"`
	} `cmd:""`
}

func probeKong(argv []string) string {
	var c kongCLI
	p, err := kong.New(&c, kong.Name("k"), kong.Exit(func(int) {}), kong.Writers(io.Discard, io.Discard))
	if err != nil {
		return "new: " + err.Error()
	}
	ctx, err := p.Parse(argv)
	if err != nil {
		return "ERR " + err.Error()
	}
	f := "<nil>"
	if c.Run.File != nil {
		f = fmt.Sprintf("%q", *c.Run.File)
	}
	return fmt.Sprintf("cmd=%q config=%q bool=%v verbose=%v string=%q file=%s list=%q args=%q", ctx.Command(), c.Config, c.Run.Bool, c.Run.Verbose, c.Run.String, f, c.Run.List, c.Run.Args)
}

func probeUrfave(argv []string) string {
	out := "action not run"
	act := func(_ context.Context, cmd *cli.Command) error {
		out = fmt.Sprintf("cmd=%q config=%q bool=%v verbose=%v string=%q file=%q(set=%v) list=%q args=%q", cmd.Name, cmd.String("config"), cmd.Bool("bool"), cmd.Bool("verbose"), cmd.String("string"), cmd.String("file"), cmd.IsSet("file"), cmd.StringSlice("list"), cmd.Args().Slice())
		return nil
	}
	root := &cli.Command{
		Name: "u", Writer: io.Discard, ErrWriter: io.Discard, ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Flags: []cli.Flag{&cli.StringFlag{Name: "config", Aliases: []string{"c"}}},
		Commands: []*cli.Command{
			{Name: "run", Aliases: []string{"r"}, Action: act, Flags: []cli.Flag{
				&cli.BoolFlag{Name: "bool", Aliases: []string{"b"}},
				&cli.BoolFlag{Name: "verbose", Aliases: []string{"v"}},
				&cli.StringFlag{Name: "string", Aliases: []string{"s"}},
				&cli.StringFlag{Name: "file", Aliases: []string{"f"}},
				&cli.StringSliceFlag{Name: "list", Aliases: []string{"l"}},
			}},
			{Name: "grp", Commands: []*cli.Command{{Name: "sub", Aliases: []string{"s"}, Action: act}}},
		},
	}
	if os.Getenv("SHORT") != "" {
		root.UseShortOptionHandling = true
	}
	err := root.Run(context.Background(), append([]string{"u"}, argv...))
	if err != nil {
		return "ERR " + err.Error() + " | " + out
	}
	return out
}

func probeFF(argv []string) string {
	out := "exec not run"
	rootFS := ff.NewFlagSet("root")
	config := rootFS.StringLong("config", "", "")
	runFS := ff.NewFlagSet("run").SetParent(rootFS)
	b := runFS.Bool('b', "bool", "")
	v := runFS.Bool('v', "verbose", "")
	s := runFS.String('s', "string", "", "")
	f := runFS.String('f', "file", "", "")
	run := &ff.Command{Name: "run", Flags: runFS, Exec: func(_ context.Context, args []string) error {
		out = fmt.Sprintf("cmd=run config=%q bool=%v verbose=%v string=%q file=%q args=%q", *config, *b, *v, *s, *f, args)
		return nil
	}}
	root := &ff.Command{Name: "f", Flags: rootFS, Subcommands: []*ff.Command{run}}
	if err := root.ParseAndRun(context.Background(), argv); err != nil {
		return "ERR " + err.Error() + " | " + out
	}
	return out
}

func main() {
	for _, line := range strings.Split(strings.TrimSpace(os.Args[1]), "\n") {
		argv := strings.Fields(line)
		for i, a := range argv {
			switch a {
			case "EMPTY":
				argv[i] = ""
			}
			argv[i] = strings.ReplaceAll(argv[i], "_SP_", " ")
		}
		fmt.Printf("argv %q\n  kong:   %s\n  urfave: %s\n  ff:     %s\n", argv, probeKong(argv), probeUrfave(argv), probeFF(argv))
	}
}
