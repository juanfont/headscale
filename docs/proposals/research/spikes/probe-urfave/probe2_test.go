package main

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/urfave/cli/v3"
)

// Our help flag must not trigger the framework's help printer.
func init() { cli.HelpFlag = nil }

// tree2: OnUsageError on every command, own completion command, own --help.
func tree2(log *[]string, out, errw *bytes.Buffer) *cli.Command {
	onUsage := func(ctx context.Context, c *cli.Command, err error, sub bool) error {
		*log = append(*log, fmt.Sprintf("usage-err path=%q args=%q err=%q", c.FullName(), c.Args().Slice(), err))
		return err
	}
	act := func(ctx context.Context, c *cli.Command) error {
		*log = append(*log, fmt.Sprintf("action path=%q args=%q help=%v", c.FullName(), c.Args().Slice(), c.Bool("help")))
		return nil
	}
	root := &cli.Command{
		Name: "headscale", HideHelp: true, HideVersion: true,
		EnableShellCompletion: true,
		ConfigureShellCompletionCommand: func(c *cli.Command) {
			c.Name = "__urfave_completion"
		},
		Writer: out, ErrWriter: errw,
		ExitErrHandler: func(context.Context, *cli.Command, error) {},
		Flags:          []cli.Flag{&cli.BoolFlag{Name: "help", Aliases: []string{"h"}}},
		Commands: []*cli.Command{
			{Name: "nodes", Commands: []*cli.Command{
				{Name: "list", Flags: []cli.Flag{&cli.StringFlag{Name: "sort", Local: true}}},
			}},
			{Name: "completion", Commands: []*cli.Command{{Name: "bash"}}},
		},
	}
	_ = root.Walk(func(c *cli.Command) error {
		c.OnUsageError = onUsage
		c.Action = act
		return nil
	})
	return root
}

func TestProbe2(t *testing.T) {
	for _, argv := range [][]string{
		{"nodes", "list", "--force"},
		{"nodes", "frob", "--force"},
		{"--help", "nodes"},
		{"nodes", "list", "--help"},
		{"completion", "bash"},
		{"__urfave_completion", "bash"},
		{"nodes", "list", "--sort", "x", "--sort", "--help"},
	} {
		var log []string
		var out, errw bytes.Buffer
		err := tree2(&log, &out, &errw).Run(context.Background(), append([]string{"headscale"}, argv...))
		t.Logf("%q\n    log=%q err=%v stdout=%d bytes %q stderr=%q", argv, log, err, out.Len(), first(out.String()), errw.String())
	}
}

func first(s string) string {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		return s[:i]
	}
	return s
}

// Fresh tree per case, run in parallel: must be race-free (run with -race).
func TestParallel(t *testing.T) {
	for i := range 64 {
		t.Run(fmt.Sprint(i), func(t *testing.T) {
			t.Parallel()
			var log []string
			var out, errw bytes.Buffer
			err := tree2(&log, &out, &errw).Run(context.Background(),
				[]string{"headscale", "nodes", "list", "--sort", fmt.Sprint(i), "--generate-shell-completion"})
			if err != nil {
				t.Fatal(err)
			}
			var log2 []string
			if err := tree2(&log2, &out, &errw).Run(context.Background(),
				[]string{"headscale", "nodes", "list", "--sort", fmt.Sprint(i)}); err != nil || len(log2) != 1 {
				t.Fatalf("err=%v log=%v", err, log2)
			}
		})
	}
}
