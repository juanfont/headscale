// Probe of urfave/cli v3 parsing, errors and completion for the Headscale
// framework choice. Throwaway: prints one line per argv case.
package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/urfave/cli/v3"
)

type result struct {
	path  string
	args  []string
	flags map[string]string
}

// variant knobs
type opts struct {
	shortOpt    bool // UseShortOptionHandling on root
	persistent  bool // -c/-o persistent on root (Local=false); else Local on root + local on leaves
	onlyOnce    bool // OnlyOnce on --sort
	enableCompl bool
	customCompl bool
}

func build(o opts, res *result, out, errw *bytes.Buffer) *cli.Command {
	leaf := func(name string, aliases []string, fl ...cli.Flag) *cli.Command {
		return &cli.Command{
			Name: name, Aliases: aliases, Flags: fl,
			Action: func(ctx context.Context, c *cli.Command) error {
				res.path = c.FullName()
				res.args = c.Args().Slice()
				res.flags = map[string]string{}
				for _, lc := range c.Lineage() {
					for _, f := range lc.Flags {
						if f.IsSet() {
							n := f.Names()[0]
							cnt := 0
							if cf, ok := f.(interface{ Count() int }); ok {
								cnt = cf.Count()
							}
							res.flags[n] = fmt.Sprintf("%q(n=%d,on=%s)", fmt.Sprint(f.Get()), cnt, lc.Name)
						}
					}
				}
				return nil
			},
		}
	}
	str := func(name, short string, local bool) cli.Flag {
		f := &cli.StringFlag{Name: name, Local: local}
		if short != "" {
			f.Aliases = []string{short}
		}
		return f
	}
	boolf := func(name string) cli.Flag { return &cli.BoolFlag{Name: name, Local: true} }
	outFlag := func() cli.Flag { return str("output", "o", true) }
	cfgFlag := func() cli.Flag { return str("config", "c", true) }
	sort := &cli.StringFlag{Name: "sort", Local: true, OnlyOnce: o.onlyOnce}
	listFlags := func() []cli.Flag {
		fl := []cli.Flag{sort, str("columns", "", true), &cli.StringSliceFlag{Name: "filter", Local: true}}
		if !o.persistent {
			fl = append(fl, outFlag(), cfgFlag())
		}
		return fl
	}
	srv := func(fl ...cli.Flag) []cli.Flag {
		if !o.persistent {
			fl = append(fl, outFlag(), cfgFlag())
		}
		return fl
	}
	group := func(name string, subs ...*cli.Command) *cli.Command {
		return &cli.Command{
			Name: name, Commands: subs,
			Action: func(ctx context.Context, c *cli.Command) error {
				res.path = "GROUP:" + c.FullName()
				res.args = c.Args().Slice()
				return nil
			},
		}
	}
	rootFlags := []cli.Flag{
		&cli.StringFlag{Name: "config", Aliases: []string{"c"}, Local: !o.persistent},
		&cli.StringFlag{Name: "output", Aliases: []string{"o"}, Local: !o.persistent},
		&cli.BoolFlag{Name: "version", Local: true},
		&cli.BoolFlag{Name: "help", Aliases: []string{"h"}}, // persistent: every command
	}
	nodes := group("nodes",
		leaf("list", []string{"ls"}, listFlags()...),
		leaf("delete", []string{"rm"}, srv(boolf("force"))...),
		leaf("set", nil, srv(str("name", "", true), str("expiry", "e", true))...),
		group("routes", leaf("set", []string{"approve"}, srv()...)),
	)
	root := &cli.Command{
		Name:                      "headscale",
		HideHelp:                  true,
		HideVersion:               true,
		EnableShellCompletion:     o.enableCompl,
		UseShortOptionHandling:    o.shortOpt,
		DisableSliceFlagSeparator: true,
		Writer:                    out,
		ErrWriter:                 errw,
		Reader:                    strings.NewReader(""),
		ExitErrHandler:            func(context.Context, *cli.Command, error) {},
		OnUsageError: func(ctx context.Context, c *cli.Command, err error, sub bool) error {
			return fmt.Errorf("USAGE[%s]: %w", c.FullName(), err)
		},
		Flags: rootFlags,
		Action: func(ctx context.Context, c *cli.Command) error {
			res.path = "ROOT"
			res.args = c.Args().Slice()
			res.flags = map[string]string{}
			for _, f := range c.Flags {
				if f.IsSet() {
					res.flags[f.Names()[0]] = fmt.Sprint(f.Get())
				}
			}
			return nil
		},
		Commands: []*cli.Command{
			nodes,
			group("check", leaf("config", nil)),
			group("policy", leaf("set", nil, srv()...)),
			group("api", group("oauth-clients", leaf("delete", []string{"rm"}, srv(boolf("force"))...))),
		},
	}
	if o.customCompl {
		var walk func(c *cli.Command)
		walk = func(c *cli.Command) {
			c.ShellComplete = func(ctx context.Context, c *cli.Command) {
				fmt.Fprintf(c.Root().Writer, "COMPLETE cmd=%q args=%q\n", c.FullName(), c.Args().Slice())
			}
			for _, s := range c.Commands {
				walk(s)
			}
		}
		walk(root)
	}
	return root
}

func run(o opts, argv ...string) string {
	var res result
	var out, errw bytes.Buffer
	root := build(o, &res, &out, &errw)
	err := root.Run(context.Background(), append([]string{"headscale"}, argv...))
	var b strings.Builder
	fmt.Fprintf(&b, "%-55q -> ", argv)
	if err != nil {
		fmt.Fprintf(&b, "ERR(%T): %v", errors.Unwrap(err), err)
	} else {
		fmt.Fprintf(&b, "path=%s args=%q flags=%v", res.path, res.args, res.flags)
	}
	if out.Len() > 0 {
		fmt.Fprintf(&b, " | STDOUT=%q", trunc(out.String()))
	}
	if errw.Len() > 0 {
		fmt.Fprintf(&b, " | STDERR=%q", trunc(errw.String()))
	}
	return b.String()
}

func trunc(s string) string {
	if len(s) > 160 {
		return s[:160] + "..."
	}
	return s
}

func main() {
	base := opts{persistent: true, enableCompl: true}
	section := func(t string) { fmt.Println("\n## " + t) }

	section("A. tree, aliases, unknown commands (persistent -c/-o on root)")
	for _, a := range [][]string{
		{"api", "oauth-clients", "delete", "c9f2", "--force"},
		{"nodes", "rm", "12"},
		{"nodes", "routes", "approve", "12", "10.0.0.0/8"},
		{"node", "ls"},
		{"nodes", "frob", "12"},
		{"nodes", "routes"},
		{},
		{"help"},
		{"nodes", "help"},
		{"nod", "list"},
		{"completion", "bash"},
	} {
		fmt.Println(run(base, a...))
	}

	section("B. flags: interspersed, dash values, = values, empty, repeats")
	for _, a := range [][]string{
		{"nodes", "delete", "--force", "12"},
		{"nodes", "delete", "12", "--force"},
		{"nodes", "list", "--sort", "-last-seen"},
		{"nodes", "list", "--columns", "-ip,-os"},
		{"nodes", "list", "--filter=owner=tag:ci", "--filter", "last-seen>30d", "--filter", "name:web,online=true"},
		{"nodes", "set", "12", "--name", ""},
		{"nodes", "set", "12", "--name="},
		{"nodes", "set", "12"},
		{"nodes", "list", "--sort", "a", "--sort", "b"},
		{"nodes", "set", "12", "-e", "90d"},
		{"nodes", "set", "12", "-e90d"},
		{"nodes", "set", "12", "-e=90d"},
		{"nodes", "list", "-o", "json"},
		{"nodes", "list", "-ojson"},
		{"nodes", "list", "-o=json"},
		{"nodes", "list", "--output=json"},
		{"nodes", "list", "--exp"},
		{"nodes", "set", "12", "--exp", "1h"},
	} {
		fmt.Println(run(base, a...))
	}
	fmt.Println("OnlyOnce on --sort:")
	fmt.Println(run(opts{persistent: true, onlyOnce: true}, "nodes", "list", "--sort", "a", "--sort", "b"))
	fmt.Println("UseShortOptionHandling:")
	for _, a := range [][]string{
		{"nodes", "list", "-ojson"},
		{"nodes", "list", "-o", "json"},
		{"nodes", "set", "12", "-e90d"},
	} {
		fmt.Println(run(opts{persistent: true, shortOpt: true}, a...))
	}

	section("C. bools, --, dash positionals, odd positionals")
	for _, a := range [][]string{
		{"nodes", "delete", "12", "--force=false"},
		{"nodes", "delete", "12", "--force", "false"},
		{"nodes", "delete", "12", "--force=maybe"},
		{"nodes", "delete", "--", "-x"},
		{"nodes", "delete", "12", "--", "--force"},
		{"policy", "set", "-"},
		{"nodes", "delete", "-5", "--force"},
		{"nodes", "delete", "hskey-auth-ab12cd-***"},
		{"nodes", "delete", " --force"},
		{"nodes", "routes", "set", "12", ""},
		{"nodes", "delete", "list"},
	} {
		fmt.Println(run(base, a...))
	}

	section("D. errors: unknown flag, missing value")
	for _, a := range [][]string{
		{"nodes", "list", "--force"},
		{"nodes", "list", "-r"},
		{"nodes", "list", "--sort"},
		{"nodes", "set", "12", "-e"},
		{"--bogus", "nodes", "list"},
		{"nodes", "--bogus", "list"},
	} {
		fmt.Println(run(base, a...))
	}

	section("E. D3 placement: persistent on root")
	for _, a := range [][]string{
		{"-c", "x", "nodes", "list"},
		{"nodes", "list", "-c", "x"},
		{"nodes", "-c", "x", "list"},
		{"-o", "json", "check", "config"},
		{"check", "config", "-o", "json"},
		{"-o", "json", "nodes", "list", "-o", "yaml"},
	} {
		fmt.Println(run(base, a...))
	}
	section("E2. D3 placement: Local on root + local on server leaves")
	lo := opts{persistent: false, enableCompl: true}
	for _, a := range [][]string{
		{"-c", "x", "nodes", "list"},
		{"nodes", "list", "-c", "x"},
		{"nodes", "-c", "x", "list"},
		{"-o", "json", "check", "config"},
		{"check", "config", "-o", "json"},
		{"-o", "json", "nodes", "list", "-o", "yaml"},
	} {
		fmt.Println(run(lo, a...))
	}

	section("F. help and version (own flags; HideHelp)")
	for _, a := range [][]string{
		{"nodes", "delete", "--help"},
		{"--help", "nodes"},
		{"nodes", "-h"},
		{"nodes", "list", "--bogus", "--help"},
		{"--version"},
		{"nodes", "list", "--version"},
	} {
		fmt.Println(run(base, a...))
	}

	section("G. completion: default ShellComplete")
	g := "--generate-shell-completion"
	for _, a := range [][]string{
		{"nodes", g},
		{"nodes", "list", "--s", g},
		{"nodes", "list", "--sort", g},
		{"nodes", "list", "--sort", "-la", g},
		{"nodes", "list", "--columns", "id,na", g},
		{"nodes", "list", "-", g},
		{"nodes", "list", "--", g},
		{"nodes", "delete", "--", "x", g},
		{"node", g},
		{g},
	} {
		fmt.Println(run(base, a...))
	}
	section("G2. completion: custom ShellComplete sees")
	cc := opts{persistent: true, enableCompl: true, customCompl: true}
	for _, a := range [][]string{
		{"nodes", g},
		{"nodes", "list", "--sort", g},
		{"nodes", "list", "--sort", "-la", g},
		{"nodes", "list", "--sort", "=", g},
		{"nodes", "list", "--columns", "id,na", g},
		{"nodes", "set", "12", "--name", g},
		{"nodes", "list", "--bogus", g},
		{"nodes", "delete", "12", g},
		{"-c", g},
	} {
		fmt.Println(run(cc, a...))
	}
	section("G3. completion disabled: the marker is a normal arg")
	fmt.Println(run(opts{persistent: true}, "nodes", "list", g))

	section("H. tree reuse: run the same *Command twice")
	{
		var res result
		var out, errw bytes.Buffer
		root := build(base, &res, &out, &errw)
		_ = root.Run(context.Background(), []string{"headscale", "nodes", "list", "--sort", "a"})
		fmt.Printf("first:  %v\n", res.flags)
		res = result{}
		err := root.Run(context.Background(), []string{"headscale", "nodes", "list"})
		fmt.Printf("second: err=%v flags=%v (sort must be unset)\n", err, res.flags)
	}
	_ = os.Stdout
}
