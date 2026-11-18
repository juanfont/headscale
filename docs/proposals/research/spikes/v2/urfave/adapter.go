// Package urfave is the urfave/cli v3 adapter for the CLI framework bake-off.
// It is the only file that imports the framework.
package urfave

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"
	"tailscale.com/tempfork/spf13/cobra"

	"spike/kit"
)

// WA: a flag named "help" on any command makes urfave print its own help
// template instead of running the Action, even with HideHelp. The only off
// switch is this package global. It is written once, before any run.
func init() { cli.HelpFlag = nil } // WA

// completionMarker is how urfave's scripts ask the binary for candidates:
// they append it to the words before the cursor.
const completionMarker = "--generate-shell-completion"

// scriptCmd is urfave's own completion-script command, renamed so the spec
// tree's `completion` leaf keeps its name.
const scriptCmd = "__urfave_completion"

type Adapter struct{}

// kflag records every value in order and whether it was given; the kit
// decides what repeats and bool spellings mean.
type kflag struct {
	f     kit.Flag
	local bool
	vals  []string
}

func (k *kflag) String() string        { return k.f.Name }
func (k *kflag) Get() any              { return k.vals }
func (k *kflag) PreParse() error       { return nil }
func (k *kflag) PostParse() error      { return nil }
func (k *kflag) Set(_, v string) error { k.vals = append(k.vals, v); return nil }
func (k *kflag) IsSet() bool           { return len(k.vals) > 0 }
func (k *kflag) IsBoolFlag() bool      { return k.f.Kind == kit.Bool }
func (k *kflag) IsLocal() bool         { return k.local }
func (k *kflag) Names() []string {
	if k.f.Short != "" {
		return []string{k.f.Name, k.f.Short}
	}
	return []string{k.f.Name}
}

// build turns the kit's tree into urfave commands. Every command runs the
// same Action and the same error hook; out receives completion output.
// tab is one Tab request (referee): the word under the cursor and the answer.
type tab struct {
	cur  string
	comp kit.Completion
}

func build(t *kit.Tree, std kit.Stdio, out io.Writer, tb *tab) *cli.Command {
	byPath := map[string]*cli.Command{}
	specs := map[*cli.Command]*kit.Command{}
	var root *cli.Command
	for i := range t.Commands {
		kc := &t.Commands[i]
		c := &cli.Command{Aliases: kc.Aliases}
		for _, f := range kc.Flags {
			// on the root, -o and -c are persistent so they parse before the
			// subcommand (D3); everything else is local to its command
			c.Flags = append(c.Flags, &kflag{f: f, local: !(len(kc.Path) == 0 && f.Global)})
		}
		specs[c] = kc
		c.ShellComplete = func(ctx context.Context, cmd *cli.Command) {
			if tb != nil {
				complete(t, kc, cmd, tb)
			}
		}
		c.Action = func(ctx context.Context, cmd *cli.Command) error { return t.Exec(ctx, std, call(cmd)) }
		c.OnUsageError = func(ctx context.Context, cmd *cli.Command, err error, _ bool) error {
			return usageError(ctx, t, std, kc, cmd, err)
		}
		if len(kc.Path) == 0 {
			root = c
			c.Name = kit.Program
			continue
		}
		c.Name = kc.Path[len(kc.Path)-1]
		parent := byPath[strings.Join(kc.Path[:len(kc.Path)-1], " ")]
		if len(kc.Path) == 1 {
			parent = root
		}
		parent.Commands = append(parent.Commands, c)
		byPath[strings.Join(kc.Path, " ")] = c
	}
	root.HideHelp = true
	root.HideVersion = true
	root.EnableShellCompletion = true
	root.ShellCompletionCommandName = scriptCmd
	root.Reader = strings.NewReader("")
	root.Writer = out
	root.ErrWriter = io.Discard
	root.ExitErrHandler = func(context.Context, *cli.Command, error) {}
	return root
}

// call reads what urfave parsed along the path to cmd.
func call(cmd *cli.Command) kit.Call {
	c := kit.Call{Path: path(cmd), Flags: map[string][]string{}, Args: cmd.Args().Slice()}
	lineage := cmd.Lineage()
	slices.Reverse(lineage)
	for _, lc := range lineage {
		for _, f := range lc.Flags {
			if k := f.(*kflag); k.IsSet() {
				c.Flags[k.f.Name] = append(c.Flags[k.f.Name], k.vals...)
			}
		}
	}
	return c
}

func path(cmd *cli.Command) []string {
	p := []string{}
	for _, c := range cmd.Lineage() {
		if c.Root() != c {
			p = append([]string{c.Name}, p...)
		}
	}
	return p
}

// usageError turns urfave's parse error into the kit's typed error. urfave
// has no error types (D4), so the reason comes from the message text.
func usageError(ctx context.Context, t *kit.Tree, std kit.Stdio, kc *kit.Command, cmd *cli.Command, err error) error {
	c := call(cmd)
	if slices.Contains(c.Flags["help"], "true") { // -h before the bad word wins (R53)
		return t.Exec(ctx, std, kit.Call{Path: c.Path, Flags: map[string][]string{"help": {"true"}}})
	}
	if !kc.Leaf && len(c.Args) > 0 { // `nodes frob --force`: the word is the error
		return t.Exec(ctx, std, kit.Call{Path: c.Path, Args: c.Args})
	}
	// WA: map the message text of urfave's three parse errors to kinds.
	msg := err.Error()                                                          // WA
	if w, ok := strings.CutPrefix(msg, "flag provided but not defined: "); ok { // WA
		return &kit.UsageError{Kind: kit.UnknownFlag, Path: c.Path, Word: w} // WA
	}
	if w, ok := strings.CutPrefix(msg, "flag needs an argument: "); ok { // WA
		return &kit.UsageError{Kind: kit.MissingValue, Path: c.Path, Word: w} // WA
	}
	if _, rest, ok := strings.Cut(msg, " for flag "); ok { // WA
		w, _, _ := strings.Cut(rest, ":")                                 // WA
		return &kit.UsageError{Kind: kit.BadValue, Path: c.Path, Word: w} // WA
	}
	return err
}

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	return build(t, std, std.Out, nil).Run(ctx, append([]string{kit.Program}, argv...))
}

// complete is urfave's ShellComplete hook (referee rewrite): urfave parsed the
// words before the cursor; the word under it comes from the cobra-protocol
// request, which urfave's own scripts never send.
func complete(t *kit.Tree, kc *kit.Command, cmd *cli.Command, tb *tab) {
	args, cur := cmd.Args().Slice(), tb.cur
	if n := len(args); n > 0 && strings.HasPrefix(args[n-1], "-") && args[n-1] != "--" {
		last := strings.TrimLeft(args[n-1], "-")
		for _, f := range append(slices.Clone(kc.Flags), t.Commands[0].Flags...) {
			if f.Kind != kit.Bool && (last == f.Name || last == f.Short) {
				tb.comp.Words = listValues(f.Values, cur)
				return
			}
		}
	}
	if name, v, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(cur, "-") {
		for _, f := range kc.Flags {
			if "--"+f.Name == name {
				tb.comp.Words = listValues(f.Values, v) // the scripts put "--x=" back
			}
		}
		return
	}
	var words, aliases []string
	switch {
	case strings.HasPrefix(cur, "-"):
		for _, f := range kc.Flags {
			words = append(words, "--"+f.Name)
		}
	case !kc.Leaf:
		for _, c := range t.Commands {
			if len(c.Path) == len(kc.Path)+1 && slices.Equal(c.Path[:len(kc.Path)], kc.Path) {
				words, aliases = append(words, c.Path[len(c.Path)-1]), append(aliases, c.Aliases...)
			}
		}
		if len(prefixed(words, cur)) == 0 { // D16
			words = aliases
		}
	case len(args) < len(kc.Args):
		words, tb.comp.Files = kc.Args[len(args)].Values, kc.Args[len(args)].File
	}
	tb.comp.Words = prefixed(words, cur)
}

func prefixed(words []string, cur string) []string {
	var out []string
	for _, w := range words {
		if strings.HasPrefix(w, cur) {
			out = append(out, w)
		}
	}
	return out
}

// listValues completes the last item of a comma list, keeping a +/- sign.
func listValues(vals []string, cur string) []string {
	head, last := "", cur
	if i := strings.LastIndex(cur, ","); i >= 0 {
		head, last = cur[:i+1], cur[i+1:]
	}
	if last != "" && (last[0] == '+' || last[0] == '-') {
		head, last = head+last[:1], last[1:]
	}
	var out []string
	for _, v := range prefixed(vals, last) {
		out = append(out, head+v)
	}
	return out
}

// Complete answers `headscale __complete <words…> <cur>`: urfave parses the
// words before the cursor in its completion mode and the hook answers.
func (Adapter) Complete(ctx context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	tb := &tab{cur: argv[len(argv)-1]}
	std := kit.Stdio{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard}
	req := append(append([]string{kit.Program}, argv[:len(argv)-1]...), completionMarker)
	if err := build(t, std, io.Discard, tb).Run(ctx, req); err != nil {
		return kit.Completion{}, err
	}
	return tb.comp, nil
}

// Answer prints a Completion in cobra's __complete format.
func Answer(w io.Writer, c kit.Completion) {
	for _, s := range c.Words {
		fmt.Fprintln(w, s)
	}
	dir := cobra.ShellCompDirectiveNoFileComp
	if c.Files {
		dir = cobra.ShellCompDirectiveDefault
	}
	fmt.Fprintf(w, ":%d\n", dir)
}

// Script writes cobra's scripts as Tailscale vendors them (Apache-2.0).
func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	gen := map[string]func(io.Writer, string, string, string) error{
		"bash": cobra.ScriptBash, "zsh": cobra.ScriptZsh, "fish": cobra.ScriptFish, "powershell": cobra.ScriptPowershell,
	}[shell]
	if gen == nil {
		return fmt.Errorf("no completion script for %q", shell)
	}
	return gen(w, kit.Program, "__complete", kit.Program)
}

var _ kit.Adapter = Adapter{}
