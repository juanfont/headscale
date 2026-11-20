// Package urfave is the urfave/cli v3 adapter for the CLI framework bake-off.
// It is the only file that imports the framework.
package urfave

import (
	"bytes"
	"context"
	"io"
	"slices"
	"strings"

	"github.com/urfave/cli/v3"

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
func build(t *kit.Tree, std kit.Stdio, out io.Writer) *cli.Command {
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
		c.ShellComplete = func(ctx context.Context, cmd *cli.Command) { complete(t, kc, cmd) }
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
	return build(t, std, std.Out).Run(ctx, append([]string{kit.Program}, argv...))
}

// complete is urfave's ShellComplete hook: it prints one candidate per line
// for the command the parser reached. urfave's scripts send the word under the
// cursor only when it starts with "-", so this sees the words before it.
func complete(t *kit.Tree, kc *kit.Command, cmd *cli.Command) {
	w := cmd.Root().Writer
	args := cmd.Args().Slice()
	if n := len(args); n > 0 && strings.HasPrefix(args[n-1], "-") {
		last := strings.TrimLeft(args[n-1], "-")
		for _, f := range append(slices.Clone(kc.Flags), t.Commands[0].Flags...) {
			if f.Kind != kit.Bool && (last == f.Name || last == f.Short) && args[n-1] != "--" {
				for _, v := range f.Values {
					io.WriteString(w, v+"\n")
				}
				return
			}
		}
		for _, f := range kc.Flags {
			io.WriteString(w, "--"+f.Name+"\n")
		}
		return
	}
	if !kc.Leaf {
		for _, c := range t.Commands {
			if len(c.Path) == len(kc.Path)+1 && slices.Equal(c.Path[:len(kc.Path)], kc.Path) {
				for _, name := range append([]string{c.Path[len(c.Path)-1]}, c.Aliases...) {
					io.WriteString(w, name+"\n")
				}
			}
		}
		return
	}
	if len(args) < len(kc.Args) {
		for _, v := range kc.Args[len(args)].Values {
			io.WriteString(w, v+"\n")
		}
	}
}

// Complete drives the binary the way urfave's bash script does at Tab time,
// then does what the script does with the answer: keep the lines that start
// with the current word, and fall back to files when there are none.
func (Adapter) Complete(ctx context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	words, cur := argv[:len(argv)-1], argv[len(argv)-1]
	req := append([]string{kit.Program}, words...)
	if strings.HasPrefix(cur, "-") {
		req = append(req, cur)
	}
	var out bytes.Buffer
	std := kit.Stdio{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard}
	if err := build(t, std, &out).Run(ctx, append(req, completionMarker)); err != nil {
		return kit.Completion{}, err
	}
	var comp kit.Completion
	for line := range strings.Lines(out.String()) {
		tok, _, _ := strings.Cut(strings.TrimSpace(line), ":")
		if tok != "" && strings.HasPrefix(tok, cur) {
			comp.Words = append(comp.Words, tok)
		}
	}
	comp.Files = len(comp.Words) == 0 // bash -o default and zsh _files
	return comp, nil
}

// Script runs urfave's own (hidden, renamed) completion command; the script
// renderers are not exported.
func (Adapter) Script(t *kit.Tree, shell string, w io.Writer) error {
	if shell == "powershell" {
		shell = "pwsh"
	}
	std := kit.Stdio{In: strings.NewReader(""), Out: io.Discard, Err: io.Discard}
	return build(t, std, w).Run(context.Background(), []string{kit.Program, scriptCmd, shell})
}

var _ kit.Adapter = Adapter{}
