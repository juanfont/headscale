// Package creachadair is the kit adapter for github.com/creachadair/command:
// the kit's tree becomes a tree of command.C values parsed with stdlib flag
// and MergeFlags(true). Completion and its scripts are not in the library:
// Tab is answered by re-running the same tree on the words before the cursor
// and reading where it stopped; the scripts are cobra's, via the tempfork
// package in tailscale.com, which Headscale already requires.
package creachadair

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"

	"github.com/creachadair/command"
	"spike/kit"
	"tailscale.com/tempfork/spf13/cobra"
)

// Adapter implements kit.Adapter. It keeps no state between calls.
type Adapter struct{}

// val records every Set, so "given", "given twice" and "given empty" reach the kit.
type val struct {
	isBool bool
	vs     []string
}

func (v *val) Set(s string) error { v.vs = append(v.vs, s); return nil }
func (v *val) String() string     { return "" }
func (v *val) IsBoolFlag() bool   { return v.isBool }

// run is the state of one parse; a fresh one per call, because command.C
// keeps its flag set and stops calling SetFlags after the first parse.
type run struct {
	t    *kit.Tree
	vals map[string]map[string]*val // command path -> long name -> value
	last []string                   // path of the last command whose flags were set up: where parsing stopped
	tail []string                   // words after "--"
}

func key(path []string) string { return strings.Join(path, " ") }

// tree builds the command.C tree; act is called when a command is reached.
func (r *run) tree(act func(*command.Env, *kit.Command) error) *command.C {
	nodes := map[string]*command.C{}
	type alias struct{ copy, of *command.C }
	var aliases []alias
	for i := range r.t.Commands {
		c := &r.t.Commands[i]
		names := []string{""}
		if len(c.Path) > 0 {
			names = append([]string{c.Path[len(c.Path)-1]}, c.Aliases...)
		}
		for j, name := range names {
			n := &command.C{Name: name, SetFlags: r.setFlags(c), Run: func(env *command.Env) error { return act(env, c) }}
			if j > 0 {
				// No alias field in command.C: an alias is a second, unlisted node.
				n.Unlisted = true
				aliases = append(aliases, alias{n, nodes[key(c.Path)]})
			} else {
				nodes[key(c.Path)] = n
			}
			if len(c.Path) > 0 {
				p := nodes[key(c.Path[:len(c.Path)-1])]
				p.Commands = append(p.Commands, n)
			}
		}
	}
	for _, a := range aliases {
		a.copy.Commands = a.of.Commands
	}
	return nodes[""]
}

func (r *run) setFlags(c *kit.Command) func(*command.Env, *flag.FlagSet) {
	return func(_ *command.Env, fs *flag.FlagSet) {
		r.last = c.Path
		m := map[string]*val{}
		r.vals[key(c.Path)] = m
		for _, f := range c.Flags {
			// With merging, a root flag (-h, -o, -c, --version) is taken by the
			// root wherever it appears, so the leaf copy would never be set.
			if len(c.Path) > 0 && r.onRoot(f.Name) {
				continue
			}
			v := &val{isBool: f.Kind == kit.Bool}
			m[f.Name] = v
			fs.Var(v, f.Name, "")
			if f.Short != "" {
				fs.Var(v, f.Short, "")
			}
		}
	}
}

func (r *run) onRoot(name string) bool {
	return slices.ContainsFunc(r.t.Commands[0].Flags, func(f kit.Flag) bool { return f.Name == name })
}

// given is what the root and the reached command were given.
func (r *run) given(path []string) map[string][]string {
	out := map[string][]string{}
	for _, k := range []string{"", key(path)} {
		for name, v := range r.vals[k] {
			if len(v.vs) > 0 {
				out[name] = v.vs
			}
		}
	}
	return out
}

func envPath(env *command.Env) []string {
	var p []string
	for e := env; e.Parent != nil; e = e.Parent {
		p = append([]string{e.Command.Name}, p...)
	}
	return p
}

// WA: "--" is split off before the library sees argv. command treats "--"
// as a stop only when it is the first free word of a level, so after a
// positional it keeps parsing flags behind it and leaves "--" in Args.
func splitDashDash(argv []string) (head, tail []string) {
	if i := slices.Index(argv, "--"); i >= 0 { // WA
		return argv[:i], slices.Clone(argv[i+1:]) // WA
	} // WA
	return argv, nil
}

// usage turns a parse error into a kit.UsageError. command returns stdlib
// flag's errors and its own as plain strings, so the kind and the flag come
// from the message text, and the path from the last SetFlags call.
func (r *run) usage(err error, head []string) error {
	kinds := []struct {
		prefix string
		kind   kit.ErrKind
	}{
		{"flag provided but not defined: ", kit.UnknownFlag}, // WA
		{"bad flag syntax: ", kit.UnknownFlag},               // WA
		{"missing value for flag ", kit.MissingValue},        // WA
		{"flag needs an argument: ", kit.MissingValue},       // WA
	}
	for _, k := range kinds {
		word, ok := strings.CutPrefix(err.Error(), k.prefix) // WA
		if !ok {
			continue
		}
		if q, err := strconv.Unquote(word); err == nil { // WA
			word = q // WA
		}
		path := r.last
		// WA: a root flag with no value at the end of argv fails in the root's
		// pass, before any subcommand is reached; walk the command words to say
		// where it was.
		if k.kind == kit.MissingValue && len(path) == 0 { // WA
			path = r.walk(head) // WA
		}
		return &kit.UsageError{Kind: k.kind, Path: path, Word: word}
	}
	return err
}

// walk follows command names and aliases through argv, skipping other words.
func (r *run) walk(argv []string) []string { // WA
	var path []string        // WA
	for _, w := range argv { // WA
		for _, c := range r.t.Commands { // WA
			if len(c.Path) == len(path)+1 && slices.Equal(c.Path[:len(path)], path) && (c.Path[len(path)] == w || slices.Contains(c.Aliases, w)) { // WA
				path = c.Path // WA
				break         // WA
			} // WA
		} // WA
	} // WA
	return path // WA
}

func (r *run) parse(ctx context.Context, argv []string, log io.Writer, act func(*command.Env, *kit.Command) error) error {
	head, tail := splitDashDash(argv)
	r.tail = tail
	env := r.tree(act).NewEnv(nil).MergeFlags(true).SetContext(ctx)
	env.Log = log
	return command.Run(env, head)
}

func newRun(t *kit.Tree) *run { return &run{t: t, vals: map[string]map[string]*val{}} }

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	// WA: the hidden Tab entry point is taken before the library sees argv:
	// as a command node, the root's merge pass would take -o/-c/-h from the
	// words being completed.
	if len(argv) > 0 && argv[0] == "__complete" { // WA
		return complete(ctx, t, argv[1:], std.Out) // WA
	} // WA
	r := newRun(t)
	reached := false
	err := r.parse(ctx, argv, std.Err, func(env *command.Env, c *kit.Command) error {
		reached = true
		path, flags := envPath(env), r.given(c.Path)
		if slices.Equal(flags["help"], []string{"true"}) {
			return t.Exec(ctx, std, kit.Call{Path: path, Flags: map[string][]string{"help": {"true"}}})
		}
		if c.Leaf {
			// WA: stdlib flag stops at the first positional, so an unknown
			// flag after one is left in Args instead of being refused.
			for _, a := range env.Args { // WA
				if len(a) > 1 && a[0] == '-' { // WA
					return &kit.UsageError{Kind: kit.UnknownFlag, Path: path, Word: a} // WA
				} // WA
			} // WA
		}
		return t.Exec(ctx, std, kit.Call{Path: path, Flags: flags, Args: append(slices.Clone(env.Args), r.tail...)})
	})
	if err == nil || reached {
		return err
	}
	return r.usage(err, argv)
}

func (Adapter) Complete(ctx context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	cur := argv[len(argv)-1]
	r := newRun(t)
	var at *kit.Command
	var args []string
	err := r.parse(ctx, argv[:len(argv)-1], io.Discard, func(env *command.Env, c *kit.Command) error {
		at, args = c, env.Args
		return nil
	})
	if err != nil {
		// "--sort <Tab>": the flag before the cursor has no value yet.
		var ue *kit.UsageError
		if errors.As(r.usage(err, argv), &ue) && ue.Kind == kit.MissingValue {
			if f, ok := r.flag(r.last, ue.Word); ok {
				return kit.Completion{Words: values(f.Values, "", cur)}, nil
			}
		}
		return kit.Completion{}, nil
	}
	if r.tail == nil && strings.HasPrefix(cur, "-") {
		if name, v, ok := strings.Cut(cur, "="); ok {
			if f, ok := r.flag(at.Path, name); ok {
				return kit.Completion{Words: values(f.Values, "", v)}, nil // referee: the scripts put "--x=" back
			}
			return kit.Completion{}, nil
		}
		var words []string
		for _, f := range at.Flags {
			words = append(words, "--"+f.Name)
		}
		return kit.Completion{Words: prefixed(words, cur)}, nil
	}
	if !at.Leaf {
		if len(args) > 0 {
			return kit.Completion{}, nil
		}
		var words, aliases []string
		for _, c := range t.Commands {
			if len(c.Path) == len(at.Path)+1 && slices.Equal(c.Path[:len(at.Path)], at.Path) {
				words, aliases = append(words, c.Path[len(at.Path)]), append(aliases, c.Aliases...)
			}
		}
		if len(prefixed(words, cur)) == 0 { // referee D16: aliases only when no name fits
			words = aliases
		}
		return kit.Completion{Words: prefixed(words, cur)}, nil
	}
	if n := len(args) + len(r.tail); n < len(at.Args) {
		a := at.Args[n]
		return kit.Completion{Words: prefixed(a.Values, cur), Files: a.File}, nil
	}
	return kit.Completion{}, nil
}

// flag finds a flag by long name or letter on the command at path, then on the root.
func (r *run) flag(path []string, word string) (kit.Flag, bool) {
	name := strings.TrimLeft(word, "-")
	for _, p := range [][]string{path, nil} {
		for _, c := range r.t.Commands {
			if !slices.Equal(c.Path, p) {
				continue
			}
			for _, f := range c.Flags {
				if f.Name == name || f.Short == name {
					return f, true
				}
			}
		}
	}
	return kit.Flag{}, false
}

// values completes the last item of a comma list, keeping a +/- sign.
func values(vs []string, pre, cur string) []string {
	if i := strings.LastIndex(cur, ","); i >= 0 {
		pre, cur = pre+cur[:i+1], cur[i+1:]
	}
	if cur != "" && (cur[0] == '+' || cur[0] == '-') {
		pre, cur = pre+cur[:1], cur[1:]
	}
	var out []string
	for _, v := range prefixed(vs, cur) {
		out = append(out, pre+v)
	}
	return out
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

// complete answers the script's "headscale __complete <words>" in cobra's protocol.
func complete(ctx context.Context, t *kit.Tree, argv []string, w io.Writer) error {
	c, err := Adapter{}.Complete(ctx, t, argv)
	if err != nil {
		return err
	}
	dir := cobra.ShellCompDirectiveNoFileComp
	if c.Files {
		dir = cobra.ShellCompDirectiveDefault
	}
	for _, word := range c.Words {
		fmt.Fprintln(w, word)
	}
	_, err = fmt.Fprintf(w, ":%d\n", dir)
	return err
}

func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	gen := map[string]func(io.Writer, string, string, string) error{
		"bash": cobra.ScriptBash, "zsh": cobra.ScriptZsh, "fish": cobra.ScriptFish, "powershell": cobra.ScriptPowershell,
	}[shell]
	if gen == nil {
		return fmt.Errorf("no completion script for %q", shell)
	}
	return gen(w, kit.Program, "__complete", kit.Program)
}
