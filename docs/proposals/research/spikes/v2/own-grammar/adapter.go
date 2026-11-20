// Package own is the "no framework" adapter: a dispatcher over the tree, a
// parser for exactly the decided grammar, and a __complete answerer that the
// copied cobra scripts call at Tab time.
package own

import (
	"context"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"spike/kit"
	"spike/own-grammar/scripts"
)

type Adapter struct{}

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	cmd, vals, args, err := walk(t, argv)
	if err != nil {
		return err
	}
	return t.Exec(ctx, std, kit.Call{Path: cmd.Path, Flags: vals, Args: args})
}

func (Adapter) Complete(_ context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	words, dir := Complete(t, argv[:len(argv)-1], argv[len(argv)-1])
	return kit.Completion{Words: words, Files: dir&scripts.ShellCompDirectiveNoFileComp == 0}, nil
}

func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	if !scripts.Script(w, shell, kit.Program, true) {
		return fmt.Errorf("no completion script for %q", shell)
	}
	return nil
}

// parse reads flags out of argv: --name, --name=v, --name v, -x, -x=v, -x v.
// A value is taken verbatim, even "" or "-last-seen". -xvalue and grouped
// shorts are refused (D11). With stop it returns at the first positional or
// "--", left in rest, so walk can read a command word.
func parse(flags []kit.Flag, argv []string, stop bool) (map[string][]string, []string, error) {
	vals := map[string][]string{}
	var args []string
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" && !stop {
			return vals, append(args, argv[i+1:]...), nil
		}
		if a == "--" || len(a) < 2 || a[0] != '-' {
			if stop {
				return vals, argv[i:], nil
			}
			args = append(args, a)
			continue
		}
		short := a[1] != '-'
		name, val, hasVal := strings.Cut(strings.TrimLeft(a, "-"), "=")
		typed := a
		if hasVal {
			typed = a[:len(a)-len(val)-1]
		}
		i0 := slices.IndexFunc(flags, func(f kit.Flag) bool {
			return name != "" && (short && f.Short == name || !short && f.Name == name)
		})
		if i0 < 0 || strings.HasPrefix(a, "---") {
			return nil, nil, &kit.UsageError{Kind: kit.UnknownFlag, Word: typed}
		}
		f := flags[i0]
		switch {
		case hasVal: // a bool's "=maybe" is refused by the layer (D9)
		case f.Kind == kit.Bool:
			val = "true"
		case i+1 == len(argv):
			return nil, nil, &kit.UsageError{Kind: kit.MissingValue, Word: typed}
		default:
			i++
			val = argv[i]
		}
		vals[f.Name] = append(vals[f.Name], val)
	}
	return vals, args, nil
}

// child finds the command under path named word, by name or alias.
func child(t *kit.Tree, path []string, word string) *kit.Command {
	for i, c := range t.Commands {
		if len(c.Path) == len(path)+1 && slices.Equal(c.Path[:len(path)], path) &&
			(c.Path[len(path)] == word || slices.Contains(c.Aliases, word)) {
			return &t.Commands[i]
		}
	}
	return nil
}

// walk descends the tree. Before the leaf only the root's flags are read
// (D3); they are parsed again with the leaf's flags, so a leaf without -o
// refuses it and a repeat across both sides stays visible.
func walk(t *kit.Tree, argv []string) (*kit.Command, map[string][]string, []string, error) {
	root := &t.Commands[0]
	cmd, rest := root, argv
	var pre []string
	for !cmd.Leaf {
		vals, r, err := parse(root.Flags, rest, true)
		if err != nil {
			return nil, nil, nil, at(err, cmd.Path)
		}
		pre = append(pre, rest[:len(rest)-len(r)]...)
		if len(r) == 0 {
			return cmd, vals, nil, nil // group or root alone: the layer prints help (D10)
		}
		next := child(t, cmd.Path, r[0])
		if next == nil {
			return nil, nil, nil, &kit.UsageError{Kind: kit.UnknownCommand, Path: cmd.Path, Word: r[0]}
		}
		cmd, rest = next, r[1:]
	}
	vals, args, err := parse(cmd.Flags, append(pre, rest...), false)
	if err != nil {
		return nil, nil, nil, at(err, cmd.Path)
	}
	return cmd, vals, args, nil
}

func at(err error, path []string) error {
	var u *kit.UsageError
	if errors.As(err, &u) {
		u.Path = path
	}
	return err
}

// Complete answers cobra's __complete protocol: candidates ("word\thelp")
// and a directive. It reads no config and calls no server (D1).
func Complete(t *kit.Tree, words []string, cur string) ([]string, int) {
	root := &t.Commands[0]
	cmd, rest := root, words
	for !cmd.Leaf {
		_, r, err := parse(root.Flags, rest, true)
		var u *kit.UsageError
		if errors.As(err, &u) && u.Kind == kit.MissingValue { // "headscale -o <TAB>"
			return values(byTyped(root.Flags, u.Word), cur)
		}
		if err != nil || len(r) == 0 {
			break
		}
		if cmd = child(t, cmd.Path, r[0]); cmd == nil {
			return nil, scripts.ShellCompDirectiveNoFileComp
		}
		rest = r[1:]
	}
	if n := len(rest); n > 0 && !strings.Contains(rest[n-1], "=") {
		if f := byTyped(cmd.Flags, rest[n-1]); f != nil && f.Kind != kit.Bool {
			return values(f, cur)
		}
	}
	if name, val, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(cur, "-") {
		return values(byTyped(cmd.Flags, name), val) // the scripts put "--x=" back
	}
	var out []string
	add := func(word string) {
		if strings.HasPrefix(word, cur) {
			out = append(out, word)
		}
	}
	switch {
	case strings.HasPrefix(cur, "-") && !slices.Contains(rest, "--"): // referee N21
		for _, f := range cmd.Flags {
			add("--" + f.Name)
			if f.Short != "" && cur == "-"+f.Short {
				add(cur)
			}
		}
	case !cmd.Leaf:
		var kids []*kit.Command
		for i, c := range t.Commands {
			if len(c.Path) == len(cmd.Path)+1 && slices.Equal(c.Path[:len(cmd.Path)], cmd.Path) {
				kids = append(kids, &t.Commands[i])
				add(c.Path[len(cmd.Path)])
			}
		}
		if len(out) == 0 { // aliases only when no name fits, as cobra
			for _, c := range kids {
				for _, a := range c.Aliases {
					add(a)
				}
			}
		}
	default:
		_, args, err := parse(cmd.Flags, rest, false)
		if err != nil || len(args) >= len(cmd.Args) {
			break
		}
		if a := cmd.Args[len(args)]; a.File {
			return nil, scripts.ShellCompDirectiveDefault
		} else {
			for _, v := range a.Values {
				add(v)
			}
		}
	}
	return out, scripts.ShellCompDirectiveNoFileComp
}

func byTyped(flags []kit.Flag, typed string) *kit.Flag {
	name := strings.TrimLeft(typed, "-")
	for i, f := range flags {
		if strings.HasPrefix(typed, "--") && f.Name == name || !strings.HasPrefix(typed, "--") && f.Short == name {
			return &flags[i]
		}
	}
	return nil
}

// values completes a flag value. Every value list is read as comma separated
// with an optional +/- per item; the kit's tree does not say which flags are
// lists, a spec field type would.
func values(f *kit.Flag, cur string) ([]string, int) {
	dir := scripts.ShellCompDirectiveNoFileComp
	if f == nil {
		return nil, dir
	}
	head, item := "", cur
	if i := strings.LastIndex(cur, ","); i >= 0 {
		head, item = cur[:i+1], cur[i+1:]
		dir |= scripts.ShellCompDirectiveNoSpace
	}
	sign := ""
	if item != "" && (item[0] == '+' || item[0] == '-') {
		sign, item = item[:1], item[1:]
	}
	var out []string
	for _, v := range f.Values {
		if strings.HasPrefix(v, item) {
			out = append(out, head+sign+v)
		}
	}
	if f.Kind == kit.Strings {
		dir |= scripts.ShellCompDirectiveNoSpace // room for the operator: --filter name=
	}
	return out, dir
}

// Serve is the hidden __complete / __completeNoDesc entry point of the binary.
func Serve(t *kit.Tree, w io.Writer, args []string) {
	if len(args) == 0 {
		args = []string{""}
	}
	words, dir := Complete(t, args[:len(args)-1], args[len(args)-1])
	for _, word := range words {
		fmt.Fprintln(w, word)
	}
	fmt.Fprintf(w, ":%d\n", dir)
}
