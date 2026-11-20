// Package headscale is Headscale's layer over the cmdline library, as far as
// the kit models it: it turns the kit's tree of specs into the library's,
// maps the library's errors to the kit's, and holds Headscale's own Tab
// convention for list values. Everything else of the layer (repeats, bool
// words, help, --version, argument counts, lists) is the kit's Exec, which
// stands for 001's builder.
package headscale

import (
	"context"
	"errors"
	"io"
	"strings"

	"spike/cmdline"
	"spike/cmdline/script"
	"spike/kit"
)

type Adapter struct{}

// Run hands the builder (the kit's Exec) what the parser read, in the order
// typed, and the parser's own mistake if it had one: the builder reports the
// first mistake on the line, whatever its kind (D35).
func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	m, err := cmdline.Parse(Root(t), argv)
	c := kit.Call{Path: m.Path, Flags: map[string][]string{}, Args: m.Args, ArgAt: m.ArgAt}
	for _, g := range m.Flags {
		c.Flags[g.Name] = append(c.Flags[g.Name], g.Value)
		c.Given = append(c.Given, kit.Given{Name: g.Name, Value: g.Value, At: g.At})
	}
	if e := (*cmdline.Error)(nil); errors.As(err, &e) {
		kind := map[cmdline.ErrorKind]kit.ErrKind{
			cmdline.UnknownCommand: kit.UnknownCommand,
			cmdline.UnknownFlag:    kit.UnknownFlag,
			cmdline.MissingValue:   kit.MissingValue,
		}[e.Kind]
		c.Stop, c.StopAt = &kit.UsageError{Kind: kind, Path: e.Path, Word: e.Word}, e.At
	}
	return t.Exec(ctx, std, c)
}

func (Adapter) Complete(_ context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	words, dir := cmdline.Complete(Root(t), argv[:len(argv)-1], argv[len(argv)-1])
	return kit.Completion{Words: words, Files: dir&cmdline.NoFiles == 0}, nil
}

func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	return script.Write(w, shell, kit.Program)
}

// Root turns the kit's flat tree (root first, parents before children)
// into the library's nested one.
func Root(t *kit.Tree) *cmdline.Command {
	byPath := map[string]*cmdline.Command{}
	for _, c := range t.Commands {
		n := &cmdline.Command{Name: kit.Program, Aliases: c.Aliases, Help: c.Short}
		for _, f := range c.Flags {
			fl := cmdline.Flag{Name: f.Name, Bool: f.Kind == kit.Bool, Repeat: f.Kind == kit.Strings, Help: f.Help}
			if f.Short != "" {
				fl.Short = rune(f.Short[0])
			}
			switch {
			case f.File: // D27
				fl.Complete = cmdline.Files
			case !fl.Bool:
				fl.Complete = values(f)
			}
			n.Flags = append(n.Flags, fl)
		}
		for _, a := range c.Args {
			n.Args = append(n.Args, cmdline.Words(a.Values...))
			if a.File {
				n.Args[len(n.Args)-1] = cmdline.Files
			}
		}
		if k := len(c.Path); k > 0 {
			n.Name = c.Path[k-1]
			p := byPath[strings.Join(c.Path[:k-1], " ")]
			p.Commands = append(p.Commands, n)
		}
		byPath[strings.Join(c.Path, " ")] = n
	}
	return byPath[""]
}

// values is Headscale's convention for a flag value: one word from the
// flag's list; a list flag (--columns, --tags) takes such words comma
// separated; on a list that takes signs (--columns, --sort) a word may carry
// a + or - (--sort -last-seen). No space after an item that may be followed
// by ",x", nor after a --filter column, which an operator follows
// (--filter name=web).
func values(f kit.Flag) cmdline.Completer {
	return func(_ *cmdline.Match, cur string) ([]string, cmdline.Directive) {
		dir := cmdline.NoFiles
		head, item := "", cur
		if i := strings.LastIndex(cur, ","); i >= 0 && f.List {
			head, item = cur[:i+1], cur[i+1:]
			dir |= cmdline.NoSpace
		}
		sign := ""
		if f.Signs && item != "" && (item[0] == '+' || item[0] == '-') {
			sign, item = item[:1], item[1:]
		}
		var out []string
		for _, v := range f.Values {
			if strings.HasPrefix(v, item) {
				out = append(out, head+sign+v)
			}
		}
		if f.Kind == kit.Strings {
			dir |= cmdline.NoSpace
		}
		return out, dir
	}
}
