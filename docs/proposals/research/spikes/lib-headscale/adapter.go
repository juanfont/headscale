// Package libhs is the Headscale adapter over the cmdline library: it turns
// the kit's tree into the library's, maps the library's errors to the
// kit's, and holds Headscale's own Tab convention for list values.
package libhs

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

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	m, err := cmdline.Parse(Root(t), argv)
	if e := (*cmdline.Error)(nil); errors.As(err, &e) {
		kind := map[cmdline.ErrorKind]kit.ErrKind{
			cmdline.UnknownCommand: kit.UnknownCommand,
			cmdline.UnknownFlag:    kit.UnknownFlag,
			cmdline.MissingValue:   kit.MissingValue,
		}[e.Kind]
		return &kit.UsageError{Kind: kind, Path: e.Path, Word: e.Word}
	}
	return t.Exec(ctx, std, kit.Call{Path: m.Path, Flags: m.Flags, Args: m.Args})
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
		n := &cmdline.Command{Name: kit.Program, Aliases: c.Aliases}
		for _, f := range c.Flags {
			fl := cmdline.Flag{Name: f.Name, Bool: f.Kind == kit.Bool}
			if f.Short != "" {
				fl.Short = rune(f.Short[0])
			}
			if !fl.Bool {
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

// values is Headscale's convention for a flag value: a comma list whose
// items may carry a + or - (--columns -ip,+hostname). The kit's tree does
// not say which flags are lists, so every value is read as one.
func values(f kit.Flag) cmdline.Completer {
	return func(cur string) ([]string, cmdline.Directive) {
		dir := cmdline.NoFiles
		head, item := "", cur
		if i := strings.LastIndex(cur, ","); i >= 0 {
			head, item = cur[:i+1], cur[i+1:]
			dir |= cmdline.NoSpace
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
			dir |= cmdline.NoSpace // room for the operator: --filter name=
		}
		return out, dir
	}
}
