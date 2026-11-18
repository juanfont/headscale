package diff

import (
	"context"
	"errors"
	"flag"
	"io"
	"slices"
	"strings"

	"github.com/spf13/pflag"

	"spike/kit"
)

// The flag readers alone: a plain pflag FlagSet and Go's flag package, with
// no dispatcher and no workaround around them. They only take lines that
// start with a leaf's canonical path; the rest goes to the reader.

var ErrSkip = errors.New("skip")

func leafOf(t *kit.Tree, argv []string) (*kit.Command, []string) {
	for i := range t.Commands {
		c := &t.Commands[i]
		if c.Leaf && len(argv) >= len(c.Path) && slices.Equal(argv[:len(c.Path)], c.Path) {
			return c, argv[len(c.Path):]
		}
	}
	return nil, nil
}

type rec struct {
	v    *[]string
	bool bool
}

func (m rec) String() string     { return "" }
func (m rec) Set(s string) error { *m.v = append(*m.v, s); return nil }
func (m rec) Type() string       { return "string" }
func (m rec) IsBoolFlag() bool   { return m.bool }

type PflagPlain struct{}

func (PflagPlain) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	c, rest := leafOf(t, argv)
	if c == nil {
		return ErrSkip
	}
	fs := pflag.NewFlagSet(kit.Program, pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	got := map[string]*[]string{}
	for _, f := range c.Flags {
		got[f.Name] = new([]string)
		pf := fs.VarPF(rec{v: got[f.Name]}, f.Name, f.Short, "")
		if f.Kind == kit.Bool {
			pf.NoOptDefVal = "true"
		}
	}
	if err := fs.Parse(rest); err != nil {
		var ne *pflag.NotExistError
		var vr *pflag.ValueRequiredError
		var is *pflag.InvalidSyntaxError
		dash := func(s string) string {
			if s != "" {
				return "-"
			}
			return "--"
		}
		switch {
		case errors.As(err, &ne):
			return &kit.UsageError{Kind: kit.UnknownFlag, Path: c.Path, Word: dash(ne.GetSpecifiedShortnames()) + ne.GetSpecifiedName()}
		case errors.As(err, &vr):
			return &kit.UsageError{Kind: kit.MissingValue, Path: c.Path, Word: dash(vr.GetSpecifiedShortnames()) + vr.GetSpecifiedName()}
		case errors.As(err, &is):
			return &kit.UsageError{Kind: kit.UnknownFlag, Path: c.Path, Word: is.GetSpecifiedFlag()}
		}
		return err
	}
	vals := map[string][]string{}
	fs.Visit(func(f *pflag.Flag) { vals[f.Name] = *got[f.Name] })
	return t.Exec(ctx, std, kit.Call{Path: c.Path, Flags: vals, Args: fs.Args()})
}

func (PflagPlain) Complete(context.Context, *kit.Tree, []string) (kit.Completion, error) {
	return kit.Completion{}, ErrSkip
}
func (PflagPlain) Script(*kit.Tree, string, io.Writer) error { return ErrSkip }

// StdFlag is Go's flag package: -name and --name are the same, a short is
// just another name, parsing stops at the first positional.
type StdFlag struct{}

func (StdFlag) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	c, rest := leafOf(t, argv)
	if c == nil {
		return ErrSkip
	}
	fs := flag.NewFlagSet(kit.Program, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	got := map[string]*[]string{}
	for _, f := range c.Flags {
		got[f.Name] = new([]string)
		fs.Var(rec{v: got[f.Name], bool: f.Kind == kit.Bool}, f.Name, "")
		if f.Short != "" {
			fs.Var(rec{v: got[f.Name], bool: f.Kind == kit.Bool}, f.Short, "")
		}
	}
	if err := fs.Parse(rest); err != nil {
		msg := err.Error()
		if w, ok := strings.CutPrefix(msg, "flag provided but not defined: "); ok {
			return &kit.UsageError{Kind: kit.UnknownFlag, Path: c.Path, Word: w}
		}
		if w, ok := strings.CutPrefix(msg, "flag needs an argument: "); ok {
			return &kit.UsageError{Kind: kit.MissingValue, Path: c.Path, Word: w}
		}
		if strings.HasPrefix(msg, "bad flag syntax: ") {
			return &kit.UsageError{Kind: kit.UnknownFlag, Path: c.Path, Word: strings.TrimPrefix(msg, "bad flag syntax: ")}
		}
		return err
	}
	vals := map[string][]string{}
	fs.Visit(func(f *flag.Flag) {
		long := t.Long(f.Name)
		vals[long] = *got[long]
	})
	return t.Exec(ctx, std, kit.Call{Path: c.Path, Flags: vals, Args: fs.Args()})
}

func (StdFlag) Complete(context.Context, *kit.Tree, []string) (kit.Completion, error) {
	return kit.Completion{}, ErrSkip
}
func (StdFlag) Script(*kit.Tree, string, io.Writer) error { return ErrSkip }

// LeafLine: argv starts with a leaf's canonical path.
func LeafLine(t *kit.Tree, argv []string) bool { c, _ := leafOf(t, argv); return c != nil }

// Ordered: every flag comes before the first positional (as the own
// grammar reads the line), so Go's flag package, which stops there, can read
// the same line.
func Ordered(t *kit.Tree, argv []string) bool {
	c, rest := leafOf(t, argv)
	if c == nil {
		return false
	}
	for i := 0; i < len(rest); i++ {
		w := rest[i]
		switch {
		case w == "--":
			return true
		case len(w) > 1 && w[0] == '-':
			name, _, eq := strings.Cut(strings.TrimLeft(w, "-"), "=")
			j := slices.IndexFunc(c.Flags, func(f kit.Flag) bool { return f.Name == name || f.Short == name })
			if !eq && j >= 0 && c.Flags[j].Kind != kit.Bool {
				i++
			}
		default:
			return !slices.ContainsFunc(rest[i:], func(w string) bool { return len(w) > 1 && w[0] == '-' })
		}
	}
	return true
}
