package own

import (
	"errors"
	"io"

	"github.com/spf13/pflag"
)

// multi records every value; String and Repeat differ only in what the layer
// accepts afterwards (D6), so pflag needs one value type for both.
type multi struct{ v *[]string }

func (m multi) String() string     { return "" }
func (m multi) Set(s string) error { *m.v = append(*m.v, s); return nil }
func (m multi) Type() string       { return "string" }

// PflagParse is variant 1: pflag does the grammar, we keep the values.
func PflagParse(flags []Flag, argv []string, stop bool) (map[string][]string, []string, error) {
	fs := pflag.NewFlagSet("", pflag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	fs.SetInterspersed(!stop)
	got := map[string]*[]string{}
	for _, f := range flags {
		if f.Kind == Bool {
			fs.BoolP(f.Long, f.Short, false, "")
			continue
		}
		got[f.Long] = new([]string)
		fs.VarP(multi{got[f.Long]}, f.Long, f.Short, "")
	}
	if err := fs.Parse(argv); err != nil {
		return nil, nil, fromPflag(err)
	}
	vals := map[string][]string{}
	fs.Visit(func(f *pflag.Flag) {
		if p := got[f.Name]; p != nil {
			vals[f.Name] = *p
		} else {
			vals[f.Name] = []string{f.Value.String()}
		}
	})
	rest := fs.Args()
	if stop && fs.ArgsLenAtDash() == 0 { // pflag ate the "--"; the dispatcher wants it
		rest = append([]string{"--"}, rest...)
	}
	return vals, rest, nil
}

func fromPflag(err error) error {
	var ne *pflag.NotExistError
	var vr *pflag.ValueRequiredError
	var iv *pflag.InvalidValueError
	var is *pflag.InvalidSyntaxError
	switch {
	case errors.As(err, &ne):
		if ne.GetSpecifiedShortnames() != "" {
			return &UnknownFlagError{Flag: "-" + ne.GetSpecifiedName()}
		}
		return &UnknownFlagError{Flag: "--" + ne.GetSpecifiedName()}
	case errors.As(err, &vr):
		if vr.GetSpecifiedShortnames() != "" {
			return &MissingValueError{Flag: "-" + vr.GetSpecifiedName()}
		}
		return &MissingValueError{Flag: "--" + vr.GetSpecifiedName()}
	case errors.As(err, &iv):
		return &BadValueError{Flag: "--" + iv.GetFlag().Name, Value: iv.GetValue()}
	case errors.As(err, &is):
		return &UnknownFlagError{Flag: is.GetSpecifiedFlag()}
	}
	return err // shortcut: an unmapped pflag error keeps pflag's text; the test table shows none occur
}
