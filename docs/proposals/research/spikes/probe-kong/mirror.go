// Package probekong probes alecthomas/kong for Headscale's adapter contract.
// Approach (a): mirror struct types generated with reflect.StructOf from spec data.
package probekong

import (
	"errors"
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
)

type Kind int

const (
	Bool Kind = iota
	String
	Repeat // --filter: values accumulate in order
)

type FlagSpec struct {
	Name  string
	Short string
	Kind  Kind
}

// Node is a stand-in for the command.Spec tree: plain data, no kong type.
type Node struct {
	Name     string
	Aliases  []string
	Flags    []FlagSpec
	Args     int // positional slots declared to kong; our layer counts
	Children []*Node
	id       int
}

// Result is what the adapter hands our builder.
type Result struct {
	Leaf  []string            // canonical path, e.g. nodes routes set
	Flags map[string][]string // every occurrence, in order ("given" = key present)
	Args  []string
}

// ParseErr is the typed error our layer writes text from.
type ParseErr struct {
	Kind  string              // unknown-flag, unknown-command, missing-value, no-leaf, other
	Word  string              // the offending token
	Path  []string            // command path reached so far
	Cause error               // kong's error, for the record only
	Flags map[string][]string // flags traced before the failure: --help and --version win
}

func (e *ParseErr) Error() string { return fmt.Sprintf("%s %q at %v", e.Kind, e.Word, e.Path) }

func flagFields(flags []FlagSpec) []reflect.StructField {
	var out []reflect.StructField
	for i, f := range flags {
		tag := fmt.Sprintf(`name:%q`, f.Name)
		if f.Short != "" {
			tag += fmt.Sprintf(` short:%q`, f.Short)
		}
		var t reflect.Type
		switch f.Kind {
		case Bool:
			t = reflect.TypeFor[bool]()
		case String:
			t = reflect.TypeFor[string]()
			tag += ` type:"hsraw"`
		case Repeat:
			t = reflect.TypeFor[[]string]()
			tag += ` type:"hsraw"`
		}
		out = append(out, reflect.StructField{Name: "F" + strconv.Itoa(i), Type: t, Tag: reflect.StructTag(tag)})
	}
	return out
}

func nodeType(n *Node, ids *[]*Node) reflect.Type {
	fields := flagFields(n.Flags)
	if len(n.Children) == 0 {
		for i := range n.Args {
			fields = append(fields, reflect.StructField{
				Name: "A" + strconv.Itoa(i), Type: reflect.TypeFor[string](),
				Tag: reflect.StructTag(fmt.Sprintf(`arg:"" optional:"" name:"a%d"`, i)),
			})
		}
		fields = append(fields, reflect.StructField{
			Name: "Extra", Type: reflect.TypeFor[[]string](), Tag: `arg:"" optional:"" name:"extra"`,
		})
	}
	for i, c := range n.Children {
		c.id = len(*ids)
		*ids = append(*ids, c)
		tag := fmt.Sprintf(`cmd:"" name:%q hsid:"%d"`, c.Name, c.id)
		if len(c.Aliases) > 0 {
			tag += fmt.Sprintf(` aliases:%q`, strings.Join(c.Aliases, ","))
		}
		fields = append(fields, reflect.StructField{Name: "C" + strconv.Itoa(i), Type: nodeType(c, ids), Tag: reflect.StructTag(tag)})
	}
	return reflect.StructOf(fields)
}

// Build makes a fresh parser. Global flags (-o, -c, -h, --version) sit on the root so they
// work before and after the subcommand (D3); our layer refuses them where a spec has none.
func Build(root *Node, opts ...kong.Option) (*kong.Kong, error) {
	var ids []*Node
	t := nodeType(root, &ids)
	v := reflect.New(t)
	base := []kong.Option{
		kong.Name("headscale"),
		kong.NoDefaultHelp(),
		kong.NamedMapper("hsraw", rawMapper),
		kong.Exit(func(int) { panic("kong called exit") }),
	}
	return kong.New(v.Interface(), append(base, opts...)...)
}

// MissingValue is returned by rawMapper and survives kong's wrapping (errors.As works).
type MissingValue struct{ Flag string }

func (e *MissingValue) Error() string { return "missing value for --" + e.Flag }

// rawMapper takes the next word whatever it looks like (pflag behaviour: --sort -last-seen),
// fails at end of line (kong's hyphen option would give ""), and reads -o=json as json.
var rawMapper = kong.MapperFunc(func(ctx *kong.DecodeContext, target reflect.Value) error {
	tok := ctx.Scan.Pop()
	if tok.IsEOL() {
		return &MissingValue{Flag: ctx.Value.Name}
	}
	s := tok.String()
	if tok.Type == kong.ShortFlagTailToken {
		s = strings.TrimPrefix(s, "=")
	}
	if target.Kind() == reflect.Slice { // --filter: one value per occurrence, in order
		target.Set(reflect.Append(target, reflect.ValueOf(s)))
		return nil
	}
	target.SetString(s)
	return nil
})

func Parse(root *Node, args []string, opts ...kong.Option) (*Result, error) {
	k, err := Build(root, opts...)
	if err != nil {
		return nil, err
	}
	ctx, err := k.Parse(args)
	var pe *kong.ParseError
	if errors.As(err, &pe) {
		return nil, classify(pe)
	}
	if err != nil {
		return nil, err
	}
	return collect(ctx.Path), nil
}

func collect(path []*kong.Path) *Result {
	r := &Result{Flags: map[string][]string{}}
	seen := map[*kong.Flag]int{}
	for _, p := range path {
		switch {
		case p.Command != nil:
			r.Leaf = append(r.Leaf, p.Command.Name)
		case p.Flag != nil:
			// kong keeps one value per flag; count occurrences from the trace.
			seen[p.Flag]++
		case p.Positional != nil:
			switch v := p.Positional.Target.Interface().(type) {
			case string:
				r.Args = append(r.Args, v)
			case []string:
				r.Args = append(r.Args, v...)
			}
		}
	}
	for f, n := range seen {
		switch v := f.Target.Interface().(type) {
		case []string:
			r.Flags[f.Name] = v
		default:
			s := fmt.Sprint(v)
			for range n {
				r.Flags[f.Name] = append(r.Flags[f.Name], s) // repeat count kept; value is the last one
			}
		}
	}
	return r
}

// classify reads the failing word from the trace, not from the message text.
func classify(pe *kong.ParseError) *ParseErr {
	e := &ParseErr{Kind: "other", Cause: pe}
	var mv *MissingValue
	if errors.As(pe, &mv) {
		e.Kind, e.Word = "missing-value", "--"+mv.Flag
	}
	ctx := pe.Context
	if ctx == nil {
		return e
	}
	e.Flags = collect(ctx.Path).Flags
	var last *kong.Path
	for _, p := range ctx.Path {
		if p.Command != nil {
			e.Path = append(e.Path, p.Command.Name)
		}
		last = p
	}
	if rem := last.Remainder(); e.Kind == "other" && len(rem) > 0 {
		e.Word = rem[0]
		switch {
		case strings.HasPrefix(e.Word, "-") && e.Word != "-":
			e.Kind = "unknown-flag"
		default:
			e.Kind = "unknown-command"
		}
	} else if e.Kind == "other" && ctx.Error != nil {
		e.Kind = "missing-value-or-other"
	}
	if sel := ctx.Selected(); ctx.Error == nil && sel != nil && len(sel.Children) > 0 || ctx.Error == nil && sel == nil {
		e.Kind = "no-leaf"
	}
	return e
}
