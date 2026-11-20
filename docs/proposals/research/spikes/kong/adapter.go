// Package kongadapter turns the kit's tree into kong commands. Kong's unit is a Go struct, so
// the adapter generates one struct type per command with reflect.StructOf (fields and tags only;
// kong's own model is read through its public API, never through reflect). Help, errors and
// completion candidates come from the kit; kong only tokenizes and walks the tree.
package kongadapter

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"slices"
	"strconv"
	"strings"

	"github.com/alecthomas/kong"
	"spike/kit"
	"tailscale.com/tempfork/spf13/cobra"
)

type Adapter struct{}

// missingValue and attachedValue come from our mapper and survive kong's %w wrap.
type missingValue struct{ flag string }

func (e *missingValue) Error() string { return "missing value for --" + e.flag }

type attachedValue struct{ word string }

func (e *attachedValue) Error() string { return "attached value in " + e.word }

// valueMapper reads every flag into a []string, one element per occurrence, so the kit sees
// repeats (D6) and "given empty" (R23). Kong's string mapper refuses "-last-seen" as a value
// and its hyphen option turns a value missing at the end into "": this takes the next word as
// pflag does and errors at the end. A short flag with "=" (-o=json) drops the "=" (D11); an
// attached value (-ojson) is refused, the D11 target.
type valueMapper struct{ bool bool }

func (m valueMapper) Decode(ctx *kong.DecodeContext, target reflect.Value) error {
	var s string
	switch tok := ctx.Scan.Peek(); {
	case m.bool && tok.Type != kong.FlagValueToken:
		s = "true" // --force; --force=false arrives as a FlagValueToken
	case tok.IsEOL():
		return &missingValue{ctx.Value.Name}
	case tok.Type == kong.ShortFlagTailToken && !strings.HasPrefix(tok.String(), "="):
		return &attachedValue{"-" + string(ctx.Value.Flag.Short) + tok.String()}
	default:
		s = ctx.Scan.Pop().String()
		if tok.Type == kong.ShortFlagTailToken {
			s = s[1:] // -o=json
		}
	}
	target.Set(reflect.Append(target, reflect.ValueOf(s)))
	return nil
}

// build makes a fresh parser per run: kong mutates its model while parsing.
func build(t *kit.Tree) (*kong.Kong, error) {
	root := reflect.New(nodeType(t, 0, nil))
	return kong.New(root.Interface(),
		kong.Name(kit.Program),
		kong.NoDefaultHelp(),
		kong.Exit(func(int) { panic("kong: exit") }),
		kong.NamedMapper("hsvalue", valueMapper{}),
		kong.NamedMapper("hsbool", valueMapper{bool: true}),
	)
}

// nodeType is the struct for t.Commands[i]. Flags an ancestor already has are left out: kong
// refuses duplicates and gives a child every flag of its parents, which is how -c/-o work
// before and after the subcommand (D3). Exec refuses them where the leaf has none.
func nodeType(t *kit.Tree, i int, inherited []string) reflect.Type {
	c := t.Commands[i]
	var fields []reflect.StructField
	for j, f := range c.Flags {
		if slices.Contains(inherited, f.Name) {
			continue
		}
		inherited = append(inherited, f.Name)
		tag := fmt.Sprintf(`name:%q type:"hsvalue"`, f.Name)
		if f.Kind == kit.Bool {
			tag = fmt.Sprintf(`name:%q type:"hsbool"`, f.Name)
		}
		if f.Short != "" {
			tag += fmt.Sprintf(` short:%q`, f.Short)
		}
		fields = append(fields, field("F"+strconv.Itoa(j), reflect.TypeFor[[]string](), tag))
	}
	// One slot per argument keeps flags between arguments working; Extra takes the rest
	// so the kit counts them (R32).
	for j := range c.Args {
		fields = append(fields, field("A"+strconv.Itoa(j), reflect.TypeFor[string](), fmt.Sprintf(`arg:"" optional:"" name:"a%d"`, j)))
	}
	if c.Leaf {
		fields = append(fields, field("Extra", reflect.TypeFor[[]string](), `arg:"" optional:"" name:"extra"`))
	}
	for j, ch := range t.Commands {
		if len(ch.Path) != len(c.Path)+1 || !slices.Equal(ch.Path[:len(c.Path)], c.Path) {
			continue
		}
		tag := fmt.Sprintf(`cmd:"" name:%q hs:"%d"`, ch.Path[len(c.Path)], j)
		if len(ch.Aliases) > 0 {
			tag += fmt.Sprintf(` aliases:%q`, strings.Join(ch.Aliases, ","))
		}
		fields = append(fields, field("C"+strconv.Itoa(j), nodeType(t, j, slices.Clone(inherited)), tag))
	}
	return reflect.StructOf(fields)
}

func field(name string, typ reflect.Type, tag string) reflect.StructField {
	return reflect.StructField{Name: name, Type: typ, Tag: reflect.StructTag(tag)}
}

// parsed is what the trace holds: the command reached and, when complete, flags and args.
type parsed struct {
	cmd   int // index into t.Commands
	path  []string
	flags map[string][]string
	args  []string
}

func read(ctx *kong.Context) parsed {
	p := parsed{flags: map[string][]string{}}
	for _, e := range ctx.Path {
		switch {
		case e.Command != nil:
			p.path = append(p.path, e.Command.Name)
			p.cmd, _ = strconv.Atoi(e.Command.Tag.Get("hs"))
		case e.Flag != nil:
			p.flags[e.Flag.Name] = e.Flag.Target.Interface().([]string)
		case e.Positional != nil:
			switch v := e.Positional.Target.Interface().(type) {
			case string:
				p.args = append(p.args, v)
			case []string:
				p.args = append(p.args, v...)
			}
		}
	}
	return p
}

func (Adapter) Run(ctx context.Context, t *kit.Tree, argv []string, std kit.Stdio) error {
	k, err := build(t)
	if err != nil {
		return err
	}
	kctx, err := k.Parse(argv)
	if err == nil {
		p := read(kctx)
		return t.Exec(ctx, std, kit.Call{Path: p.path, Flags: p.flags, Args: p.args})
	}
	var pe *kong.ParseError
	if !errors.As(err, &pe) {
		return err
	}
	p := read(pe.Context)
	var mv *missingValue
	var av *attachedValue
	switch {
	case errors.As(err, &mv):
		return &kit.UsageError{Kind: kit.MissingValue, Path: p.path, Word: "--" + mv.flag}
	case errors.As(err, &av):
		return &kit.UsageError{Kind: kit.UnknownFlag, Path: p.path, Word: av.word}
	// WA: kong has no typed error for these. A finished trace means the error came from
	// Validate, which with no validating tags can only be a group or the root with no command:
	// help (D10), --help or --version. Otherwise the word that stopped the trace is the first one
	// left after the last thing it took (kong's unknown flag is an unexported type, its unknown
	// command a string); its leading "-" tells the two apart.
	case pe.Context.Error == nil: // WA
		return t.Exec(ctx, std, kit.Call{Path: p.path, Flags: p.flags}) // WA
	}
	rest := pe.Context.Path[len(pe.Context.Path)-1].Remainder() // WA
	if len(rest) == 0 {
		return err
	}
	if w := rest[0]; len(w) > 1 && w[0] == '-' { // WA
		return &kit.UsageError{Kind: kit.UnknownFlag, Path: p.path, Word: w} // WA
	}
	return &kit.UsageError{Kind: kit.UnknownCommand, Path: p.path, Word: rest[0]} // WA
}

// Complete is what `headscale __complete <words…>` answers (cobra's protocol). Kong traces the
// words before the cursor; the kit's tree gives the candidates.
func (Adapter) Complete(_ context.Context, t *kit.Tree, argv []string) (kit.Completion, error) {
	if len(argv) == 0 {
		argv = []string{""}
	}
	k, err := build(t)
	if err != nil {
		return kit.Completion{}, err
	}
	kctx, err := kong.Trace(k, argv[:len(argv)-1])
	if err != nil {
		return kit.Completion{}, err
	}
	p, cur := read(kctx), argv[len(argv)-1]
	c := t.Commands[p.cmd]
	var mv *missingValue
	switch {
	case errors.As(kctx.Error, &mv): // the word before the cursor is a flag that wants a value
		for _, f := range append(slices.Clone(c.Flags), t.Commands[0].Flags...) {
			if f.Name == mv.flag {
				return kit.Completion{Words: listValues(f.Values, cur)}, nil
			}
		}
	case kctx.Error != nil:
	case strings.HasPrefix(cur, "-"):
		var w []string
		for _, f := range c.Flags {
			w = append(w, "--"+f.Name)
		}
		return kit.Completion{Words: prefixed(w, cur)}, nil
	case !c.Leaf:
		var w []string
		for _, ch := range t.Commands {
			if len(ch.Path) == len(c.Path)+1 && slices.Equal(ch.Path[:len(c.Path)], c.Path) {
				w = append(append(w, ch.Path[len(c.Path)]), ch.Aliases...)
			}
		}
		return kit.Completion{Words: prefixed(w, cur)}, nil
	case len(p.args) < len(c.Args):
		a := c.Args[len(p.args)]
		return kit.Completion{Words: prefixed(a.Values, cur), Files: a.File}, nil
	}
	return kit.Completion{}, nil
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

// listValues completes the last item of a comma list, keeping a +/- sign (--columns id,+na).
func listValues(values []string, cur string) []string {
	head, last := "", cur
	if i := strings.LastIndex(cur, ","); i >= 0 {
		head, last = cur[:i+1], cur[i+1:]
	}
	if last != "" && (last[0] == '+' || last[0] == '-') {
		head, last = head+last[:1], last[1:]
	}
	var out []string
	for _, v := range prefixed(values, last) {
		out = append(out, head+v)
	}
	return out
}

// Script writes cobra's scripts as Tailscale vendors them (Apache-2.0); they call
// `headscale __complete <words…>` and read cobra's directive line.
func (Adapter) Script(_ *kit.Tree, shell string, w io.Writer) error {
	write := map[string]func(io.Writer, string, string, string) error{
		"bash": cobra.ScriptBash, "zsh": cobra.ScriptZsh, "fish": cobra.ScriptFish, "powershell": cobra.ScriptPowershell,
	}[shell]
	if write == nil {
		return fmt.Errorf("no completion for shell %q", shell)
	}
	return write(w, kit.Program, "__complete", kit.Program)
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
