package cmdline

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline/reader"
)

// Line is one command line as Parse read it.
type Line struct {
	Command *Info    // the command reached: one that runs, or a group when the line ends there
	Flags   []Given  // every flag given, in the order typed
	Args    []string // the arguments as typed, in order, without the "--" that ends the flags
	ArgAt   []int    // the index in argv of each argument

	node    *node
	parts   map[reflect.Type]reflect.Value
	pending []pending
	err     *UsageError
	ran     bool
}

// Given is one flag as it was typed. The typed value is in the struct the
// flag belongs to; Given is for a caller that places a mistake of its own
// on the line, and for a Completer.
type Given struct {
	Name  string // the flag's long name, whatever spelling was typed
	Value string // as typed; "true" for a bool given bare
	At    int    // the index in argv of the flag word
}

// pending is a word that waits for its LateReader.
type pending struct {
	f     *field
	text  string
	word  string
	items []string
	at    int
}

// Kind says what is wrong with a line.
type Kind int

const (
	UnknownCommand Kind = iota + 1 // Word is not a command of the group at Path
	UnknownFlag                    // Word is no flag where it stands, or no flag of the command reached
	MissingValue                   // the flag is the last word and has no value
	Repeated                       // the flag is given a second time and is no Repeat
	BadValue                       // the reader of the field's type refused the value; Err says why
	ArgCount                       // too few or too many arguments
	Unresolved                     // a LateReader refused the value; Err says why
)

// UsageError is a mistake on the command line, as data. Its text is a
// default; a caller that writes its own reads the fields.
type UsageError struct {
	Kind  Kind
	Path  []string // the command reached, as Info.Path
	At    int      // the index in argv of the word the mistake stands at; len(argv) for ArgCount
	Word  string   // that word: a command word, an argument, or a flag as typed, up to any "="
	Flag  string   // the long name, when the mistake is about a flag the command takes
	Arg   string   // the name, when the mistake is about an argument
	Value string   // BadValue and Unresolved: what was typed for it
	Err   error    // BadValue and Unresolved: what the reader said
}

// Unwrap returns Err, so errors.Is and errors.As find what the reader said.
func (e *UsageError) Unwrap() error { return e.Err }

// Error gives the default English text.
func (e *UsageError) Error() string {
	at := ""
	if len(e.Path) > 0 {
		at = fmt.Sprintf(" for %q", strings.Join(e.Path, " "))
	}

	what := "argument " + e.Arg
	if e.Flag != "" {
		what = "flag --" + e.Flag
	}

	//nolint:exhaustive // BadValue and Unresolved fall to the cause below
	switch e.Kind {
	case UnknownCommand:
		return fmt.Sprintf("unknown command %q%s", e.Word, at)
	case UnknownFlag:
		return fmt.Sprintf("unknown flag %s%s", e.Word, at)
	case MissingValue:
		return fmt.Sprintf("flag %s needs a value", e.Word)
	case Repeated:
		return what + " is given more than once"
	case ArgCount:
		return "wrong number of arguments" + at
	}

	return fmt.Sprintf("%s: %q: %v", what, e.Value, e.Err)
}

// Parse reads argv (without the program name) and fills the structs of the
// command reached. The error is a *UsageError: the first mistake on the
// line, left to right, whatever its kind. A wrong argument count belongs to
// the whole line, so it is reported only when nothing else is wrong.
//
// The Line is never nil. Next to an error it holds what was read before the
// mistake, so a caller can place a mistake of its own. Its structs are
// filled when there is no error, and next to ArgCount, so a caller can still
// see a flag such as --help.
func (t *Tree) Parse(argv []string) (*Line, error) {
	m, err := reader.Parse(t.root.low, argv)
	l := t.line(m)
	n := l.node

	found := func(e *UsageError) {
		if e.Path = n.info.Path; l.err == nil || e.At < l.err.At {
			l.err = e
		}
	}

	if e, ok := errors.AsType[*reader.Error](err); ok {
		found(&UsageError{Kind: Kind(e.Kind), At: e.At, Word: e.Word})

		if e.Kind == reader.MissingValue {
			l.err.Flag = n.spell[e.Word]
		}
	}

	l.parts = map[reflect.Type]reflect.Value{}
	for _, p := range n.parts {
		l.parts[p] = reflect.New(p).Elem()
	}

	seen := map[string]bool{}

	for _, g := range l.Flags {
		f := n.flags[g.Name]

		word, _, _ := strings.Cut(argv[g.At], "=")
		if seen[g.Name] && !f.repeat {
			found(&UsageError{Kind: Repeated, At: g.At, Word: word, Flag: f.name})
			continue
		}

		seen[g.Name] = true

		err := l.put(f, g.Value, word, g.At)
		if err != nil {
			found(
				&UsageError{
					Kind:  BadValue,
					At:    g.At,
					Word:  word,
					Flag:  f.name,
					Value: g.Value,
					Err:   err,
				},
			)
		}
	}

	for i, a := range l.Args {
		if i == len(n.args) {
			break
		}

		err := l.put(n.args[i], a, a, l.ArgAt[i])
		if err != nil {
			found(
				&UsageError{
					Kind:  BadValue,
					At:    l.ArgAt[i],
					Word:  a,
					Arg:   n.args[i].name,
					Value: a,
					Err:   err,
				},
			)
		}
	}

	// In field order, so the same line reports the same refusal (X1).
	for _, f := range n.defs {
		if !seen[f.name] {
			vals, err := f.defaults()
			if err != nil {
				found(
					&UsageError{
						Kind:  BadValue,
						At:    len(argv),
						Flag:  f.name,
						Value: *f.def,
						Err:   err,
					},
				)

				continue
			}

			f.store(l.parts[f.part].Field(f.index), vals)
		}
	}

	needed := slices.IndexFunc(n.args, func(a *field) bool { return a.opt })
	if needed < 0 {
		needed = len(n.args)
	}

	if l.err == nil && n.in != nil &&
		(len(l.Args) < needed || len(l.Args) > len(n.args)) {
		found(&UsageError{Kind: ArgCount, At: len(argv)})
	}

	if l.err != nil {
		if l.err.Kind != ArgCount {
			l.parts = nil
		}

		return l, l.err
	}

	return l, nil
}

// line makes the Line of what the reader read.
func (t *Tree) line(m *reader.Match) *Line {
	n := t.nodes[m.Command]

	l := &Line{Command: n.info, Args: m.Args, ArgAt: m.ArgAt, node: n}
	for _, g := range m.Flags {
		l.Flags = append(l.Flags, Given(g))
	}

	return l
}

// put reads one occurrence of f, or keeps it for the LateReader.
func (l *Line) put(f *field, text, word string, at int) error {
	if f.late != nil {
		items, err := f.split(text)
		l.pending = append(
			l.pending,
			pending{f: f, text: text, word: word, items: items, at: at},
		)

		return err
	}

	vals, err := f.parse(text)
	if err == nil {
		f.store(l.parts[f.part].Field(f.index), vals)
	}

	return err
}

// Get returns the struct of type T that Parse filled for the line: the
// input struct of the command reached, or one of the structs in its Flags.
// At a group these are the Flags of the group and of the groups above it.
// It reports false when the command has no such struct, and next to a
// mistake other than ArgCount.
func Get[T any](l *Line) (T, bool) {
	v, ok := l.parts[reflect.TypeFor[T]()]
	if !ok {
		var zero T
		return zero, false
	}

	//nolint:forcetypeassert // parts is keyed by the type
	return v.Interface().(T), true
}

// Run runs the command of a line that Parse read without a mistake. First
// every LateReader reads its word, in the order typed; the first that fails
// stops the run with a *UsageError of kind Unresolved. A caller does its own
// work between Parse and Run: show help, make a client and put it into ctx.
//
// A line with a mistake does not run: Run returns the mistake. Nor does a
// line that ends at a group (ErrGroup), or a Line that Parse did not make,
// such as the one a Complete method gets (ErrNotParsed). A line runs once:
// a second Run returns ErrRan and calls nothing, also when the first one
// stopped at a LateReader.
func (l *Line) Run(ctx context.Context) error {
	switch {
	case l.err != nil:
		return l.err
	case l.parts == nil:
		return ErrNotParsed
	case l.node.run == nil:
		return ErrGroup
	case l.ran:
		return ErrRan
	}

	l.ran = true
	slices.SortStableFunc(l.pending, func(a, b pending) int { return a.at - b.at })

	for _, p := range l.pending {
		vals := make([]reflect.Value, len(p.items))
		for i, it := range p.items {
			v, err := p.f.late(ctx, it)
			if err != nil {
				e := &UsageError{
					Kind:  Unresolved,
					Path:  l.Command.Path,
					At:    p.at,
					Word:  p.word,
					Arg:   p.f.name,
					Value: p.text,
					Err:   err,
				}
				if l.node.flags[p.f.name] == p.f {
					e.Flag, e.Arg = p.f.name, ""
				}

				return e
			}

			vals[i] = v
		}

		p.f.store(l.parts[p.f.part].Field(p.f.index), vals)
	}

	return l.node.run(ctx, l.parts[l.node.in].Interface())
}
