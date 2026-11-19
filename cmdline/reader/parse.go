// Package reader is the string reader under cmdline: it reads a command line
// against a tree of commands described as plain data, and answers shell
// completion for that tree over cobra's __complete protocol.
//
// A program describes its tree with cmdline, not with this package.
// Command, Flag, Given, Words, Directive and Completer have namesakes in
// cmdline; the ones here belong to this lower layer. This package is outside
// any compatibility promise of cmdline.
//
// It does the grammar and nothing else: no conversion of values, no argument
// counts, no repeat rule. Every value comes back as the string that was
// typed, and every occurrence of a flag is kept; cmdline reads the values
// into typed fields and checks them.
//
// The grammar: --name, --name=value, --name value, -x, -x=value, -x value.
// A bool flag never takes the next word. The word after a value flag is its
// value, whatever it looks like. Flags and positionals mix in any order;
// "--" ends the flags. Attached short values (-ovalue), grouped shorts (-ab)
// and abbreviations are unknown flags.
package reader

import (
	"fmt"
	"slices"
	"strings"
)

// Command is one node of the tree. The root's Name is the program name.
// A command with Commands is a group: Parse reads the next word as one of
// them, never as a positional.
type Command struct {
	Name     string
	Aliases  []string
	Help     string // one line; Tab shows it next to the name
	Flags    []Flag
	Args     []Completer // Tab for the n-th positional; nil entries offer nothing
	Commands []*Command
}

// Flag is one flag of one command. A flag declared on a group may be typed
// at that group, or below it before the command is reached; it counts only
// if the command that is reached declares it too.
type Flag struct {
	Name     string    // long name, without dashes
	Short    rune      // one letter, or 0
	Bool     bool      // takes no value: "--x" reads "true", "--x=v" reads "v"
	Repeat   bool      // Tab offers it again once given; Parse keeps every occurrence of every flag
	Help     string    // one line; Tab shows it next to the name
	Complete Completer // Tab for the value; nil offers nothing, Files offers file names
}

// Match is what Parse read of a command line: all of it, or, next to an
// error, everything before the word it could not read.
type Match struct {
	Command *Command
	Path    []string // names from the root (not aliases), root excluded
	Flags   []Given  // every flag given, in the order typed
	Args    []string // positionals, in order
	ArgAt   []int    // the index in argv of each positional
}

// Given is one flag as it was given.
type Given struct {
	Name  string // the flag's long name, whatever spelling was typed
	Value string // as typed; "true" for a bool given bare
	At    int    // the index in argv of the flag word
}

// Values returns every value given for the flag name, in order; nil when it
// was not given.
func (m *Match) Values(name string) []string {
	var vs []string

	for _, g := range m.Flags {
		if g.Name == name {
			vs = append(vs, g.Value)
		}
	}

	return vs
}

// ErrorKind says what Parse could not read.
type ErrorKind int

const (
	UnknownCommand ErrorKind = iota + 1 // Word is not a command of the group at Path
	UnknownFlag                         // Word is the flag as typed, up to any "="
	MissingValue                        // Word is the flag as typed; argv ended
)

// Error is every error Parse returns. Its text is a default; callers that
// write their own read Kind, Path and Word, and At to compare it with
// mistakes of their own earlier on the line.
type Error struct {
	Kind ErrorKind
	Path []string // the command reached, as in Match.Path
	Word string
	At   int // the index in argv of the word
}

func (e *Error) Error() string {
	at := ""
	if len(e.Path) > 0 {
		at = fmt.Sprintf(" for %q", strings.Join(e.Path, " "))
	}

	switch e.Kind { //nolint:exhaustive // MissingValue is the text below
	case UnknownCommand:
		return fmt.Sprintf("unknown command %q%s", e.Word, at)
	case UnknownFlag:
		return fmt.Sprintf("unknown flag %s%s", e.Word, at)
	}

	return fmt.Sprintf("flag %s needs a value", e.Word)
}

// Parse reads argv (without the program name) against root. It stops at the
// first word it cannot read, left to right, and returns what it read before
// that word with the error, so the caller can find an earlier mistake of its
// own. A group with nothing after it is a Match too: what to do with it is
// the caller's call.
func Parse(root *Command, argv []string) (*Match, error) {
	l, err := read(root, argv, false)
	return l.m, err
}

// line is what read made of argv.
type line struct {
	m     *Match
	scope []Flag // the flags readable where the line stopped
	wait  *Flag  // the last word is this value flag, still without its value
	ended bool   // a "--" ended the flags of the command reached
}

// read is the one reader behind Parse and Complete. In tab mode it never
// fails: a word it cannot read is skipped, so Tab completes from the last
// command it understood (D30), and a value flag at the end is returned in
// wait instead of as MissingValue.
func read(root *Command, argv []string, tab bool) (*line, error) {
	l := &line{m: &Match{Command: root}, scope: root.Flags}
	m := l.m

	type seg struct {
		words []string // the flag word, then its value word if apart
		at    int
	}

	var pre []seg // flags read before the command was reached

	take := func(f *Flag, val string, at int) { m.Flags = append(m.Flags, Given{f.Name, val, at}) }
	flush := func() { // the flags read on the way down count where the line stops
		for _, p := range pre {
			f, _, val, _ := l.flag(p.words, new(int))
			take(f, val, p.at)
		}

		pre = nil
	}
	refuse := func(kind ErrorKind, word string, at int) (*line, error) {
		return l, &Error{Kind: kind, Path: m.Path, Word: word, At: at}
	}

	//nolint:intrange // l.flag advances i past a value word
	for i := 0; i < len(argv); i++ {
		a, group := argv[i], len(m.Command.Commands) > 0
		if a == "--" && !group {
			for j := i + 1; j < len(argv); j++ {
				m.Args, m.ArgAt = append(m.Args, argv[j]), append(m.ArgAt, j)
			}

			l.ended = true

			break
		}

		if a == "--" || len(a) < 2 ||
			a[0] != '-' { // a command word at a group, else a positional
			if !group {
				m.Args, m.ArgAt = append(m.Args, a), append(m.ArgAt, i)
				continue
			}

			c := m.Command.child(a)
			if c == nil {
				if tab {
					continue
				}

				flush()

				return refuse(UnknownCommand, a, i)
			}

			m.Command, m.Path = c, append(m.Path, c.Name)
			if len(c.Commands) > 0 {
				l.scope = append(slices.Clip(l.scope), c.Flags...)
				continue
			}

			l.scope = c.Flags // a leaf: what was read on the way down must be its flags too
			for _, p := range pre {
				f, typed, val, ok := l.flag(p.words, new(int))
				if f == nil && !tab {
					return refuse(UnknownFlag, typed, p.at)
				}

				if ok {
					take(f, val, p.at)
				}
			}

			pre = nil

			continue
		}

		start := i

		f, typed, val, ok := l.flag(argv, &i)
		switch {
		case f == nil && tab:
		case f == nil:
			flush()
			return refuse(UnknownFlag, typed, i)
		case !ok && tab:
			l.wait = f
		case !ok:
			flush()
			return refuse(MissingValue, typed, i)
		case group:
			pre = append(pre, seg{argv[start : i+1], start})
		default:
			take(f, val, start)
		}
	}

	flush() // the line ends at a group: every level's flags count (B1)

	return l, nil
}

// flag reads the flag word words[*i] against l.scope, and its value: after
// "=", or the next word (then *i moves on). ok is false when the flag is
// unknown, or known, taking a value, and words end.
//
//nolint:nonamedreturns // the names tell the strings apart
func (l *line) flag(words []string, i *int) (f *Flag, typed, val string, ok bool) {
	f, typed, val, hasVal := lookup(l.scope, words[*i])
	switch {
	case f == nil:
		return nil, typed, "", false
	case hasVal:
	case f.Bool:
		val = "true"
	case *i+1 == len(words):
		return f, typed, "", false
	default:
		*i++
		val = words[*i]
	}

	return f, typed, val, true
}

// lookup finds the flag a word names: "--name", "--name=v", "-x", "-x=v".
//
//nolint:nonamedreturns // the names tell the strings apart
func lookup(flags []Flag, word string) (f *Flag, typed, val string, hasVal bool) {
	typed, val, hasVal = strings.Cut(word, "=")

	name, long := strings.CutPrefix(typed, "--")
	if !long {
		name = strings.TrimPrefix(typed, "-")
	}

	for i, fl := range flags {
		if long && name != "" && fl.Name == name ||
			!long && fl.Short != 0 && string(fl.Short) == name {
			return &flags[i], typed, val, hasVal
		}
	}

	return nil, typed, val, hasVal
}

func (c *Command) child(word string) *Command {
	for _, s := range c.Commands {
		if s.Name == word || slices.Contains(s.Aliases, word) {
			return s
		}
	}

	return nil
}
