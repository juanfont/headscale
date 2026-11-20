// Package cmdline reads a command line against a tree of commands that the
// caller describes as plain data, and answers shell completion for that
// tree over cobra's __complete protocol.
//
// It does the grammar and nothing else: no help, no conversion of values,
// no argument counts, no error wording beyond a default, no os.Exit, no
// package state. Every value comes back as the string that was typed, and
// every occurrence of a flag is kept, so the caller decides what a repeat
// or "--force=maybe" means.
//
// The grammar: --name, --name=value, --name value, -x, -x=value, -x value.
// A bool flag never takes the next word. The word after a value flag is its
// value, whatever it looks like. Flags and positionals mix in any order;
// "--" ends the flags. Attached short values (-ovalue), grouped shorts (-ab)
// and abbreviations are unknown flags.
package cmdline

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
	Complete Completer // Tab for the value; nil offers nothing
}

// Match is a command line that Parse could read.
type Match struct {
	Command *Command
	Path    []string            // names from the root (not aliases), root excluded
	Flags   map[string][]string // by long name: every value given, in order
	Args    []string            // positionals, in order
}

// ErrorKind says what Parse could not read.
type ErrorKind int

const (
	UnknownCommand ErrorKind = iota + 1 // Word is not a command of the group at Path
	UnknownFlag                         // Word is the flag as typed, up to any "="
	MissingValue                        // Word is the flag as typed; argv ended
)

// Error is every error Parse returns. Its text is a default; callers that
// write their own read Kind, Path and Word.
type Error struct {
	Kind ErrorKind
	Path []string // the command reached, as in Match.Path
	Word string
}

func (e *Error) Error() string {
	at := ""
	if len(e.Path) > 0 {
		at = fmt.Sprintf(" for %q", strings.Join(e.Path, " "))
	}
	switch e.Kind {
	case UnknownCommand:
		return fmt.Sprintf("unknown command %q%s", e.Word, at)
	case UnknownFlag:
		return fmt.Sprintf("unknown flag %s%s", e.Word, at)
	}
	return fmt.Sprintf("flag %s needs a value", e.Word)
}

// Parse reads argv (without the program name) against root. A group with
// nothing after it is a Match too: what to do with it is the caller's call.
func Parse(root *Command, argv []string) (*Match, error) {
	m := &Match{Command: root}
	cmd, rest, flags := root, argv, root.Flags
	var pre []string // flag words typed before the command was reached
	for len(cmd.Commands) > 0 {
		_, r, err := parse(flags, rest, true)
		if err != nil {
			return nil, at(err, m.Path)
		}
		pre = append(pre, rest[:len(rest)-len(r)]...)
		if len(r) == 0 {
			m.Flags, _, _ = parse(flags, pre, false)
			return m, nil
		}
		if cmd = cmd.child(r[0]); cmd == nil {
			return nil, &Error{UnknownCommand, m.Path, r[0]}
		}
		m.Command, m.Path, rest = cmd, append(m.Path, cmd.Name), r[1:]
		flags = append(slices.Clip(flags), cmd.Flags...)
	}
	vals, args, err := parse(cmd.Flags, append(pre, rest...), false)
	if err != nil {
		return nil, at(err, m.Path)
	}
	m.Flags, m.Args = vals, args
	return m, nil
}

// parse reads the flags in argv. With stop it returns at the first
// positional or "--", left in rest, so the walk can read a command word.
func parse(flags []Flag, argv []string, stop bool) (vals map[string][]string, rest []string, err error) {
	vals = map[string][]string{}
	for i := 0; i < len(argv); i++ {
		a := argv[i]
		if a == "--" && !stop {
			return vals, append(rest, argv[i+1:]...), nil
		}
		if a == "--" || len(a) < 2 || a[0] != '-' {
			if stop {
				return vals, argv[i:], nil
			}
			rest = append(rest, a)
			continue
		}
		f, typed, val, hasVal := lookup(flags, a)
		if f == nil {
			return nil, nil, &Error{Kind: UnknownFlag, Word: typed}
		}
		switch {
		case hasVal:
		case f.Bool:
			val = "true"
		case i+1 == len(argv):
			return nil, nil, &Error{Kind: MissingValue, Word: typed}
		default:
			i++
			val = argv[i]
		}
		vals[f.Name] = append(vals[f.Name], val)
	}
	return vals, rest, nil
}

// lookup finds the flag a word names: "--name", "--name=v", "-x", "-x=v".
func lookup(flags []Flag, word string) (f *Flag, typed, val string, hasVal bool) {
	typed, val, hasVal = strings.Cut(word, "=")
	long, name := strings.HasPrefix(typed, "--"), strings.TrimLeft(typed, "-")
	if !strings.HasPrefix(typed, "-") || strings.HasPrefix(typed, "---") || name == "" {
		return nil, typed, val, hasVal
	}
	for i, fl := range flags {
		if long && fl.Name == name || !long && fl.Short != 0 && string(fl.Short) == name {
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

func at(err error, path []string) error {
	err.(*Error).Path = path
	return err
}
