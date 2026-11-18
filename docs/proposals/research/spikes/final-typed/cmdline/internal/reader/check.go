package reader

import (
	"errors"
	"fmt"
	"strings"
)

// Check refuses a tree that Parse would read ambiguously: a word that
// appears twice among the children of one group (names and aliases), a group
// with positionals, a flag spelling that means two flags (or one flag that is
// a bool in one place and takes a value in another) where both may be typed,
// names or shorts that cannot be typed as one word, a command that Serve's
// entry point would hide, and a help text that would break the __complete
// answer. It returns every problem, joined, in declaration order. Parse and
// Complete do not call it.
func Check(root *Command) error {
	var errs []error
	check(root, []string{root.Name}, nil, &errs)
	return errors.Join(errs...)
}

func check(c *Command, path []string, scope []Flag, errs *[]error) {
	at := strings.Join(path, " ")
	bad := func(format string, a ...any) { *errs = append(*errs, fmt.Errorf(format, a...)) }
	if len(c.Commands) > 0 && len(c.Args) > 0 {
		bad("%s: a group takes no positionals", at)
	}
	if strings.ContainsAny(c.Help, "\n\r") {
		bad("%s: help text holds a line break", at)
	}
	seen := map[string]bool{}
	for _, s := range c.Commands {
		for _, w := range append([]string{s.Name}, s.Aliases...) {
			if !word(w) || strings.HasPrefix(w, "-") {
				bad("%s: %q cannot be typed as a command word", at, w)
			}
			if len(path) == 1 && (w == "__complete" || w == "__completeNoDesc") {
				bad("%s: %q is Serve's entry point", at, w)
			}
			if seen[w] {
				bad("%s: %q names two commands", at, w)
			}
			seen[w] = true
		}
	}
	own := map[string]bool{}
	for _, f := range c.Flags {
		if !word(f.Name) || strings.HasPrefix(f.Name, "-") || strings.Contains(f.Name, "=") {
			bad("%s: flag name %q cannot be typed", at, f.Name)
		}
		if f.Short != 0 && (f.Short <= ' ' || f.Short > '~' || f.Short == '-' || f.Short == '=') {
			bad("%s: --%s: short %q is not one printable ASCII letter", at, f.Name, f.Short)
		}
		if strings.ContainsAny(f.Help, "\n\r") {
			bad("%s: --%s: help text holds a line break", at, f.Name)
		}
		if own[f.Name] {
			bad("%s: flag --%s declared twice", at, f.Name)
		}
		own[f.Name] = true
	}
	all := append(append([]Flag{}, scope...), c.Flags...) // what may be typed here, or reach here from above
	for i, f := range all {
		for _, g := range all[:i] {
			same := f.Name == g.Name
			if same && (f.Short != g.Short || f.Bool != g.Bool) || !same && f.Short != 0 && f.Short == g.Short {
				bad("%s: --%s and --%s: one spelling, two flags", at, g.Name, f.Name)
			}
		}
	}
	if len(c.Commands) > 0 {
		scope = all
	}
	for _, s := range c.Commands {
		check(s, append(path[:len(path):len(path)], s.Name), scope, errs)
	}
}

// word: not empty, no space or control byte.
func word(w string) bool {
	return w != "" && !strings.ContainsFunc(w, func(r rune) bool { return r <= ' ' || r == 0x7f })
}
