package cmdline

import (
	"fmt"
	"strings"
)

// Check refuses a tree that Parse would read ambiguously: a word that
// appears twice among the children of one group (names and aliases), a group
// with positionals, a flag spelling that means two flags (or one flag that is
// a bool in one place and takes a value in another) where both may be typed,
// names or shorts that cannot be typed as one word, a command that Serve's
// entry point would hide, and a help text that would break the __complete
// answer. Parse and Complete do not call it; a caller runs it once, in a test
// or at start.
func Check(root *Command) error {
	return check(root, []string{root.Name}, nil)
}

func check(c *Command, path []string, scope []Flag) error {
	at := strings.Join(path, " ")
	if len(c.Commands) > 0 && len(c.Args) > 0 {
		return fmt.Errorf("%s: a group takes no positionals", at)
	}
	if strings.ContainsAny(c.Help, "\n\r") {
		return fmt.Errorf("%s: help text holds a line break", at)
	}
	seen := map[string]bool{}
	for _, s := range c.Commands {
		for _, w := range append([]string{s.Name}, s.Aliases...) {
			if !word(w) || strings.HasPrefix(w, "-") {
				return fmt.Errorf("%s: %q cannot be typed as a command word", at, w)
			}
			if len(path) == 1 && (w == "__complete" || w == "__completeNoDesc") {
				return fmt.Errorf("%s: %q is Serve's entry point", at, w)
			}
			if seen[w] {
				return fmt.Errorf("%s: %q names two commands", at, w)
			}
			seen[w] = true
		}
	}
	own := map[string]bool{}
	for _, f := range c.Flags {
		if !word(f.Name) || strings.HasPrefix(f.Name, "-") || strings.Contains(f.Name, "=") {
			return fmt.Errorf("%s: flag name %q cannot be typed", at, f.Name)
		}
		if f.Short != 0 && (f.Short <= ' ' || f.Short > '~' || f.Short == '-' || f.Short == '=') {
			return fmt.Errorf("%s: --%s: short %q is not one printable ASCII letter", at, f.Name, f.Short)
		}
		if strings.ContainsAny(f.Help, "\n\r") {
			return fmt.Errorf("%s: --%s: help text holds a line break", at, f.Name)
		}
		if own[f.Name] {
			return fmt.Errorf("%s: flag --%s declared twice", at, f.Name)
		}
		own[f.Name] = true
	}
	all := append(append([]Flag{}, scope...), c.Flags...) // what may be typed here, or reach here from above
	for i, f := range all {
		for _, g := range all[:i] {
			same := f.Name == g.Name
			if same && (f.Short != g.Short || f.Bool != g.Bool) || !same && f.Short != 0 && f.Short == g.Short {
				return fmt.Errorf("%s: --%s and --%s: one spelling, two flags", at, g.Name, f.Name)
			}
		}
	}
	if len(c.Commands) > 0 {
		scope = all
	}
	for _, s := range c.Commands {
		if err := check(s, append(path[:len(path):len(path)], s.Name), scope); err != nil {
			return err
		}
	}
	return nil
}

// word: not empty, no space or control byte.
func word(w string) bool {
	return w != "" && !strings.ContainsFunc(w, func(r rune) bool { return r <= ' ' || r == 0x7f })
}
