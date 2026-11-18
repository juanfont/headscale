package diff

import (
	"fmt"
	"slices"
	"strings"

	"spike/kit"
)

// Named is one adapter under test.
type Named struct {
	Name string
	A    kit.Adapter
}

// Outcome runs argv and never panics: a panic is an outcome.
func Outcome(a kit.Adapter, argv []string) (o string) {
	defer func() {
		if p := recover(); p != nil {
			o = fmt.Sprintf("panic: %v", p)
		}
	}()
	return kit.RunOnce(a, argv)
}

// Tab is Outcome for Complete.
func Tab(a kit.Adapter, argv []string) (o string) {
	defer func() {
		if p := recover(); p != nil {
			o = fmt.Sprintf("panic: %v", p)
		}
	}()
	return kit.ProbeComplete(a, argv)
}

// Kind is the first word of an outcome: run, help, unknown-flag, ...
func Kind(o string) string {
	k, _, _ := strings.Cut(o, " ")
	return strings.TrimSuffix(k, ":")
}

// Shrink makes argv as small and plain as it can while still, for the
// adapters a and b, giving outcomes that differ with the same kinds (Run)
// or that still differ (Tab). Deterministic.
func Shrink(argv []string, still func([]string) bool) []string {
	cur := slices.Clone(argv)
	budget := 400
	try := func(c []string) bool {
		if budget <= 0 {
			return false
		}
		budget--
		if still(c) {
			cur = c
			return true
		}
		return false
	}
	for changed := true; changed; {
		changed = false
		for i := 0; i < len(cur); i++ { // drop a word
			if try(slices.Delete(slices.Clone(cur), i, i+1)) {
				changed, i = true, i-1
			}
		}
		for i := 0; i+1 < len(cur); i++ { // drop a pair (a flag and its value)
			if try(slices.Delete(slices.Clone(cur), i, i+2)) {
				changed, i = true, i-1
			}
		}
		for i := range cur { // plainer words
			for _, s := range simpler(cur[i]) {
				if s == cur[i] {
					break
				}
				c := slices.Clone(cur)
				c[i] = s
				if try(c) {
					changed = true
					break
				}
			}
		}
	}
	return cur
}

// simpler lists replacements for a word, plainest first.
func simpler(w string) []string {
	out := []string{"x", "12"}
	if strings.HasPrefix(w, "-") {
		out = []string{"-", "--"}
	}
	if name, val, ok := strings.Cut(w, "="); ok && strings.HasPrefix(w, "-") {
		for _, v := range []string{"", "x", "-x", "true"} {
			out = append(out, name+"="+v)
		}
		_ = val
	}
	if len(w) > 8 {
		out = append(out, w[:8], w[:len(w)/2])
	}
	if !isPrint(w) {
		out = append(out, strings.Map(func(r rune) rune {
			if r < ' ' || r == 0xFFFD || r > '~' {
				return -1
			}
			return r
		}, w))
	}
	return out
}

func isPrint(w string) bool {
	for _, r := range w {
		if r < ' ' || r > '~' {
			return false
		}
	}
	return true
}

// Abstract maps a shrunk line to word classes so lines with the same cause
// land in one bucket: "--F:bool=v", "-s:str", "CMD", "V-", ...
func Abstract(t *kit.Tree, argv []string) string {
	var out []string
	for _, w := range argv {
		out = append(out, class(t, w))
	}
	return strings.Join(out, " ")
}

func class(t *kit.Tree, w string) string {
	switch {
	case w == "--" || w == "-":
		return w
	case w == "":
		return "''"
	case strings.HasPrefix(w, "--"):
		name, val, eq := strings.Cut(w[2:], "=")
		s := "--" + flagKind(t, name, false)
		if eq {
			s += "=" + valClass(t, val)
		}
		return s
	case strings.HasPrefix(w, "-"):
		name, val, eq := strings.Cut(w[1:], "=")
		var s string
		switch {
		case len(name) == 1:
			s = "-" + flagKind(t, name, true)
		case len(name) > 1 && flagKind(t, name[:1], true) != "?":
			s = "-" + flagKind(t, name[:1], true) + "+tail"
		default:
			s = "-?" + "(" + valClass(t, name) + ")"
		}
		if eq {
			s += "=" + valClass(t, val)
		}
		return s
	}
	return valClass(t, w)
}

func flagKind(t *kit.Tree, name string, short bool) string {
	for _, c := range t.Commands {
		for _, f := range c.Flags {
			if !short && f.Name == name || short && f.Short == name && name != "" {
				if f.Name == "help" || f.Name == "version" {
					return f.Name
				}
				if f.Global {
					return "G:" + f.Kind.String()
				}
				return f.Kind.String()
			}
		}
	}
	return "?"
}

func valClass(t *kit.Tree, w string) string {
	switch {
	case w == "":
		return "''"
	case strings.HasPrefix(w, "-"):
		return "V-"
	case strings.ContainsRune(w, 0):
		return "NUL"
	case !isPrint(w):
		return "U"
	}
	for _, c := range t.Commands {
		if len(c.Path) > 0 && (c.Path[len(c.Path)-1] == w || slices.Contains(c.Aliases, w)) {
			return "CMD"
		}
	}
	if w == "true" || w == "false" {
		return "BOOL"
	}
	return "V"
}
