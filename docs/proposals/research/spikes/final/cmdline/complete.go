package cmdline

import (
	"fmt"
	"io"
	"strings"
)

// Completer offers the words that may follow prefix: a flag's value or a
// positional. line is what was typed before the word under the cursor, read
// as Parse reads it but never refused (words it cannot read are left out).
// A word may carry a description after a tab ("json\tJSON").
type Completer func(line *Match, prefix string) ([]string, Directive)

// Directive tells the completion script what to do with the words. The bits
// are cobra's ShellCompDirective, so cobra's scripts read them.
type Directive int

const (
	Failed     Directive = 1 << iota // the script shows nothing
	NoSpace                          // no space after the word: room for ",x" or "=x"
	NoFiles                          // offer no file names when there are no words
	FilterExt                        // the words are file extensions to filter by
	FilterDirs                       // offer directories (in the word, if one is given)
	KeepOrder                        // keep the order of the words
)

// Words completes from a fixed list.
func Words(words ...string) Completer {
	return func(_ *Match, prefix string) ([]string, Directive) {
		var out []string
		for _, w := range words {
			if strings.HasPrefix(w, prefix) {
				out = append(out, w)
			}
		}
		return out, NoFiles
	}
}

// Files lets the shell offer file names.
func Files(*Match, string) ([]string, Directive) { return nil, 0 }

// Complete answers Tab: words are the words after the program name before
// the cursor, cur is the word under it ("" for a new word). It runs no
// command and calls only the tree's Completers.
func Complete(root *Command, words []string, cur string) ([]string, Directive) {
	l, _ := read(root, words, true)
	m, cmd := l.m, l.m.Command
	switch name, val, isVal := strings.Cut(cur, "="); {
	case l.wait != nil: // the word under the cursor is a value, whatever it looks like (D20)
		return value(l.wait, m, cur)
	case !l.ended && isVal && strings.HasPrefix(cur, "-"):
		f, _, _, _ := lookup(l.scope, name)
		if f == nil || f.Bool {
			return nil, NoFiles
		}
		return value(f, m, val) // the scripts put "--x=" back
	case !l.ended && strings.HasPrefix(cur, "-"):
		var out []string
		for _, f := range cmd.Flags { // long names; a short only when typed in full (D29)
			if m.Values(f.Name) != nil && !f.Repeat {
				continue // given once already (D15)
			}
			out = add(out, cur, "--"+f.Name, f.Help)
			if f.Short != 0 && cur == "-"+string(f.Short) {
				out = add(out, cur, cur, f.Help)
			}
		}
		return out, NoFiles
	case len(cmd.Commands) > 0:
		var out []string
		for _, c := range cmd.Commands {
			out = add(out, cur, c.Name, c.Help)
		}
		if len(out) == 0 { // an alias only when no name fits (D16)
			for _, c := range cmd.Commands {
				for _, a := range c.Aliases {
					out = add(out, cur, a, c.Help)
				}
			}
		}
		return out, NoFiles
	case len(m.Args) < len(cmd.Args) && cmd.Args[len(m.Args)] != nil:
		return cmd.Args[len(m.Args)](m, cur)
	}
	return nil, NoFiles
}

func add(out []string, cur, word, help string) []string {
	if !strings.HasPrefix(word, cur) {
		return out
	}
	if help != "" {
		word += "\t" + help
	}
	return append(out, word)
}

func value(f *Flag, m *Match, cur string) ([]string, Directive) {
	if f.Complete == nil || m.Values(f.Name) != nil && !f.Repeat { // given once already (D15)
		return nil, NoFiles
	}
	return f.Complete(m, cur)
}

// Serve answers the hidden entry point the completion scripts call: when
// args[0] is "__complete" or "__completeNoDesc" it writes the words and
// the directive to w and reports true. Write errors are dropped: the
// script is the reader and has no way to show them.
func Serve(w io.Writer, root *Command, args []string) bool {
	if len(args) == 0 || args[0] != "__complete" && args[0] != "__completeNoDesc" {
		return false
	}
	noDesc := args[0] == "__completeNoDesc"
	args = args[1:]
	if len(args) == 0 {
		args = []string{""}
	}
	words, dir := Complete(root, args[:len(args)-1], args[len(args)-1])
	for _, word := range words {
		if noDesc {
			word, _, _ = strings.Cut(word, "\t")
		}
		fmt.Fprintln(w, word)
	}
	fmt.Fprintf(w, ":%d\n", dir)
	return true
}
