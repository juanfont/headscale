package cmdline

import (
	"fmt"
	"io"
	"slices"
	"strings"
)

// Completer offers the words that may follow prefix: a flag's value or a
// positional. A word may carry a description after a tab ("json\tJSON").
type Completer func(prefix string) ([]string, Directive)

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
	return func(prefix string) ([]string, Directive) {
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
func Files(string) ([]string, Directive) { return nil, 0 }

// Complete answers Tab: words are the words after the program name before
// the cursor, cur is the word under it ("" for a new word). It runs no
// command and calls only the tree's Completers.
func Complete(root *Command, words []string, cur string) ([]string, Directive) {
	cmd, rest, flags := root, words, root.Flags
	for len(cmd.Commands) > 0 {
		_, r, err := parse(flags, rest, true)
		if e, ok := err.(*Error); ok && e.Kind == MissingValue { // "prog -o <Tab>"
			f, _, _, _ := lookup(flags, e.Word)
			return value(f, cur)
		}
		if err != nil || len(r) == 0 {
			break
		}
		if cmd = cmd.child(r[0]); cmd == nil {
			return nil, NoFiles
		}
		rest, flags = r[1:], append(slices.Clip(flags), cmd.Flags...)
	}
	if n := len(rest); n > 0 && !strings.Contains(rest[n-1], "=") {
		if f, _, _, _ := lookup(cmd.Flags, rest[n-1]); f != nil && !f.Bool {
			return value(f, cur)
		}
	}
	if name, val, ok := strings.Cut(cur, "="); ok && strings.HasPrefix(cur, "-") {
		f, _, _, _ := lookup(cmd.Flags, name)
		return value(f, val) // the scripts put "--x=" back
	}
	var out []string
	add := func(word string) {
		if strings.HasPrefix(word, cur) {
			out = append(out, word)
		}
	}
	switch {
	case strings.HasPrefix(cur, "-") && !slices.Contains(rest, "--"):
		for _, f := range cmd.Flags {
			add("--" + f.Name)
			if f.Short != 0 && cur == "-"+string(f.Short) {
				add(cur)
			}
		}
	case len(cmd.Commands) > 0:
		for _, c := range cmd.Commands {
			add(c.Name)
		}
		if len(out) == 0 { // aliases only when no name fits, as cobra does
			for _, c := range cmd.Commands {
				for _, a := range c.Aliases {
					add(a)
				}
			}
		}
	default:
		_, args, err := parse(cmd.Flags, rest, false)
		if err != nil || len(args) >= len(cmd.Args) || cmd.Args[len(args)] == nil {
			break
		}
		return cmd.Args[len(args)](cur)
	}
	return out, NoFiles
}

func value(f *Flag, cur string) ([]string, Directive) {
	if f == nil || f.Complete == nil {
		return nil, NoFiles
	}
	return f.Complete(cur)
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
