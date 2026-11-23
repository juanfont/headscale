package cmdline

import (
	"io"
	"reflect"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline/reader"
)

// Completer is implemented by a type that offers its own words on Tab, for
// a flag value or an argument of that type. line is what was typed before
// the word under the cursor, read as Parse reads it but never refused; no
// struct of it is filled. prefix is the word under the cursor; in a list it
// is the item after the last comma. A word may carry a description after a
// tab. Complete is called on the zero value and must not use it.
//
// A field whose type has no Complete offers nothing.
type Completer interface {
	Complete(line *Line, prefix string) ([]string, Directive)
}

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

// Words returns the words that start with prefix, for a Completer with a
// fixed list.
func Words(prefix string, words ...string) []string {
	var out []string

	for _, w := range words {
		if strings.HasPrefix(w, prefix) {
			out = append(out, w)
		}
	}

	return out
}

// completer is the reader's Completer for f, or nil when the type of f
// offers nothing. In a list only the item after the last comma is
// completed; the items before it are kept, and no space follows, so the
// next item can.
func (f *field) completer(nodes map[*reader.Command]*node) reader.Completer {
	c, ok := reflect.TypeAssert[Completer](reflect.Zero(f.elem))
	if !ok {
		if c, ok = reflect.TypeAssert[Completer](reflect.New(f.elem)); !ok {
			return nil
		}
	}

	return func(m *reader.Match, cur string) ([]string, reader.Directive) {
		l := (&Tree{nodes: nodes}).line(m)

		i := strings.LastIndex(cur, ",")
		if !f.list || i < 0 {
			words, dir := c.Complete(l, cur)
			return words, reader.Directive(dir)
		}

		words, dir := c.Complete(l, cur[i+1:])
		// Extensions and directories describe the shell's file search.
		if dir&(FilterExt|FilterDirs) != 0 {
			return words, reader.Directive(dir | NoSpace)
		}

		// The list prefix is copied verbatim into every candidate.
		if len(words) > 0 && strings.ContainsAny(cur[:i+1], "\t\r\n") {
			return nil, reader.NoFiles
		}

		words = slices.Clone(words)

		for j := range words {
			words[j] = cur[:i+1] + words[j]
		}

		return words, reader.Directive(dir | NoSpace)
	}
}

// Complete answers Tab: words are the words after the program name before
// the cursor, cur is the word under it ("" for a new word). It offers
// command names, flag names and what the Completers of the field types
// offer. It runs no command and no reader.
func (t *Tree) Complete(words []string, cur string) ([]string, Directive) {
	out, dir := reader.Complete(t.root.low, words, cur)
	return out, Directive(dir)
}

// Serve answers the hidden entry point the completion scripts call: when
// args[0] is "__complete" or "__completeNoDesc" it writes the words and the
// directive to w and reports true. A program calls it first in main.
func (t *Tree) Serve(w io.Writer, args []string) bool {
	return reader.Serve(w, t.root.low, args)
}
