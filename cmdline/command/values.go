package command

import (
	"errors"
	"io"
	"slices"
	"strings"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/script"
)

// Words is a fixed set of words, for [OneOf].
type Words interface{ Words() []string }

// OneOf is a word of W: Tab offers W's words, and any other word is a
// mistake of the line.
type OneOf[W Words] string

func (o *OneOf[W]) UnmarshalText(b []byte) error {
	var w W

	words := w.Words()
	if !slices.Contains(words, string(b)) {
		//nolint:err113 // the words are W's
		return errors.New("it is one of " + strings.Join(words, ", "))
	}

	*o = OneOf[W](b)

	return nil
}

func (OneOf[W]) Complete(_ *cmdline.Line, prefix string) ([]string, cmdline.Directive) {
	var w W

	return cmdline.Words(prefix, w.Words()...), cmdline.NoFiles
}

// Shells are the shells that [Script] writes for.
type Shells struct{}

func (Shells) Words() []string { return []string{"bash", "zsh", "fish", "powershell"} }

// Script writes the completion script of shell for the program: cobra's
// scripts, which call the hidden entry point that [Run] answers.
func Script(w io.Writer, shell OneOf[Shells], program string) error {
	return script.Write(w, string(shell), program)
}
