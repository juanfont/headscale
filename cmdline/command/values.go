package command

import (
	"errors"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/script"
	"github.com/juanfont/headscale/cmdline/table"
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

// NowNever are the words of a node's expiry: now, which expires the node
// at the server's clock, and never.
type NowNever struct{}

func (NowNever) Words() []string { return []string{"now", "never"} }

// Expiry is the value of an expiry flag, read by the one time parser of
// the CLI: a time, a date at midnight UTC, a duration from now, or one of
// the words of W. The command declares with W what it takes: a node takes
// now and never; a type W with no words takes a time alone, and a word is
// a mistake of the line. A default is the flag's default tag, such as
// default:"1h".
type Expiry[W Words] struct {
	word string
	in   time.Duration
	at   time.Time
}

var errZero = errors.New("a duration from now is longer than 0")

func (e *Expiry[W]) UnmarshalText(b []byte) error {
	var w W

	s := string(b)
	if slices.Contains(w.Words(), s) {
		*e = Expiry[W]{word: s}

		return nil
	}

	d, t, ahead, err := table.ReadTime(s)

	switch {
	case err != nil:
		//nolint:err113 // the words are W's
		return errors.New(
			"it is " + oneOf(
				append(
					[]string{"a time", "a date", "a duration such as 90d"},
					w.Words()...),
			),
		)
	case ahead && d == 0:
		return errZero
	case ahead:
		*e = Expiry[W]{in: d}
	default:
		*e = Expiry[W]{at: t}
	}

	return nil
}

// oneOf is "a, b or c".
func oneOf(words []string) string {
	if len(words) == 1 {
		return words[0]
	}

	return strings.Join(words[:len(words)-1], ", ") + " or " + words[len(words)-1]
}

// Word is the word that was given, such as now; "" for a time.
func (e Expiry[W]) Word() string { return e.word }

// At is the time of the expiry for a command that runs at now: a duration
// counts from now. The zero time for a word.
func (e Expiry[W]) At(now time.Time) time.Time {
	switch {
	case e.word != "":
		return time.Time{}
	case e.in > 0:
		return now.Add(e.in)
	}

	return e.at
}
