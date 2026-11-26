// Package command is a layer over the parser cmdline for a program that
// talks to a server: the command spec and the one builder that runs every
// command.
//
// A command is a [Spec] (or a [ListSpec]): its texts, one input struct whose
// fields are its arguments and flags, the type of what it gives back, and
// one function that makes the call. The builder does the rest, in one
// order, for every command: it reads the line, shows help, checks the
// argument count, makes the session the program calls its server with (S),
// runs the command, turns an error into the program's sentence and prints
// the result. What is the program's own, its session and its server's
// errors, is a [Program].
package command

import (
	"context"
	"io"
	"os"
	"time"

	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/cmdline/table"
	"golang.org/x/term"
)

// Spec is a command that gives back one object, or [NoOutput]; S is the
// session of the program (Ctx.API).
type Spec[S, In, Out any] struct {
	// Name is the command word; with the arg fields of In it makes the
	// usage line.
	Name string
	// Short is one line that starts with a verb.
	Short string
	// Long is the full text: what it does, its rules, whether it prompts,
	// what -o json returns.
	Long string
	// Example holds at least one runnable example; each is a test case.
	Example []string
	// Aliases are only ls, rm and approve.
	Aliases []string
	// OldNames are the paths this command had before the redesign, such as
	// "health"; an unknown command that is one of them points here.
	OldNames []string

	// Local is a command that needs no server.
	Local bool
	// NeedsServer decides, for a Local command, whether this input talks to
	// the server after all. It runs before the lookups.
	NeedsServer func(in In) bool
	// ReadsConfig gives a Local command --config.
	ReadsConfig bool

	// Columns show Out as a sheet.
	Columns table.Columns[Out]
	// Run is the one function that does the work.
	Run func(c Ctx[S], in In) (Out, error)
	// Done is the text printed in place of Out, when not -o json. now is
	// the time the command runs at, for a relative time.
	Done func(in In, out Out, now time.Time) string
}

// ListSpec is a command that gives back rows, printed as a table.
type ListSpec[S, In, Row any] struct {
	Name     string
	Short    string
	Long     string
	Example  []string
	Aliases  []string
	OldNames []string

	Local       bool
	NeedsServer func(in In) bool
	ReadsConfig bool

	// Columns are required: a list without columns cannot be written.
	Columns table.Columns[Row]
	Run     func(c Ctx[S], in In) ([]Row, error)
}

// NoInput is the input of a command that takes nothing.
type NoInput struct{}

// NoOutput is the result of a command that gives nothing back.
type NoOutput struct{}

// Opt is a value that may be left out; [Opt.Get] says whether it was given.
// As an argument it makes the argument optional.
type Opt[T any] = cmdline.Opt[T]

// Path is a file path; Tab offers files for it.
type Path = cmdline.Path

// Ctx is what Run gets. It is the context of the command, so a call made
// with it ends when the command's time is up.
type Ctx[S any] struct {
	context.Context //nolint:containedctx // the context of the run, by design
	*run

	// API is the session of the run (Program.Session).
	API S
}

// run is what a run keeps, whatever its session.
type run struct {
	// ConfigFile is what --config or the program's ConfigEnv names; "" for
	// none.
	ConfigFile string

	// Environ is the environment, for a command that reads the config.
	Environ []string

	// The streams are the builder's: a command returns what it prints, so
	// nothing it writes can break -o json, and the prompt is asked by the
	// builder.
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	terminal bool

	json bool
	now  func() time.Time
	// tree is the tree that runs, for its program.
	tree *Tree
	// api is the session, Ctx.API; server says the line talks to a server.
	api    any
	server bool
}

// Note writes a line for the human to stderr. With -o json it writes
// nothing: the object takes its place.
func (c *run) Note(line string) {
	if !c.json {
		_, _ = io.WriteString(c.stderr, line+"\n")
	}
}

// Stderr is stderr: a warning written to it is read also with -o json,
// unlike a Note, for what a script must see too.
func (c *run) Stderr() io.Writer { return c.stderr }

// Now is the time the command runs at.
func (c *run) Now() time.Time { return c.now() }

// Env is the world a run of the CLI sees. Tests give each run its own.
type Env struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	// Environ is the environment, in the form of os.Environ.
	Environ []string
	// Terminal reports whether stdin is a terminal, which a prompt needs.
	Terminal bool
	// StdoutTerminal reports whether stdout is a terminal: an empty list
	// then says so in words.
	StdoutTerminal bool
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Context is the context of the run; nil is context.Background(). The
	// program's session reads what it put there.
	Context context.Context //nolint:containedctx // the run's own, by design
}

// terminal reports whether f is a terminal; /dev/null is a character
// device and no terminal.
func terminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd())) //nolint:gosec // a file descriptor fits an int
}

// OSEnv is the Env of the process.
func OSEnv() Env {
	return Env{
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Environ:        os.Environ(),
		Terminal:       terminal(os.Stdin),
		StdoutTerminal: terminal(os.Stdout),
	}
}
