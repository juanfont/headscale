// Package command is Headscale's layer over the parser cmdline: the command
// spec and the one builder that runs every command.
//
// A command is a [Spec] (or a [ListSpec]): its texts, one input struct whose
// fields are its arguments and flags, the type of what it gives back, and
// one function that makes the API call. The builder does the rest, in one
// order, for every command: it reads the line, shows help, checks the
// argument count, makes the API client, checks the server's version, runs
// the command, turns a problem of the server into the CLI's sentence and
// prints the result. Only this package imports cmdline.
package command

import (
	"context"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	"github.com/juanfont/headscale/hscontrol/types"
)

// Spec is a command that gives back one object, or [NoOutput].
type Spec[In, Out any] struct {
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
	// NeedsChange is a command whose Opt flags each change a field, such as
	// a set: a line that gives none of them is refused before any call.
	NeedsChange bool

	// Columns show Out as a sheet.
	Columns table.Columns[Out]
	// Run is the one function that does the work.
	Run func(c Ctx, in In) (Out, error)
	// Done is the text printed in place of Out, when not -o json. now is
	// the time the command runs at, for a relative time.
	Done func(in In, out Out, now time.Time) string
}

// ListSpec is a command that gives back rows, printed as a table.
type ListSpec[In, Row any] struct {
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
	// NoRows is what a terminal shows when no row is left: "No users.".
	NoRows string
	Run    func(c Ctx, in In) ([]Row, error)
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
type Ctx struct {
	context.Context //nolint:containedctx // the context of the run, by design

	// API is the v0 client; nil for a command that needs no server.
	API *API
	// ConfigFile is what --config or HEADSCALE_CONFIG names; "" for none.
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
	// screen is a stdout that is a terminal.
	screen bool
	// line is the command line, for the flags the builder adds.
	line *cmdline.Line

	json     bool
	now      func() time.Time
	build    *types.VersionInfo
	releases func(context.Context) ([]string, error)
}

// Note writes a line for the human to stderr. With -o json it writes
// nothing: the object takes its place.
func (c Ctx) Note(line string) {
	if !c.json {
		_, _ = io.WriteString(c.stderr, line+"\n")
	}
}

// Now is the time the command runs at.
func (c Ctx) Now() time.Time { return c.now() }

// Build is the version of this binary, as the run sees it.
func (c Ctx) Build() *types.VersionInfo { return c.build }

// Releases lists the release tags of headscale, for the update hint; none
// when the run has no source of them.
func (c Ctx) Releases(ctx context.Context) ([]string, error) {
	if c.releases == nil {
		return nil, nil
	}

	return c.releases(ctx)
}

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
	// PageSize is the rows of one page of a list walk; 0 is 1000, the most
	// v0 takes. A test sets it small, to walk many pages.
	PageSize int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Answered, when set, is told every answer of the server as it came, so
	// a test compares -o json with what the server sent in that run.
	Answered func(req *http.Request, body []byte)
	// Version is the build the run is; nil is this binary's. A test sets
	// it to run as a release.
	Version *types.VersionInfo
	// Releases lists the release tags of headscale; nil gives no update
	// hint. Only main sets it, so no test reaches the network.
	Releases func(ctx context.Context) ([]string, error)
}

// OSEnv is the Env of the process.
func OSEnv() Env {
	terminal := func(f *os.File) bool {
		st, err := f.Stat()

		return err == nil && st.Mode()&os.ModeCharDevice != 0
	}

	return Env{
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Environ:        os.Environ(),
		Terminal:       terminal(os.Stdin),
		StdoutTerminal: terminal(os.Stdout),
	}
}
