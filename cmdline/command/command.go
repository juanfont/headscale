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
// the result. What is the program's own, its session, its server's errors,
// its credentials, is a [Program].
package command

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"reflect"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

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
	// "health"; an unknown command that is one of them points here. One may
	// end in the flags that the old command meant: "dumpConfig --running".
	OldNames []string

	// Local is a command that needs no server.
	Local bool
	// NeedsServer decides, for a Local command, whether this input talks to
	// the server after all. It runs before the lookups.
	NeedsServer func(in In) bool
	// ReadsConfig gives a Local command --config.
	ReadsConfig bool
	// NoJSON is a test tool that prints one fixed format: it takes no
	// --output.
	NoJSON bool
	// IgnoresConfig decides, for a command with ReadsConfig, that this
	// input reads no config, such as a check of a file it names: --config
	// and HEADSCALE_CONFIG are not looked at then.
	IgnoresConfig func(in In) bool
	// MissingConfig runs when the config file that --config or
	// HEADSCALE_CONFIG names does not exist, before the run ends with the
	// base's sentence: serve logs what the environment warns about, as it
	// does for a file it loads.
	MissingConfig func(c Ctx[S])
	// NeedsChange is a command whose Opt flags each change a field, such as
	// a set: a line that gives none of them is refused before any call.
	NeedsChange bool

	// Columns show Out as a sheet; Blocks follow its lines.
	Columns table.Columns[Out]
	Blocks  table.Blocks[Out]
	// Confirm is the question asked before Run, for a command whose change
	// cannot be undone; a Prompt with no Question asks nothing this time. A
	// command with Confirm takes --force, which answers yes. It runs again
	// after the server refused the guard the builder stored, on the target
	// as it is then, also under --force, so a question made from a call to
	// the server is made anew.
	Confirm func(c Ctx[S], in In) (Prompt, error)
	// Changed is the code with which the server refuses the Guard that
	// Confirm hands over, when what the question showed is no longer true:
	// the builder then asks again and runs once more. A spec with Changed
	// hands over a Guard every time, on a target that is an entity with no
	// revision. A target's revision needs no Changed: precondition_failed
	// refuses it. The builder tries again only a refusal of a guard it
	// stored, never one a command sends itself.
	Changed string
	// Hint is a line of what to do after a wrong argument count, an empty
	// list argument, or a word of another kind than its lookup takes, such
	// as a tag for a user, from the arguments as typed; "" adds nothing.
	Hint func(args []string) string
	// EmptyList is why an empty list argument is refused, said after "the
	// tag list is empty.", so the CLI's refusal reads as the server's.
	EmptyList string
	// Valid checks a value that the parser takes as any word, such as a
	// route, once the line is read and before any call or lookup; its error
	// is the sentence. The lookups have not run, so it sees no entity.
	Valid func(in In) error
	// Run is the one function that does the work. A Run whose change is
	// made and whose object to print cannot be read returns ErrNotRead.
	Run func(c Ctx[S], in In) (Out, error)
	// Done is the text printed in place of Out, when not -o json. now is
	// the time the command runs at, for a relative time.
	Done func(in In, out Out, now time.Time) string
	// Secret is the secret of a result shown once, such as a new key: Done
	// goes to stderr first, then the secret alone to stdout. -o json prints
	// the result. Each is written past the rule that shows a credential as
	// its kind (credential.go). A result that holds a field key or secret,
	// at any depth, needs Secret, and no other may have it; the command
	// needs list and delete beside it, which a lost secret names.
	Secret func(out Out) string
	// Verbatim is a text of the result that the server keeps, such as the
	// policy, printed to stdout byte for byte: not trimmed, not made
	// visible, past the rule that shows a credential as its kind, so a file
	// it is written to holds what the server holds. -o json prints the
	// result. It takes neither Columns nor Done, and a test lists each
	// command that has it, with why.
	Verbatim func(out Out) string
	// End is the delete of what a Secret command beside it makes: a
	// Secret's group needs one, and only such a group has one.
	End bool
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
	// NoRows is what a terminal shows when no row is left: "No users.".
	NoRows string
	// Only is the filter the list applies unless told otherwise, such as
	// state=valid: the API gives every row, and the list hides the ones a
	// person rarely wants. --all, or a --filter on its column, removes it,
	// and --all adds its column to the default columns. A list with Only
	// takes --all, and its Long says what --all shows.
	Only string
	Run  func(c Ctx[S], in In) ([]Row, error)
}

// Prompt is what a command asks: the Question, to which the builder adds
// " [y/N]", and the Action that --force would take, for the error when no
// terminal can answer: "delete Node 12 (mynode)". Warning, when there is
// one, is a sentence that follows both; the builder reads it only when a
// person will read it, after --force, so it may cost a call. List is shown
// under the question, on one line cut to the terminal, and [y/N] then
// stands on a line of its own.
//
// Guard stands for what the question showed, such as the token of a dry
// run: the builder hands it to the write on the target (Ctx.Expect). It
// needs Spec.Changed, and a spec with Changed always gives one: a guard is
// never dropped. It is never kept in a variable of the spec: a spec is
// shared by every run.
type Prompt struct {
	Question string
	Action   string
	Warning  func() string
	List     []string
	Guard    string
}

// NoInput is the input of a command that takes nothing.
type NoInput struct{}

// NoOutput is the result of a command that gives nothing back.
type NoOutput struct{}

// Said is the result of a write whose answer has no body, such as a 204:
// What is what the command read before it acted, for Done to name. -o json
// prints nothing, as for NoOutput.
type Said struct{ What string }

// Text is the result of a local command that prints a text and no object,
// such as a generated file: it is printed as a Verbatim text is, so it
// holds its own line ends, and the command has no --output. Only a Local
// spec may have it: a server command prints the server's answer.
type Text string

// Failed is what a Run returns with its Text when the text is printed and
// the run fails all the same, such as a report with a line that failed:
// the builder prints the text, then err. With any other result it is err
// alone, so a server command's error stays the server's, and no secret is
// printed past its rule. Failed(nil) is nil.
func Failed(err error) error {
	if err == nil {
		return nil
	}

	return &failure{err: err}
}

type failure struct{ err error }

func (f *failure) Error() string { return f.err.Error() }
func (f *failure) Unwrap() error { return f.err }

// ExitCode is err, ending the run with code in place of 1, for a command
// whose exit code a caller reads, such as serve under systemd. Only a Local
// spec has it; elsewhere, and for a code outside 1 to 255, the run exits 1
// as for any error. ExitCode(code, nil) is nil.
func ExitCode(code int, err error) error {
	if err == nil {
		return nil
	}

	return &exitError{code: code, err: err}
}

type exitError struct {
	code int
	err  error
}

func (e *exitError) Error() string { return e.err.Error() }
func (e *exitError) Unwrap() error { return e.err }

// codedError is an ExitCode that the builder took: the only one Run reads.
type codedError exitError

func (e *codedError) Error() string { return e.err.Error() }
func (e *codedError) Unwrap() error { return e.err }

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
	// none, and for a run that reads no config.
	ConfigFile string

	// Environ is the environment, for a command that reads the config.
	Environ []string

	// The streams are the builder's: a command returns what it prints, so
	// nothing it writes can break -o json, and the prompt is asked by the
	// builder.
	stdin  io.Reader
	stdout io.Writer
	stderr io.Writer
	// raw is stdout past the rule at the edge (credential.go), for the JSON
	// of a result, which the server sent, and the secret of Spec.Secret.
	raw      io.Writer
	terminal bool
	// program is the name of the program, for a command line in a message.
	program string
	// screen is a stdout that is a terminal; width is its width in cells,
	// 0 when unknown, and colour whether a table is drawn in colour.
	screen bool
	width  int
	colour bool
	// askWidth is the width of stderr's terminal, which a question is
	// written to; 0 when unknown.
	askWidth int
	// answers reads the replies to prompts from stdin; stdinFile is a line
	// that gives - for a Path, so stdin is that file and answers nothing.
	answers   *bufio.Reader
	stdinFile bool
	// discard drops the answers typed and not yet read; nil drops none.
	discard func()
	// local keeps the JSON of the results a Local command made: Answer.
	local map[answerKey]json.RawMessage
	// line is the command line, for the flags the builder adds.
	line *cmdline.Line

	json bool
	now  func() time.Time
	// tree is the tree that runs, for the pages generated from it, and its
	// program.
	tree *Tree
	// api is the session, Ctx.API; server says the line talks to a server.
	api    any
	server bool
	// guard is the guard of the target, which every write on it sends;
	// see revision.
	guard atomic.Pointer[revision]
}

// answerKey is a value: its type, and its value in a canonical encoding.
// The encoding is only a key; it is never printed.
type answerKey struct {
	t reflect.Type
	v string
}

func keyOf(v any) (answerKey, bool) {
	b, err := json.Marshal(v)

	return answerKey{t: reflect.TypeOf(v), v: string(b)}, err == nil
}

// Note writes a line for the human to stderr. With -o json it writes
// nothing: the object takes its place.
func (c *run) Note(line string) {
	if !c.json {
		_, _ = io.WriteString(c.stderr, line+"\n")
	}
}

// Answer makes as the JSON that -o json prints for v, a result that a
// Local command makes as the server would answer it: a type of the client
// writes its keys in another order than the server.
func (c *run) Answer(v, as any) {
	b, err := json.Marshal(as)

	k, ok := keyOf(v)
	if err == nil && ok {
		c.local[k] = b
	}
}

// Stdin is what the command reads, such as a file given as -.
func (c *run) Stdin() io.Reader {
	if c.stdin == nil {
		return strings.NewReader("")
	}

	return c.stdin
}

// ReadFile is the file p, or stdin for -, whole, at most the program's
// MaxFile, and UTF-8 text: every file a command takes is a text, and the
// server reads no other. Its error is a sentence that names the file as typed, and
// stdin as (stdin). Stdin on a terminal says on stderr how to end it.
func (c *run) ReadFile(p Path) ([]byte, error) {
	name := table.Visible(string(p), "")
	if p == "-" {
		name = "(stdin)"
	}

	if p == "-" && c.terminal {
		_, _ = io.WriteString(
			c.stderr,
			"Reading from stdin: end with Ctrl-D at the start of a line.\n",
		)
	}

	r := c.Stdin()

	if p != "-" {
		f, err := os.Open(string(p))

		switch {
		case errors.Is(err, fs.ErrNotExist):
			//nolint:err113,staticcheck // a sentence of the CLI
			return nil, fmt.Errorf("the file %s does not exist.", name)
		case err != nil:
			//nolint:err113,staticcheck // a sentence of the CLI
			return nil, fmt.Errorf(
				"the file %s cannot be read: %s.",
				name,
				CauseOf(err),
			)
		}

		defer f.Close()

		st, err := f.Stat()
		if err == nil && st.IsDir() {
			//nolint:err113,staticcheck // a sentence of the CLI
			return nil, fmt.Errorf("%s is a directory, not a file.", name)
		}

		r = f
	}

	limit := c.tree.prog.MaxFile

	b, err := io.ReadAll(io.LimitReader(r, limit+1))

	switch {
	case err == nil && int64(len(b)) > limit:
		//nolint:err113,staticcheck // a sentence of the CLI
		return nil, fmt.Errorf(
			"%s is larger than %d MiB, more than a command reads.",
			name,
			limit>>20,
		)
	case err != nil:
		//nolint:err113,staticcheck // a sentence of the CLI
		return nil, fmt.Errorf("the file %s cannot be read: %s.", name, CauseOf(err))
	case !utf8.Valid(b):
		//nolint:err113,staticcheck // a sentence of the CLI
		return nil, fmt.Errorf(
			"%s is not UTF-8 text: line %d holds a byte that is not.",
			name,
			notUTF8(b),
		)
	}

	return b, nil
}

// notUTF8 is the line of the first byte of b that is not UTF-8, from 1.
func notUTF8(b []byte) int {
	i := 0
	for i < len(b) {
		r, n := utf8.DecodeRune(b[i:])
		if r == utf8.RuneError && n == 1 {
			break
		}

		i += n
	}

	return 1 + bytes.Count(b[:i], []byte("\n"))
}

// fromStdin reports whether line gives - for an argument or a flag that is
// a Path: stdin is then that file.
func fromStdin(line *cmdline.Line) bool {
	path := reflect.TypeFor[Path]()

	for i, a := range line.Command.Args {
		if i < len(line.Args) && a.Type == path && !a.List && line.Args[i] == "-" {
			return true
		}
	}

	// --config is the builder's, and never reads stdin.
	for _, g := range line.Flags {
		for _, f := range line.Command.Flags {
			if f.Name == g.Name && f.Name != "config" && f.Type == path &&
				g.Value == "-" {
				return true
			}
		}
	}

	return false
}

// Stderr is stderr past no rule but the edge's: a warning written to it is
// read also with -o json, unlike a Note, for what a script must see too.
func (c *run) Stderr() io.Writer { return c.stderr }

// ServerOutput is stdout for the log of a server that a command runs, as
// serve does: past the rule at the edge, since a log is no sentence of the
// CLI, and written while the command runs.
func (c *run) ServerOutput() io.Writer { return c.raw }

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
	// DiscardInput drops what was typed on the terminal and not yet read,
	// before a second question, so that an answer typed ahead does not
	// answer what it never saw; nil drops nothing, as for a pipe, whose
	// script knows what it answers.
	DiscardInput func()
	// StdoutTerminal reports whether stdout is a terminal: an empty list
	// then says so in words, and a table is drawn in colour, unless
	// NO_COLOR is set, and cut to Width.
	StdoutTerminal bool
	// Width is the width of the terminal in cells; 0 cuts nothing.
	Width int
	// StderrWidth is the width of stderr's terminal, which the list under a
	// question is cut to, so a question still fits when stdout is a file.
	StderrWidth int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Context ends a command that runs until it is stopped, such as serve,
	// as a signal does; nil is context.Background(). A test stops it so.
	Context context.Context //nolint:containedctx // the run's own, by design
}

// terminal reports whether f is a terminal; /dev/null is a character
// device and no terminal.
func terminal(f *os.File) bool {
	return term.IsTerminal(int(f.Fd())) //nolint:gosec // a file descriptor fits an int
}

// OSEnv is the Env of the process.
func OSEnv() Env {
	// No terminal, or one that cannot say, is 0, which cuts nothing.
	width := func(f *os.File) int {
		//nolint:gosec // a file descriptor fits an int
		w, _, err := term.GetSize(int(f.Fd()))
		if err != nil {
			return 0
		}

		return w
	}

	var discard func()
	if terminal(os.Stdin) {
		//nolint:gosec // a file descriptor fits an int
		discard = func() { discardInput(int(os.Stdin.Fd())) }
	}

	return Env{
		DiscardInput:   discard,
		Stdin:          os.Stdin,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Environ:        os.Environ(),
		Terminal:       terminal(os.Stdin),
		StdoutTerminal: terminal(os.Stdout),
		Width:          width(os.Stdout),
		StderrWidth:    width(os.Stderr),
	}
}
