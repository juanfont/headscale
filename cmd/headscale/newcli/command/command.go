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
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"os"
	"reflect"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"github.com/juanfont/headscale/cmdline"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"golang.org/x/term"
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
	// NoJSON is a test tool that prints one fixed format: it takes no
	// --output.
	NoJSON bool
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
	Confirm func(c Ctx, in In) (Prompt, error)
	// Changed is the code with which the server refuses the Guard that
	// Confirm hands over, when what the question showed is no longer true:
	// the builder then asks again and runs once more. A spec with Changed
	// hands over a Guard every time, on a target that is an entity with no
	// revision. A target's revision needs no Changed: precondition_failed
	// refuses it. The builder tries again only a refusal of a guard it
	// stored, never one a command sends itself.
	Changed clientv0.ProblemCode
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
	Run func(c Ctx, in In) (Out, error)
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
	// Only is the filter the list applies unless told otherwise, such as
	// state=valid: the API gives every row, and the list hides the ones a
	// person rarely wants. --all, or a --filter on its column, removes it,
	// and --all adds its column to the default columns. A list with Only
	// takes --all, and its Long says what --all shows.
	Only string
	Run  func(c Ctx, in In) ([]Row, error)
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
// run: the builder hands it to the write on the target (API.expect). It
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
	// local keeps the JSON of a result that a Local command made: Answer.
	local *API
	// entities are the tree's types of target: the retry of a write the
	// server refused because the target changed reads one again by its ID.
	entities map[reflect.Type]entity
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

// Answer makes as the JSON that -o json prints for v, a result that a
// Local command makes as the server would answer it: a type of the client
// writes its keys in another order than the server.
func (c Ctx) Answer(v, as any) {
	b, err := json.Marshal(as)
	if err == nil && c.local != nil {
		c.local.keep(v, b)
	}
}

// Stdin is what the command reads, such as a file given as -.
func (c Ctx) Stdin() io.Reader {
	if c.stdin == nil {
		return strings.NewReader("")
	}

	return c.stdin
}

// maxRead is the most ReadFile reads: more than any file a command takes,
// and an end for a device that never ends, such as /dev/zero.
const maxRead = 16 << 20

// ReadFile is the file p, or stdin for -, whole, at most 16 MiB, and
// UTF-8 text: every file a command takes is a text, and the server reads
// no other. Its error is a sentence that names the file as typed, and
// stdin as (stdin). Stdin on a terminal says on stderr how to end it.
func (c Ctx) ReadFile(p Path) ([]byte, error) {
	name := table.Visible(string(p), "")
	if p == "-" {
		name = "(stdin)"
	}

	if p == "-" && c.terminal {
		_, _ = io.WriteString(c.stderr, "Reading from stdin: end with Ctrl-D at the start of a line.\n")
	}

	r := c.Stdin()

	if p != "-" {
		f, err := os.Open(string(p))

		switch {
		case errors.Is(err, fs.ErrNotExist):
			return nil, fmt.Errorf("the file %s does not exist.", name) //nolint:err113,staticcheck // a sentence of the CLI
		case err != nil:
			return nil, fmt.Errorf("the file %s cannot be read: %s.", name, causeOf(err)) //nolint:err113,staticcheck // a sentence of the CLI
		}

		defer f.Close()

		st, err := f.Stat()
		if err == nil && st.IsDir() {
			return nil, fmt.Errorf("%s is a directory, not a file.", name) //nolint:err113,staticcheck // a sentence of the CLI
		}

		r = f
	}

	b, err := io.ReadAll(io.LimitReader(r, maxRead+1))

	switch {
	case err != nil:
		return nil, fmt.Errorf("the file %s cannot be read: %s.", name, causeOf(err)) //nolint:err113,staticcheck // a sentence of the CLI
	case len(b) > maxRead:
		return nil, fmt.Errorf("%s is larger than 16 MiB, more than a command reads.", name) //nolint:err113,staticcheck // a sentence of the CLI
	case !utf8.Valid(b):
		return nil, fmt.Errorf("%s is not UTF-8 text: line %d holds a byte that is not.", name, notUTF8(b)) //nolint:err113,staticcheck // a sentence of the CLI
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
			if f.Name == g.Name && f.Name != "config" && f.Type == path && g.Value == "-" {
				return true
			}
		}
	}

	return false
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
	// then says so in words, and a table is drawn in colour, unless
	// NO_COLOR is set, and cut to Width.
	StdoutTerminal bool
	// Width is the width of the terminal in cells; 0 cuts nothing.
	Width int
	// StderrWidth is the width of stderr's terminal, which the list under a
	// question is cut to, so a question still fits when stdout is a file.
	StderrWidth int
	// PageSize is the rows of one page of a list walk; 0 is 1000, the most
	// v0 takes. A test sets it small, to walk many pages.
	PageSize int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Answered, when set, is told every answer of the server as it came, so
	// a test compares -o json with what the server sent in that run.
	Answered func(req *http.Request, body []byte)
	// Sent, when set, is told every request as it leaves for the server,
	// before any answer, with its headers: GET /version before a first
	// write, and a request that gets no answer, too.
	Sent func(req *http.Request)
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

	// No terminal, or one that cannot say, is 0, which cuts nothing.
	width := func(f *os.File) int {
		w, _, err := term.GetSize(int(f.Fd())) //nolint:gosec // a file descriptor fits an int
		if err != nil {
			return 0
		}

		return w
	}

	return Env{
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
