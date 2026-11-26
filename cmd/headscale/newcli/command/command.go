// Package command is Headscale's binding of the command library
// cmdline/command: the session its commands call the server with (API),
// the sentences of the server's problems, the lookups of its entities,
// the delete of a credential, and the program that ties them to the
// library. The commands themselves are package cli.
package command

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"reflect"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmdline"
	lib "github.com/juanfont/headscale/cmdline/command"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
)

// The library's types, with Headscale's session.
type (
	Ctx                   = lib.Ctx[*API]
	Spec[In, Out any]     = lib.Spec[*API, In, Out]
	ListSpec[In, Row any] = lib.ListSpec[*API, In, Row]

	Node            = lib.Node
	Group           = lib.Group
	Tree            = lib.Tree
	Command         = lib.Command
	Prompt          = lib.Prompt
	NoInput         = lib.NoInput
	NoOutput        = lib.NoOutput
	Said            = lib.Said
	Text            = lib.Text
	Opt[T any]      = lib.Opt[T]
	Path            = lib.Path
	OneOf[W Words]  = lib.OneOf[W]
	Words           = lib.Words
	Shells          = lib.Shells
	NowNever        = lib.NowNever
	NoWords         = lib.NoWords
	Expiry[W Words] = lib.Expiry[W]
)

// New makes the command of a spec.
func New[In, Out any](s Spec[In, Out]) Node { return lib.New(s) }

// NewList makes the command of a list spec.
func NewList[In, Row any](s ListSpec[In, Row]) Node { return lib.NewList(s) }

// Failed is lib.Failed: a text printed and a run that fails.
func Failed(err error) error { return lib.Failed(err) }

// ExitCode is lib.ExitCode: err, ending the run with code.
func ExitCode(code int, err error) error { return lib.ExitCode(code, err) }

// Script writes the completion script of shell for program.
func Script(w io.Writer, shell OneOf[Shells], program string) error {
	return lib.Script(w, shell, program)
}

// CreatedNote is lib.CreatedNote: the note of a create before its secret.
func CreatedNote(name, owner, what, word string) string {
	return lib.CreatedNote(name, owner, what, word)
}

// ErrNotRead is what a Run returns when its change is made and the object
// to print cannot be read.
var ErrNotRead = lib.ErrNotRead

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
	// before a second question; nil drops nothing.
	DiscardInput func()
	// StdoutTerminal reports whether stdout is a terminal; Width is its
	// width in cells, 0 cuts nothing; StderrWidth is stderr's.
	StdoutTerminal bool
	Width          int
	StderrWidth    int
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Context ends a command that runs until it is stopped, such as serve,
	// as a signal does; nil is context.Background().
	Context context.Context //nolint:containedctx // the run's own, by design

	// PageSize is the rows of one page of a list walk; 0 is 1000, the most
	// v0 takes. A test sets it small, to walk many pages.
	PageSize int
	// Transport, when set, carries the requests to cli.address, so a test
	// can run the client on the fake clock of testing/synctest.
	Transport http.RoundTripper
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
	o := lib.OSEnv()

	return Env{
		Stdin:          o.Stdin,
		Stdout:         o.Stdout,
		Stderr:         o.Stderr,
		Environ:        o.Environ,
		Terminal:       o.Terminal,
		DiscardInput:   o.DiscardInput,
		StdoutTerminal: o.StdoutTerminal,
		Width:          o.Width,
		StderrWidth:    o.StderrWidth,
	}
}

// envKey carries the Env of a run to its session, in the run's context;
// readsKey what the client read in the run, for -o json.
type (
	envKey   struct{}
	readsKey struct{}
)

// runContext is ctx for the run of env: it carries env to the session, and
// tells every success the client reads in the run to the run's reads.
func runContext(ctx context.Context, env *Env) context.Context {
	r := &reads{}

	return clientv0.WithDecoded(
		context.WithValue(context.WithValue(ctx, envKey{}, env), readsKey{}, r),
		r.decoded,
	)
}

// envOf is the Env of the run of ctx.
func envOf(ctx context.Context) *Env {
	e, _ := ctx.Value(envKey{}).(*Env)
	if e == nil {
		e = &Env{}
	}

	if e.Version == nil {
		e.Version = types.GetVersionInfo()
	}

	return e
}

// Run runs one command line of the tree, argv without the program name,
// and returns the exit code.
func Run(t *Tree, argv []string, env Env) int {
	ctx := env.Context
	if ctx == nil {
		ctx = context.Background()
	}

	return lib.Run(t, argv, lib.Env{
		Stdin:          env.Stdin,
		Stdout:         env.Stdout,
		Stderr:         env.Stderr,
		Environ:        env.Environ,
		Terminal:       env.Terminal,
		DiscardInput:   env.DiscardInput,
		StdoutTerminal: env.StdoutTerminal,
		Width:          env.Width,
		StderrWidth:    env.StderrWidth,
		Now:            env.Now,
		Context:        runContext(ctx, &env),
	})
}

// Build checks every spec and makes the tree of the headscale CLI.
func Build(name, short string, nodes ...Node) (*Tree, error) {
	return lib.Build(program(name, short), nodes...)
}

// program is the headscale CLI as the library sees it.
func program(name, short string) lib.Program[*API] {
	return lib.Program[*API]{
		Name:  name,
		Short: short,
		Version: func(ctx context.Context) string {
			line, _, _ := strings.Cut(envOf(ctx).Version.String(), "\n")

			return line
		},
		Session:  session,
		Error:    func(a *API, err error) error { return a.errorOf(err) },
		Sentence: sentence,
		Answer:   func(a *API, v any) (json.RawMessage, bool) { return a.answerOf(v) },
		Target:   func(a *API) string { return a.target },
		// The server's packages log through zerolog's global logger, which
		// a command does not own: what it says goes past the edge, in the
		// server's words. The command that is the server sets its own log.
		Start: func() { zerolog.SetGlobalLevel(zerolog.Disabled) },

		Refusal:      refusalCode,
		Precondition: string(clientv0.ProblemCodePreconditionFailed),
		Again: func(err error) {
			if p, ok := problemIn(err); ok {
				p.changed = true
			}
		},
		About:     about,
		Fields:    flagsOf,
		MayBeMade: mayBeMade,

		Entities: entities(),
		Readers:  []cmdline.Option{cmdline.LateReader(findOwner)},
		Owner: func(ctx context.Context, word string) (string, error) {
			u, err := findUser(ctx, word)

			return u.Id, err
		},

		Credentials: credentials(),
		OpenFields: map[reflect.Type]string{
			reflect.TypeFor[clientv0.HealthMessage](): "Details",
		},
		Unprintable: map[reflect.Type]error{
			reflect.TypeFor[clientv0.AuthRequest](): errAuthReq,
		},

		Aliases:   []string{"ls", "rm", "approve"},
		ConfigEnv: "HEADSCALE_CONFIG",
		MaxFile:   config.MaxFileSize,
		Server:    "a running headscale",
		Doc: lib.Doc{
			Reference: "headscale generate cli-reference",
			Man:       "headscale generate man",
			Source:    "cmd/headscale",
			SeeAlso:   "https://headscale.net/stable/ref/cli/",
		},
	}
}

// credentials are the credentials of Headscale: hskey-<kind>-, and the
// other spellings the server takes. A key from before 0.28 is 48 hex
// characters with no hskey-: it has no form to tell it from other text,
// and the rule does not see it.
func credentials() lib.Credentials {
	return lib.Credentials{
		Prefix: hskey,
		Kinds:  []string{"auth", "api", "authreq", "client", "oauthtok", "reg"},
		Fronts: types.SecretFronts(),
	}
}

const hskey = "hskey-"
