// Package command is Headscale's binding of the command library
// cmdline/command: the session its commands call the server with (API),
// the sentences of the server's problems, the lookups of its entities, and
// the program that ties them to the library. The commands themselves are
// package newcli.
package command

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"

	lib "github.com/juanfont/headscale/cmdline/command"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
)

// The library's types, with Headscale's session.
type (
	Ctx                   = lib.Ctx[*API]
	Spec[In, Out any]     = lib.Spec[*API, In, Out]
	ListSpec[In, Row any] = lib.ListSpec[*API, In, Row]

	Node           = lib.Node
	Group          = lib.Group
	Tree           = lib.Tree
	Command        = lib.Command
	NoInput        = lib.NoInput
	NoOutput       = lib.NoOutput
	Opt[T any]     = lib.Opt[T]
	Path           = lib.Path
	OneOf[W Words] = lib.OneOf[W]
	Words          = lib.Words
	Shells         = lib.Shells
)

// New makes the command of a spec.
func New[In, Out any](s Spec[In, Out]) Node { return lib.New(s) }

// NewList makes the command of a list spec.
func NewList[In, Row any](s ListSpec[In, Row]) Node { return lib.NewList(s) }

// Script writes the completion script of shell for program.
func Script(w io.Writer, shell OneOf[Shells], program string) error {
	return lib.Script(w, shell, program)
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
	// Now is the clock; nil is time.Now.
	Now func() time.Time
	// Context is the context of the run; nil is context.Background().
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
		StdoutTerminal: o.StdoutTerminal,
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
		StdoutTerminal: env.StdoutTerminal,
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
		Fields:   flagsOf,

		Entities: []lib.Entity{
			lib.EntityOf(
				"user",
				findUser,
				userCandidates(),
				func(u clientv0.User) string { return u.LoginName },
			),
		},
		Owner: func(ctx context.Context, word string) (string, error) {
			u, err := findUser(ctx, word)

			return u.Id, err
		},

		Aliases:   []string{"ls", "rm", "approve"},
		ConfigEnv: "HEADSCALE_CONFIG",
		Server:    "a running headscale",
	}
}
