package command

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/juanfont/headscale/client"
	"github.com/juanfont/headscale/client/shape"
	"github.com/juanfont/headscale/cmdline/command"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
)

// API is the v0 client of a run: the generated client, which a command
// calls directly, with what the run keeps beside it. The builder turns what
// the client returns into the CLI's sentences (errorOf), and prints -o json
// from the bodies the server sent.
type API struct {
	*clientv0.ClientWithResponses

	// target is the socket or the host, as messages name it.
	target string
	// socket is a run on the unix socket.
	socket  bool
	timeout time.Duration
	// local is the session of a Local command, which has no server.
	local bool
	// build is the version of this binary, as the run sees it; releases
	// lists the release tags of headscale, for the update hint.
	build    *types.VersionInfo
	releases func(ctx context.Context) ([]string, error)

	// read keeps the bodies of what the client read in this run, for
	// -o json (answerOf).
	read *reads
}

// answerKey is a decoded object: its type, and its value in a canonical
// encoding. The encoding is only a key; it is never printed.
type answerKey struct {
	t reflect.Type
	v string
}

func keyOf(v any) (answerKey, bool) {
	b, err := json.Marshal(v)

	return answerKey{t: reflect.TypeOf(v), v: string(b)}, err == nil
}

// reads are the objects the client read in a run, each with the bytes it
// was read from: every success, and every row of the list member of a page.
// It is told them by the generated client (clientv0.WithDecoded).
type reads struct {
	mu   sync.Mutex
	objs map[answerKey]json.RawMessage
}

// decoded keeps raw as the body of v, a pointer to what the client read,
// and each row of a list in it as the body of that row: an item of the
// list is paired with the item of the member of raw that the list was
// read from, by its place. Two answers that read as one value can differ
// only in members this build does not know; the later one is kept.
func (r *reads) decoded(v any, raw []byte) {
	val := reflect.ValueOf(v).Elem()

	r.mu.Lock()
	defer r.mu.Unlock()

	if r.objs == nil {
		r.objs = map[answerKey]json.RawMessage{}
	}

	r.keep(val.Interface(), bytes.TrimSpace(raw))

	if val.Kind() != reflect.Struct {
		return
	}

	var members map[string]json.RawMessage
	if json.Unmarshal(raw, &members) != nil {
		return
	}

	for i := range val.NumField() {
		f, sf := val.Field(i), val.Type().Field(i)
		name, _, _ := strings.Cut(sf.Tag.Get("json"), ",")

		var rows []json.RawMessage
		if f.Kind() != reflect.Slice || f.Type().Elem().Kind() != reflect.Struct ||
			json.Unmarshal(members[name], &rows) != nil || len(rows) != f.Len() {
			continue
		}

		for j, row := range rows {
			r.keep(f.Index(j).Interface(), row)
		}
	}
}

func (r *reads) keep(v any, raw json.RawMessage) {
	if k, ok := keyOf(v); ok {
		r.objs[k] = raw
	}
}

// answerOf is the body that v was read from, whole or as a row of a list,
// so -o json prints it as it came, with the members this build does not
// know.
func (a *API) answerOf(v any) (json.RawMessage, bool) {
	k, ok := keyOf(v)
	if !ok || a.read == nil {
		return nil, false
	}

	a.read.mu.Lock()
	defer a.read.mu.Unlock()

	raw, ok := a.read.objs[k]

	return raw, ok
}

// errorOf is err, an error of the client, as the CLI says it: a problem
// the server answered, an answer the CLI cannot read, a server that is
// slow, not there, or of another version, a write that may have been
// made. An error that is the CLI's already stays as it is.
func (a *API) errorOf(err error) error {
	if err == nil || a == nil || cliError(err) {
		return err
	}

	if re, ok := errors.AsType[*clientv0.ResponseError](err); ok {
		return a.problemOf(re.Response, re.Body)
	}

	if ae, ok := errors.AsType[*clientv0.AnswerError](err); ok {
		return a.unreadable(ae)
	}

	if pe, ok := errors.AsType[*client.ProbeError](err); ok {
		return a.errorOf(pe.Err)
	}

	re, sent := errors.AsType[*client.RequestError](err)
	sent = sent && re.Sent

	if ve, ok := errors.AsType[*client.VersionError](err); ok {
		return a.versionOf(ve)
	}

	if r, ok := errors.AsType[*client.RedirectError](err); ok {
		return &redirectError{target: a.target, to: r.To}
	}

	// Any other error is not the client's.
	if re == nil {
		return err
	}

	deadline := errors.Is(err, context.DeadlineExceeded)

	switch {
	// A server that answered before, or that has the request, is reached:
	// it is slow, or it hung up, not gone.
	case deadline && (sent || re.Reached):
		return &slowError{target: a.target, timeout: a.timeout}
	case sent:
		return &slowError{target: a.target, cause: re.Err}
	}

	// A request that ran out of time while the socket was not there says
	// why the dial failed, not that the time was up.
	if de, ok := errors.AsType[*client.DialError](err); ok && deadline && a.socket {
		return &connectError{target: a.target, err: de.Last}
	}

	return &connectError{target: a.target, err: err}
}

// cliError reports whether err is already one of the CLI's sentences.
func cliError(err error) bool {
	for _, is := range []func(error) bool{
		func(err error) bool { _, ok := errors.AsType[*ProblemError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*unreadableError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*slowError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*connectError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*versionError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*redirectError](err); return ok },
	} {
		if is(err) {
			return true
		}
	}

	return false
}

// problemOf is an answer that is not a success: the problem it holds, or
// its status. A server fault that answered a write may come after the
// change.
func (a *API) problemOf(resp *http.Response, body []byte) error {
	var (
		p   clientv0.Problem
		err error
	)

	if clientv0.DecodeResponse(body, &p) != nil || p.Code == "" {
		//nolint:err113 // a status, not a condition to test
		err = fmt.Errorf(
			"the server answered %d %s",
			resp.StatusCode,
			http.StatusText(resp.StatusCode),
		)
	} else {
		err = &ProblemError{Problem: p}
	}

	return err
}

// unreadable is an answer the client cannot read, as the CLI says it. A
// status that is not a success is the problem it holds, or its status; a
// success says why it was refused. The answer of a write came, so the
// change may have been made.
func (a *API) unreadable(ae *clientv0.AnswerError) error {
	resp := ae.Response
	if resp.StatusCode/100 != 2 {
		return a.problemOf(resp, ae.Body)
	}

	var why string

	se, isShape := errors.AsType[*shape.Error](ae.Err)

	switch {
	case errors.Is(ae.Err, clientv0.ErrStatus):
		names := make([]string, len(ae.Want))
		for i, s := range ae.Want {
			names[i] = statusText(s)
		}

		why = "it is " + statusText(resp.StatusCode) + ", not the " +
			strings.Join(names, " or ") + " this operation answers"
	case isShape:
		why = se.Why
	default:
		why = ae.Err.Error()
	}

	return &unreadableError{
		text: "the server at " + a.target + " sent an answer this CLI cannot read: " + why + ".",
	}
}

// statusText is a status as a sentence names it: 204 No Content.
func statusText(status int) string {
	return strings.TrimSpace(strconv.Itoa(status) + " " + http.StatusText(status))
}

// unreadableError is an answer the CLI cannot read: what the server did is
// not known.
type unreadableError struct{ text string }

func (e *unreadableError) Error() string { return e.text }

// slowError is a server that was reached and did not answer a request
// that changes nothing: not in time, or, with a cause, not whole.
type slowError struct {
	target  string
	timeout time.Duration
	cause   error
}

func (e *slowError) Error() string {
	what := "answer"

	again := "Run the command again"

	if e.cause != nil {
		return "the server at " + e.target + " did not " + what + ": " + command.CauseOf(
			e.cause,
		) + ".\n" + again + "."
	}

	return "the server at " + e.target + " did not " + what + " in " + e.timeout.String() + ".\n" +
		again + ", or wait longer with HEADSCALE_CLI_TIMEOUT or cli.timeout."
}

// connectError is a server that cannot be reached, with what was wrong.
type connectError struct {
	target string
	err    error
}

func (e *connectError) Error() string {
	head := "cannot connect to " + e.target + ": "

	switch {
	case errors.Is(e.err, syscall.EACCES), errors.Is(e.err, syscall.EPERM):
		return head + "permission denied.\nRun it as a user that may open the socket, or use HEADSCALE_CLI_ADDRESS."
	case errors.Is(e.err, syscall.ENOENT),
		errors.Is(e.err, syscall.ECONNREFUSED),
		errors.Is(e.err, context.DeadlineExceeded):
		return head + command.CauseOf(e.err) + "\n" +
			"Is headscale running? To use another server:\n" +
			"  --config <file>, HEADSCALE_UNIX_SOCKET, or HEADSCALE_CLI_ADDRESS"
	}

	return head + command.CauseOf(e.err)
}

func (e *connectError) Unwrap() error { return e.err }

// redirectError is an answer that points elsewhere, as a proxy answers an
// address it moved. It names where by scheme and host only: the rest of the
// Location may hold what was sent.
type redirectError struct{ target, to string }

func (e *redirectError) Error() string {
	if e.to == "" {
		return "the server at " + e.target + " answered with a redirect, which this CLI does not follow."
	}

	return "the server at " + e.target + " answered with a redirect to " + e.to + ", which this CLI does not follow.\n" +
		"If that is the server, set it as the address: HEADSCALE_CLI_ADDRESS, or cli.address in the config."
}

// versionError is a server that this CLI must not talk to.
type versionError struct {
	own, server string
	// A server with no v0 answers without the header.
	tooOld bool
	status string
	target string
}

func (e *versionError) Error() string {
	switch {
	case e.tooOld:
		return "the server at " + e.target + " is too old for this CLI.\nIt has no /api/headscale/v0."
	case e.own == "":
		return "the server at " + e.target + " answered " + e.status + " without Headscale-Version.\nIs it headscale?"
	}

	return "this headscale is " + e.own + ", the server is " + e.server + ".\n" +
		"The CLI and the server must have the same major and minor version.\n" +
		"If you just upgraded, restart the server."
}

func (a *API) versionOf(v *client.VersionError) *versionError {
	if v.Missing {
		return &versionError{
			tooOld: v.TooOld,
			status: v.Status,
			target: a.target,
		}
	}

	return &versionError{
		own:    named(v.OwnVersion, v.OwnCommit),
		server: named(v.ServerVersion, v.ServerCommit),
	}
}

// named is a version as the messages write it, with the commit when the
// build knows it. Both can come from the server's headers.
func named(version, commit string) string {
	if commit == "" {
		return version
	}

	return version + " (" + commit + ")"
}

var errNoAPIKey = errors.New(
	"a remote server needs an API key: set HEADSCALE_CLI_API_KEY, or cli.api_key in the config",
)

// session is the API of a run: for a line that talks to the server, a
// client of the server the config names; for a Local command, the build
// and its releases alone. cli.timeout bounds each request, not the whole
// command: a walk of many pages, then a write, may take longer than one
// wait.
func session(c Ctx, server bool) (*API, error) {
	env := envOf(c)

	if !server {
		// A Local command that calls all the same is a fault of its spec,
		// which every call says.
		none, err := clientv0.NewClientWithResponses(
			"http://headscale",
			clientv0.WithHTTPClient(noServer{}),
		)

		return &API{
			ClientWithResponses: none,
			local:               true,
			build:               env.Version,
			releases:            env.Releases,
		}, err
	}

	cfg, err := loadConfig(c.ConfigFile, c.Environ)
	if err != nil {
		return nil, err
	}

	a, err := connect(cfg, *env, c.Stderr())
	if err == nil {
		a.read, _ = c.Value(readsKey{}).(*reads)
	}

	return a, err
}

// loadConfig loads what the CLI needs to reach the server. A missing file
// is normal: the defaults and the environment are enough, and no warning
// is printed, because a server command prints no log line.
func loadConfig(file string, environ []string) (*types.Config, error) {
	l, err := config.Load(file, file != "", environ)
	switch {
	case err != nil && l.File != "":
		return nil, fmt.Errorf("the config file %s cannot be read: %w", l.File, err)
	case err != nil:
		return nil, fmt.Errorf("the configuration cannot be read: %w", err)
	}

	return l.Config, nil
}

// Build is the version of this binary, as the run sees it.
func (a *API) Build() *types.VersionInfo { return a.build }

// Releases lists the release tags of headscale, for the update hint; none
// when the run has no source of them.
func (a *API) Releases(ctx context.Context) ([]string, error) {
	if a.releases == nil {
		return nil, nil
	}

	return a.releases(ctx)
}

// connect makes the client for the socket of cfg, or for cli.address with
// the API key. stderr is the run's: the warning of a server of another
// commit is written to it, also with -o json, unlike Ctx.Note: it says
// whether what is read can be trusted, so a script must see it too.
func connect(cfg *types.Config, env Env, stderr io.Writer) (*API, error) {
	a := &API{
		target:   cfg.UnixSocket,
		timeout:  cfg.CLI.Timeout,
		build:    env.Version,
		releases: env.Releases,
	}

	opts := client.Options{
		Socket:  cfg.UnixSocket,
		Timeout: cfg.CLI.Timeout,
		Version: env.Version.Version,
		Commit:  env.Version.Commit,
		Warn: func(ownVersion, ownCommit, serverVersion, serverCommit string) {
			fmt.Fprintf(
				stderr,
				"warning: this headscale is %s, the server is %s.\n",
				named(ownVersion, ownCommit),
				named(serverVersion, serverCommit),
			)
		},
	}

	if env.Answered != nil {
		opts.Answered = func(resp *http.Response, body []byte) {
			env.Answered(resp.Request, body)
		}
	}

	a.socket = cfg.CLI.Address == ""

	if !a.socket {
		key, err := types.ResolveSecret("cli.api_key", string(cfg.CLI.APIKey))
		if err != nil {
			return nil, err
		}

		if key == "" {
			return nil, errNoAPIKey
		}

		opts.Address, opts.APIKey, opts.Insecure = cfg.CLI.Address, key, cfg.CLI.Insecure
		opts.Transport = env.Transport

		// Messages name the host, as the operator knows it.
		server := cfg.CLI.Address
		if !strings.Contains(server, "://") {
			server = "https://" + server
		}

		a.target = server

		u, err := url.Parse(server)
		if err == nil && u.Host != "" {
			a.target = u.Host
		}
	}

	c, err := client.New(opts)
	if err != nil {
		return nil, err
	}

	a.ClientWithResponses = c

	return a, nil
}

// errNoServer is a Local command that calls the API: a fault of its spec.
var errNoServer = errors.New("this command is Local and has no server to call")

// noServer is the client of a Local command: it sends nothing.
type noServer struct{}

func (noServer) Do(*http.Request) (*http.Response, error) { return nil, errNoServer }
