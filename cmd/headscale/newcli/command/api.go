package command

import (
	"bytes"
	"cmp"
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
	"github.com/juanfont/headscale/cmdline/table"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/config"
	"github.com/juanfont/headscale/hscontrol/types"
)

// API is the v0 client of a run: the generated client, which a command
// calls directly, with what the run keeps beside it. A command passes the
// guard of a write itself (Ctx.IfMatch, Ctx.Expect) and asks a list with
// PageSize; the builder turns what the client returns into the CLI's
// sentences (errorOf), and prints -o json from the bodies the server sent.
type API struct {
	*clientv0.ClientWithResponses

	// PageSize is the rows of one page of a walk.
	PageSize *int64

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
	// me is GET /me, read once a run. A delete asks its question again
	// after the server refused the write because the target changed, and
	// the warning under the question (OwnWarning) needs who calls each
	// time; who calls does not change within a run, so the second question
	// sends no second GET /me.
	meOnce sync.Once
	me     clientv0.Me
	meErr  error

	// read keeps the bodies of what the client read in this run, for
	// -o json (answerOf).
	read *reads

	mu sync.Mutex
	// requests are the auth requests read in this run; see AuthRequest.
	requests map[AuthID]clientv0.AuthRequest
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

// whoAmI is GET /me, read once a run: see the field me.
func (a *API) whoAmI(ctx context.Context) (clientv0.Me, error) {
	a.meOnce.Do(func() {
		a.me, a.meErr = clientv0.Got(a.GetMeWithResponse(ctx))
		a.meErr = a.errorOf(a.meErr)
	})

	return a.me, a.meErr
}

// AuthRequest is GET /auth-requests/{id}, read once a run: the
// question of a command and its message say the same, and the secret goes
// out once more only for the answer itself.
func (a *API) AuthRequest(
	ctx context.Context,
	id AuthID,
) (clientv0.AuthRequest, error) {
	a.mu.Lock()
	r, ok := a.requests[id]
	a.mu.Unlock()

	if ok {
		return r, nil
	}

	r, err := clientv0.Got(a.GetAuthRequestWithResponse(ctx, string(id)))
	if err != nil {
		return r, a.errorOf(err)
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.requests == nil {
		a.requests = map[AuthID]clientv0.AuthRequest{}
	}

	a.requests[id] = r

	return r, nil
}

// errRestarted is a walk whose token the server refused twice.
//
//nolint:staticcheck // a sentence of the CLI
var errRestarted = errors.New(
	"the server restarted while the list was read. Run the command again.",
)

// errorOf is err, an error of the client, as the CLI says it: a problem
// the server answered, an answer the CLI cannot read, a server that is
// slow, not there, or of another version, a write that may have been
// made. An error that is the CLI's already stays as it is.
func (a *API) errorOf(err error) error {
	if err == nil || a == nil || cliError(err) {
		return err
	}

	_, list := errors.AsType[*clientv0.PageError](err)

	switch {
	case errors.Is(err, clientv0.ErrEmptyPageToken):
		//nolint:err113,staticcheck // a sentence of the CLI
		return fmt.Errorf(
			"the server at %s sent an empty page token. This is a fault of the server.",
			a.target,
		)
	case errors.Is(err, clientv0.ErrRepeatedPageToken):
		//nolint:err113,staticcheck // a sentence of the CLI
		return fmt.Errorf(
			"the server at %s sent a page token it had sent before, so the list would never end. This is a fault of the server.",
			a.target,
		)
	}

	if re, ok := errors.AsType[*clientv0.ResponseError](err); ok {
		if list && re.Problem != nil &&
			re.Problem.Code == clientv0.ProblemCodeInvalidPageToken {
			return errRestarted
		}

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
		v := a.versionOf(ve)
		if sent && re.Write {
			return &writeError{target: a.target, err: v}
		}

		return v
	}

	if r, ok := errors.AsType[*client.RedirectError](err); ok {
		return &redirectError{target: a.target, to: table.Visible(r.To, "")}
	}

	// Any other error is not the client's.
	if re == nil {
		return err
	}

	// A write that was sent may have been made, whatever went wrong after,
	// until its answer is read whole and taken.
	if sent && re.Write {
		return &writeError{target: a.target, err: re.Err}
	}

	deadline := errors.Is(err, context.DeadlineExceeded)

	switch {
	// A server that answered before, or that has the request, is reached:
	// it is slow, or it hung up, not gone.
	case deadline && (sent || re.Reached):
		return &slowError{
			target:  a.target,
			timeout: a.timeout,
			dryRun:  sent && re.DryRun,
			list:    list,
		}
	case sent:
		return &slowError{
			target: a.target,
			cause:  re.Err,
			dryRun: re.DryRun,
			list:   list,
		}
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
		func(err error) bool { _, ok := errors.AsType[*writeError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*slowError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*connectError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*versionError](err); return ok },
		func(err error) bool { _, ok := errors.AsType[*redirectError](err); return ok },
		func(err error) bool { return errors.Is(err, errRestarted) },
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

	if resp.StatusCode/100 == 5 && resp.Request != nil &&
		resp.Request.Method != http.MethodGet {
		return &faultAfterWriteError{err}
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
	// GET /config is the one success that is not JSON: nearly any text
	// reads as YAML, so its type says it.
	case errors.Is(ae.Err, clientv0.ErrContentType):
		why = "it is not YAML"
	case isShape:
		why = se.Why
	case errors.Is(ae.Err, clientv0.ErrPageTokenNotString):
		why = "its nextPageToken is not a string"
	default:
		// The decoder quotes what it could not read, which the server wrote.
		why = table.Visible(ae.Err.Error(), "")
	}

	err := &unreadableError{
		text: "the server at " + a.target + " sent an answer this CLI cannot read: " + why + ".",
	}

	req := resp.Request
	if req != nil && req.Method != http.MethodGet &&
		req.URL.Query().Get("dryRun") != "true" {
		return &writeError{target: a.target, err: err, answered: true}
	}

	return err
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
	// list is a page of a walk; dryRun the dry run of a write, which a
	// person may take for the write.
	list, dryRun bool
}

func (e *slowError) Error() string {
	what := "answer"
	if e.list {
		what = "send the next page of the list"
	}

	again := "Run the command again"
	if e.dryRun {
		again = "Nothing was changed: run the command again"
	}

	if e.cause != nil {
		return "the server at " + e.target + " did not " + what + ": " + command.CauseOf(
			e.cause,
		) + ".\n" + again + "."
	}

	return "the server at " + e.target + " did not " + what + " in " + e.timeout.String() + ".\n" +
		again + ", or wait longer with HEADSCALE_CLI_TIMEOUT or cli.timeout."
}

// writeError is a write that was sent and got no answer: the server may
// have made the change.
type writeError struct {
	target string
	err    error
	// answered is an answer that came and was refused.
	answered bool
}

func (e *writeError) Error() string {
	// An answer that came and was refused says what was wrong with it.
	if _, version := errors.AsType[*versionError](e.err); e.answered || version {
		return e.err.Error() + "\nThe change may have been made: look before you run the command again."
	}

	return "the server at " + e.target + " did not answer the change: " + command.CauseOf(
		e.err,
	) + ".\n" +
		"The change may have been made: look before you run the command again."
}

func (e *writeError) Unwrap() error { return e.err }

// MayBeMade is err with look after it when err is a write whose answer
// was lost or refused: what a person runs to see whether the change was
// made. Any other error is err, as the CLI says it.
func (a *API) MayBeMade(err error, look string) error {
	err = a.errorOf(err)
	if !sentWrite(err) {
		return err
	}

	//nolint:err113 // a sentence of the CLI
	return fmt.Errorf("%s\n%s", sentence(err), look)
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
			status: table.Visible(v.Status, ""),
			target: a.target,
		}
	}

	return &versionError{
		own:    named(v.OwnVersion, v.OwnCommit),
		server: named(v.ServerVersion, v.ServerCommit),
	}
}

// sentWrite reports whether err is a write that went out and whose answer
// was not read, or was refused: it may have been made.
func sentWrite(err error) bool {
	_, ok := errors.AsType[*writeError](err)

	return ok
}

// named is a version as the messages write it, with the commit when the
// build knows it. Both can come from the server's headers.
func named(version, commit string) string {
	version, commit = table.Visible(version, ""), table.Visible(commit, "")
	if commit == "" {
		return version
	}

	return version + " (" + commit + ")"
}

// maxPage is the most rows v0 gives on one page; a walk asks for it, so a
// list of up to 1000 rows is one call.
const maxPage = 1000

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
		Sent:    env.Sent,
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
	a.PageSize = new(int64(cmp.Or(env.PageSize, maxPage)))

	return a, nil
}

// errNoServer is a Local command that calls the API: a fault of its spec.
var errNoServer = errors.New("this command is Local and has no server to call")

// noServer is the client of a Local command: it sends nothing.
type noServer struct{}

func (noServer) Do(*http.Request) (*http.Response, error) { return nil, errNoServer }
