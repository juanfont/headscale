package command

import (
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// API is the CLI's client of v0: one method per operation, each returning
// the object of the answer with its own type. A problem comes back as an
// error that the CLI can print as it is.
//
// Every object it decodes keeps the body it came from, for -o json: the
// object as the server sent it, with the fields this build does not know.
// The builder finds that body by the type and the value that Run returns,
// so what it prints is the answer the value came from, two answers of one
// type never mix, and a value that no answer holds is a fault, not a
// re-encoding.
type API struct {
	c *clientv0.Client
	// target is the socket or the host, as messages name it.
	target string
	// answered sees every answer as it came; see Env.Answered.
	answered func(req *http.Request, body []byte)
	// socket is the unix socket; nil for a remote server.
	socket *socket

	mu      sync.Mutex
	answers map[answerKey]json.RawMessage
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

// keep records the body that v was decoded from. Two answers that decode
// to one value can differ only in fields this build does not know; the
// later one is kept.
func (a *API) keep(v any, body json.RawMessage) {
	k, ok := keyOf(v)
	if !ok {
		return
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.answers == nil {
		a.answers = map[answerKey]json.RawMessage{}
	}

	a.answers[k] = body
}

// answerOf is the body that v was decoded from.
func (a *API) answerOf(v any) (json.RawMessage, bool) {
	k, ok := keyOf(v)
	if !ok {
		return nil, false
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	raw, ok := a.answers[k]

	return raw, ok
}

// errNoServer is a Local command that calls the API: a fault of its spec.
var errNoServer = errors.New("this command is Local and has no server to call")

// Me is GET /me.
func (a *API) Me(ctx context.Context) (clientv0.Me, error) {
	return call[clientv0.Me](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetMe(ctx) })
}

// Health is GET /health.
func (a *API) Health(ctx context.Context) (clientv0.Health, error) {
	return call[clientv0.Health](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetHealth(ctx) })
}

// call makes one request and reads its answer: a 2xx body as T, kept for
// -o json; no body (a 204) as the zero T; any other status as a problem.
func call[T any](a *API, do func(*clientv0.Client) (*http.Response, error)) (T, error) {
	var out T

	body, err := a.do(do)
	if err != nil || len(body) == 0 {
		return out, err
	}

	err = json.Unmarshal(body, &out)
	if err != nil {
		return out, a.unreadable(err)
	}

	a.keep(out, body)

	return out, nil
}

// walk reads every page of a list, from the first to the one with no
// nextPageToken; items is the key of the rows in a page. Each row keeps
// its own body, so -o json prints the rows as they came, in the order
// that Run returns them.
func walk[Row any](a *API, items string, page func(c *clientv0.Client, token string) (*http.Response, error)) ([]Row, error) {
	var (
		rows  []Row
		token string
	)

	for {
		body, err := a.do(func(c *clientv0.Client) (*http.Response, error) { return page(c, token) })
		if err != nil {
			return nil, err
		}

		var p map[string]json.RawMessage

		err = json.Unmarshal(body, &p)
		if err != nil {
			return nil, a.unreadable(err)
		}

		var raws []json.RawMessage

		err = json.Unmarshal(p[items], &raws)
		if err != nil {
			return nil, a.unreadable(err)
		}

		for _, raw := range raws {
			var r Row

			err = json.Unmarshal(raw, &r)
			if err != nil {
				return nil, a.unreadable(err)
			}

			a.keep(r, raw)
			rows = append(rows, r)
		}

		next, ok := p["nextPageToken"]
		if !ok {
			return rows, nil
		}

		err = json.Unmarshal(next, &token)
		if err != nil {
			return nil, a.unreadable(err)
		}
	}
}

// do makes one request and returns the body of a 2xx answer, trimmed.
func (a *API) do(do func(*clientv0.Client) (*http.Response, error)) ([]byte, error) {
	if a == nil {
		return nil, errNoServer
	}

	resp, err := do(a.c)
	if err != nil {
		return nil, a.callError(err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, a.callError(err)
	}

	if a.answered != nil {
		a.answered(resp.Request, body)
	}

	if resp.StatusCode/100 != 2 {
		return nil, problemOf(resp.StatusCode, body)
	}

	return bytes.TrimSpace(body), nil
}

func (a *API) unreadable(err error) error {
	return fmt.Errorf("the server at %s sent an answer this CLI cannot read: %w", a.target, err)
}

// callError keeps an error of the version check, which already says what
// to do, and names the server for any other.
func (a *API) callError(err error) error {
	if v, ok := errors.AsType[*versionError](err); ok {
		return v
	}

	// A request that ran out of time while the socket was not there says
	// why the dial failed, not that the time was up.
	if a.socket != nil && errors.Is(err, context.DeadlineExceeded) {
		err = cmp.Or(a.socket.failed(), err)
	}

	return &connectError{target: a.target, err: err}
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
	case errors.Is(e.err, syscall.ENOENT), errors.Is(e.err, syscall.ECONNREFUSED), errors.Is(e.err, context.DeadlineExceeded):
		return head + causeOf(e.err) + "\n" +
			"Is headscale running? To use another server:\n" +
			"  --config <file>, HEADSCALE_UNIX_SOCKET, or HEADSCALE_CLI_ADDRESS"
	}

	return head + causeOf(e.err)
}

// causeOf is the part of a dial or request error that says what was wrong,
// without the operation and the address that the message already names.
func causeOf(err error) string {
	var (
		errno syscall.Errno
		uerr  *url.Error
	)

	switch {
	case errors.As(err, &errno):
		return errno.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	case errors.As(err, &uerr):
		return uerr.Err.Error()
	}

	return err.Error()
}

func (e *connectError) Unwrap() error { return e.err }

var errNoAPIKey = errors.New("a remote server needs an API key: set HEADSCALE_CLI_API_KEY, or cli.api_key in the config")

// connect makes the client for the socket of cfg, or for cli.address with
// the API key, and puts the version check in front of it.
func connect(cfg *types.Config, env Env) (*API, error) {
	var (
		base   http.RoundTripper
		server = "http://headscale"
		target = cfg.UnixSocket
		key    string
	)

	var sock *socket

	if cfg.CLI.Address == "" {
		sock = &socket{path: cfg.UnixSocket}
		base = &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return sock.dial(ctx)
		}}
	} else {
		var err error

		key, err = types.ResolveSecret("cli.api_key", string(cfg.CLI.APIKey))
		if err != nil {
			return nil, err
		}

		if key == "" {
			return nil, errNoAPIKey
		}

		server = cfg.CLI.Address
		if !strings.Contains(server, "://") {
			server = "https://" + server
		}

		// Messages name the host, as the operator knows it.
		target = server

		u, err := url.Parse(server)
		if err == nil && u.Host != "" {
			target = u.Host
		}

		// The operator asks for it with cli.insecure.
		base = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.CLI.Insecure}} //nolint:gosec
	}

	check := &versionCheck{next: base, own: env.Version, target: target, server: server, warn: env.Stderr}

	c, err := clientv0.NewClient(server,
		clientv0.WithHTTPClient(&http.Client{Transport: check}),
		clientv0.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			if key != "" {
				req.Header.Set("Authorization", "Bearer "+key)
			}

			return nil
		}),
	)
	if err != nil {
		return nil, err
	}

	return &API{c: c, target: target, answered: env.Answered, socket: sock}, nil
}

var errNoSocket = errors.New("unix_socket is empty")

// socket is the unix socket of a local server, with the error of the last
// dial that failed.
type socket struct {
	path string

	mu   sync.Mutex
	last error
}

// dial connects to the socket, and tries again until it appears or the
// time of the command is up: a command run right after the server starts
// can come before the socket. A socket the user may not open does not get
// better by waiting.
func (s *socket) dial(ctx context.Context) (net.Conn, error) {
	if s.path == "" {
		return nil, errNoSocket
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 50 * time.Millisecond
	b.MaxInterval = time.Second

	return backoff.Retry(ctx, func() (net.Conn, error) {
		conn, err := util.SocketDialer(ctx, s.path)
		if err != nil {
			s.mu.Lock()
			s.last = err
			s.mu.Unlock()
		}

		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, backoff.Permanent(err)
		}

		return conn, err
	}, backoff.WithBackOff(b))
}

// failed is the error of the last dial that failed; nil for none.
func (s *socket) failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.last
}

// versionCheck compares the Headscale-Version of every answer with the
// CLI's own before a body is read, so no answer of another version is
// decoded. A write that would be the first request of the run asks
// GET /version first, so no write reaches a server of another version and
// no new secret is lost; every command gets this from its method, without
// saying that it writes.
type versionCheck struct {
	next   http.RoundTripper
	own    *types.VersionInfo
	target string
	// server is the base URL, for GET /version.
	server string
	// checked is set once an answer has passed the check.
	checked atomic.Bool
	// warn is stderr, also with -o json, unlike Ctx.Note: the warning says
	// whether what is read can be trusted, so a script must see it too.
	warn   io.Writer
	warned sync.Once
}

func (v *versionCheck) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && !v.checked.Load() {
		first, err := clientv0.NewGetVersionRequest(v.server)
		if err != nil {
			return nil, err
		}

		resp, err := v.RoundTrip(first.WithContext(req.Context()))
		if err != nil {
			return nil, err
		}

		resp.Body.Close()
	}

	resp, err := v.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	server := resp.Header.Get("Headscale-Version")
	if server == "" {
		resp.Body.Close()

		return nil, &versionError{tooOld: resp.StatusCode == http.StatusNotFound, status: resp.Status, target: v.target}
	}

	own, ownCommit := v.own.Version, shortCommit(v.own.Commit)
	serverCommit := resp.Header.Get("Headscale-Commit")

	switch {
	case IsRelease(own) && IsRelease(server):
		if semver.MajorMinor(canonical(own)) != semver.MajorMinor(canonical(server)) {
			resp.Body.Close()

			return nil, &versionError{own: named(own, ownCommit), server: named(server, serverCommit)}
		}
	case ownCommit != "" && serverCommit != "" && ownCommit != serverCommit:
		v.warned.Do(func() {
			fmt.Fprintf(v.warn, "warning: this headscale is %s, the server is %s.\n", named(own, ownCommit), named(server, serverCommit))
		})
	}

	v.checked.Store(true)

	return resp, nil
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

// IsRelease reports whether v is a release number, such as 0.30.1. A build
// from a checkout carries a pseudo-version, and one without version
// information carries dev; neither has a number to compare.
func IsRelease(v string) bool {
	c := canonical(v)

	return semver.IsValid(c) && !module.IsPseudoVersion(c)
}

func canonical(v string) string {
	if !strings.HasPrefix(v, "v") {
		return "v" + v
	}

	return v
}

func shortCommit(c string) string {
	if c == "unknown" {
		return ""
	}

	return c[:min(len(c), 7)]
}

// named is a version as the messages write it, with the commit when the
// build knows it.
func named(version, commit string) string {
	if commit == "" {
		return version
	}

	return version + " (" + commit + ")"
}
