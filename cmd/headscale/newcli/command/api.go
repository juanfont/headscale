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
	"net/http/httptrace"
	"net/url"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
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
	// pageSize is the rows of one page of a walk.
	pageSize int64
	// check is the version check, which also knows whether the server
	// answered before and whether a write is out; timeout is cli.timeout.
	check   *versionCheck
	timeout time.Duration
	// guard is the guard of the target, which every write on it sends;
	// see revision.
	guard atomic.Pointer[revision]
	// me is GET /me, read once a run: see whoAmI.
	meOnce sync.Once
	me     clientv0.Me
	meErr  error

	mu      sync.Mutex
	answers map[answerKey]json.RawMessage
	// requests are the auth requests read in this run; see GetAuthRequest.
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

// whoAmI is Me, read once a run: a question asked again asks the same.
func (a *API) whoAmI(ctx context.Context) (clientv0.Me, error) {
	a.meOnce.Do(func() { a.me, a.meErr = a.Me(ctx) })

	return a.me, a.meErr
}

// Health is GET /health.
func (a *API) Health(ctx context.Context) (clientv0.Health, error) {
	return call[clientv0.Health](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetHealth(ctx) })
}

// ListUsers is every page of GET /users.
func (a *API) ListUsers(ctx context.Context) ([]clientv0.User, error) {
	return walk[clientv0.User](a, "users", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListUsers(ctx, &clientv0.ListUsersParams{PageSize: &p.size, PageToken: p.token})
	})
}

// CreateUser is POST /users.
func (a *API) CreateUser(ctx context.Context, body clientv0.CreateUserBody) (clientv0.User, error) {
	return call[clientv0.User](a, func(c *clientv0.Client) (*http.Response, error) { return c.CreateUser(ctx, body) })
}

// UpdateUser is PATCH /users/{id}, as a merge patch.
func (a *API) UpdateUser(ctx context.Context, id string, body clientv0.UpdateUserBody) (clientv0.User, error) {
	return call[clientv0.User](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.UpdateUserWithApplicationMergePatchPlusJSONBody(ctx, id, body)
	})
}

// DeleteUser is DELETE /users/{id}: with dryRun what it would remove, and
// otherwise the removal, which sends the token the question showed.
func (a *API) DeleteUser(ctx context.Context, id string, withNodes, dryRun bool) (clientv0.DeletedUser, error) {
	return call[clientv0.DeletedUser](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.DeleteUser(ctx, id, &clientv0.DeleteUserParams{WithNodes: &withNodes, DryRun: &dryRun, Expect: a.expect(id)})
	})
}

// ListNodes is every page of GET /nodes.
func (a *API) ListNodes(ctx context.Context) ([]clientv0.Node, error) {
	return walk[clientv0.Node](a, "nodes", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListNodes(ctx, &clientv0.ListNodesParams{PageSize: &p.size, PageToken: p.token})
	})
}

// GetNode is GET /nodes/{id}.
func (a *API) GetNode(ctx context.Context, id string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetNode(ctx, id) })
}

// UpdateNode is PATCH /nodes/{id}, as a merge patch.
func (a *API) UpdateNode(ctx context.Context, id string, body clientv0.UpdateNodeBody) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.UpdateNodeWithApplicationMergePatchPlusJSONBody(ctx, id, &clientv0.UpdateNodeParams{IfMatch: a.ifMatch(id)}, body)
	})
}

// DeleteNode is DELETE /nodes/{id}.
func (a *API) DeleteNode(ctx context.Context, id string) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.DeleteNode(ctx, id, &clientv0.DeleteNodeParams{IfMatch: a.ifMatch(id)})
	})

	return err
}

// ExpireNode is POST /nodes/{id}/expire.
func (a *API) ExpireNode(ctx context.Context, id string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.ExpireNode(ctx, id, &clientv0.ExpireNodeParams{IfMatch: a.ifMatch(id)})
	})
}

// UpdateNodeClient is POST /nodes/{id}/update-client.
func (a *API) UpdateNodeClient(ctx context.Context, id string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) { return c.UpdateNodeClient(ctx, id) })
}

// SetNodeTags is PUT /nodes/{id}/tags.
func (a *API) SetNodeTags(ctx context.Context, id string, tags []string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.SetNodeTags(ctx, id, &clientv0.SetNodeTagsParams{IfMatch: a.ifMatch(id)}, clientv0.SetNodeTagsBody{Tags: tags})
	})
}

// SetNodeRoutes is PUT /nodes/{id}/routes.
func (a *API) SetNodeRoutes(ctx context.Context, id string, routes []string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.SetNodeRoutes(ctx, id, &clientv0.SetNodeRoutesParams{IfMatch: a.ifMatch(id)}, clientv0.SetNodeRoutesBody{Routes: routes})
	})
}

// ListTags is every page of GET /tags; with a node ID, of the tags that
// node has.
func (a *API) ListTags(ctx context.Context, node string) ([]clientv0.Tag, error) {
	var of *string
	if node != "" {
		of = &node
	}

	return walk[clientv0.Tag](a, "tags", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListTags(ctx, &clientv0.ListTagsParams{PageSize: &p.size, PageToken: p.token, Node: of})
	})
}

// ListAuthKeys is every page of GET /auth-keys, revoked keys included.
func (a *API) ListAuthKeys(ctx context.Context) ([]clientv0.AuthKey, error) {
	return walk[clientv0.AuthKey](a, "authKeys", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListAuthKeys(ctx, &clientv0.ListAuthKeysParams{PageSize: &p.size, PageToken: p.token})
	})
}

// GetAuthKey is GET /auth-keys/{id}.
func (a *API) GetAuthKey(ctx context.Context, id string) (clientv0.AuthKey, error) {
	return call[clientv0.AuthKey](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetAuthKey(ctx, id) })
}

// CreateAuthKey is POST /auth-keys. Its answer is the one that holds the
// secret.
func (a *API) CreateAuthKey(ctx context.Context, body clientv0.CreateAuthKeyBody) (clientv0.CreatedAuthKey, error) {
	return call[clientv0.CreatedAuthKey](a, func(c *clientv0.Client) (*http.Response, error) { return c.CreateAuthKey(ctx, body) })
}

// DeleteAuthKey is DELETE /auth-keys/{id}: it revokes the key.
func (a *API) DeleteAuthKey(ctx context.Context, id string) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) { return c.DeleteAuthKey(ctx, id) })

	return err
}

// ListAPIKeys is every page of GET /api-keys, revoked keys included.
func (a *API) ListAPIKeys(ctx context.Context) ([]clientv0.ApiKey, error) {
	return walk[clientv0.ApiKey](a, "apiKeys", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListApiKeys(ctx, &clientv0.ListApiKeysParams{PageSize: &p.size, PageToken: p.token})
	})
}

// GetAPIKey is GET /api-keys/{id}.
func (a *API) GetAPIKey(ctx context.Context, id string) (clientv0.ApiKey, error) {
	return call[clientv0.ApiKey](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetApiKey(ctx, id) })
}

// CreateAPIKey is POST /api-keys. Its answer is the one that holds the
// secret.
func (a *API) CreateAPIKey(ctx context.Context, body clientv0.CreateApiKeyBody) (clientv0.CreatedApiKey, error) {
	return call[clientv0.CreatedApiKey](a, func(c *clientv0.Client) (*http.Response, error) { return c.CreateApiKey(ctx, body) })
}

// DeleteAPIKey is DELETE /api-keys/{id}: it revokes the key.
func (a *API) DeleteAPIKey(ctx context.Context, id string) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) { return c.DeleteApiKey(ctx, id) })

	return err
}

// ListOAuthClients is every page of GET /oauth-clients, revoked clients
// included.
func (a *API) ListOAuthClients(ctx context.Context) ([]clientv0.OAuthClient, error) {
	return walk[clientv0.OAuthClient](a, "oauthClients", func(c *clientv0.Client, p page) (*http.Response, error) {
		return c.ListOAuthClients(ctx, &clientv0.ListOAuthClientsParams{PageSize: &p.size, PageToken: p.token})
	})
}

// GetOAuthClient is GET /oauth-clients/{id}.
func (a *API) GetOAuthClient(ctx context.Context, id string) (clientv0.OAuthClient, error) {
	return call[clientv0.OAuthClient](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetOAuthClient(ctx, id) })
}

// CreateOAuthClient is POST /oauth-clients. Its answer is the one that
// holds the secret.
func (a *API) CreateOAuthClient(ctx context.Context, body clientv0.CreateOAuthClientBody) (clientv0.CreatedOAuthClient, error) {
	return call[clientv0.CreatedOAuthClient](a, func(c *clientv0.Client) (*http.Response, error) { return c.CreateOAuthClient(ctx, body) })
}

// DeleteOAuthClient is DELETE /oauth-clients/{id}: it revokes the client
// and every token of it.
func (a *API) DeleteOAuthClient(ctx context.Context, id string) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) { return c.DeleteOAuthClient(ctx, id) })

	return err
}

// GetAuthRequest is GET /auth-requests/{id}, read once a run: the
// question of a command and its message say the same, and the secret goes
// out once more only for the answer itself.
func (a *API) GetAuthRequest(ctx context.Context, id AuthID) (clientv0.AuthRequest, error) {
	a.mu.Lock()
	r, ok := a.requests[id]
	a.mu.Unlock()

	if ok {
		return r, nil
	}

	r, err := call[clientv0.AuthRequest](a, func(c *clientv0.Client) (*http.Response, error) { return c.GetAuthRequest(ctx, string(id)) })
	if err != nil {
		return r, err
	}

	a.mu.Lock()
	defer a.mu.Unlock()

	if a.requests == nil {
		a.requests = map[AuthID]clientv0.AuthRequest{}
	}

	a.requests[id] = r

	return r, nil
}

// RegisterAuthRequest is POST /auth-requests/{id}/register: the new node.
func (a *API) RegisterAuthRequest(ctx context.Context, id AuthID, userID string) (clientv0.Node, error) {
	return call[clientv0.Node](a, func(c *clientv0.Client) (*http.Response, error) {
		return c.RegisterAuthRequest(ctx, string(id), clientv0.RegisterAuthRequestBody{UserId: userID})
	})
}

// ApproveAuthRequest is POST /auth-requests/{id}/approve.
func (a *API) ApproveAuthRequest(ctx context.Context, id AuthID) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) { return c.ApproveAuthRequest(ctx, string(id)) })

	return err
}

// RejectAuthRequest is POST /auth-requests/{id}/reject.
func (a *API) RejectAuthRequest(ctx context.Context, id AuthID) error {
	_, err := call[NoOutput](a, func(c *clientv0.Client) (*http.Response, error) { return c.RejectAuthRequest(ctx, string(id)) })

	return err
}

// CreateDebugNode is POST /debug/nodes: a registration of a made-up node,
// waiting under id. Its answer, an auth request, holds id and is not
// returned.
func (a *API) CreateDebugNode(ctx context.Context, id AuthID, hostname string, routes []string) error {
	// routes is required, so none is the empty list, not null.
	body := clientv0.CreateDebugNodeBody{AuthId: string(id), Hostname: hostname, Routes: append([]string{}, routes...)}

	_, err := a.do(func(c *clientv0.Client) (*http.Response, error) { return c.CreateDebugNode(ctx, body) })

	return err
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

// page is the request of one page of a walk: its size, and the token of
// the page before; nil for the first.
type page struct {
	size  int64
	token *string
}

// errRestarted is a walk whose token the server refused twice.
var errRestarted = errors.New("the server restarted while the list was read. Run the command again.") //nolint:staticcheck // a sentence of the CLI

// walk reads every page of a list, from the first to the one with no
// nextPageToken; items is the key of the rows in a page. Each row keeps
// its own body, so -o json prints the rows as they came, in the order
// that Run returns them. A server that refuses a token, as after a
// restart, is walked again from the first page, once.
func walk[Row any](a *API, items string, get func(c *clientv0.Client, p page) (*http.Response, error)) ([]Row, error) {
	refused := func(err error) bool {
		p, ok := errors.AsType[*ProblemError](err)

		return ok && p.Problem.Code == clientv0.ProblemCodeInvalidPageToken
	}

	rows, err := pages[Row](a, items, get)
	if refused(err) {
		rows, err = pages[Row](a, items, get)
	}

	if refused(err) {
		return nil, errRestarted
	}

	return rows, err
}

func pages[Row any](a *API, items string, get func(c *clientv0.Client, p page) (*http.Response, error)) ([]Row, error) {
	var rows []Row

	p := page{size: a.pageSize}
	seen := map[string]bool{}

	for {
		body, err := a.do(func(c *clientv0.Client) (*http.Response, error) { return get(c, p) })
		if s, ok := errors.AsType[*slowError](err); ok {
			s.list = true
		}

		if err != nil {
			return nil, err
		}

		var list map[string]json.RawMessage

		err = json.Unmarshal(body, &list)
		if err != nil {
			return nil, a.unreadable(err)
		}

		var raws []json.RawMessage

		err = json.Unmarshal(list[items], &raws)
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

		next, ok := list["nextPageToken"]
		if !ok {
			return rows, nil
		}

		var token string

		err = json.Unmarshal(next, &token)

		// A walk ends only on a page with no token, so a token that leads
		// nowhere new would ask for ever.
		switch {
		case err != nil:
			return nil, a.unreadable(err)
		case token == "":
			return nil, fmt.Errorf("the server at %s sent an empty page token. This is a fault of the server.", a.target) //nolint:err113,staticcheck // a sentence of the CLI
		case seen[token]:
			return nil, fmt.Errorf("the server at %s sent a page token it had sent before, so the list would never end. This is a fault of the server.", a.target) //nolint:err113,staticcheck // a sentence of the CLI
		}

		seen[token] = true
		p.token = &token
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

	// Headscale-Version is no proof that the answer is the API's: a page in
	// front of the server can carry it. Every answer of v0 but a 204 is JSON,
	// so a call that reads no body cannot take another for success.
	if resp.StatusCode != http.StatusNoContent && !json.Valid(body) {
		return nil, &unreadableError{text: "the server at " + a.target + " sent an answer this CLI cannot read: it is not JSON."}
	}

	return bytes.TrimSpace(body), nil
}

func (a *API) unreadable(err error) error {
	// The decoder quotes what it could not read, which the server wrote.
	return &unreadableError{text: "the server at " + a.target + " sent an answer this CLI cannot read: " + table.Visible(err.Error(), "")}
}

// unreadableError is an answer the CLI cannot read: what the server did is
// not known.
type unreadableError struct{ text string }

func (e *unreadableError) Error() string { return e.text }

// callError keeps an error of the version check, which already says what
// to do, and names the server for any other.
func (a *API) callError(err error) error {
	if v, ok := errors.AsType[*versionError](err); ok {
		return v
	}

	if r, ok := errors.AsType[*redirectError](err); ok {
		return r
	}

	deadline := errors.Is(err, context.DeadlineExceeded)
	u, sent := errors.AsType[*unanswered](err)

	switch {
	// A write that was sent may have been made, whatever went wrong after,
	// until its answer is read whole.
	case sent && u.write:
		return &writeError{target: a.target, err: u.err}
	// A server that answered before, or that has the request, is reached:
	// it is slow, or it hung up, not gone.
	case deadline && (sent || a.check != nil && a.check.checked.Load()):
		return &slowError{target: a.target, timeout: a.timeout, dryRun: sent && u.dryRun}
	case sent:
		return &slowError{target: a.target, cause: u.err, dryRun: u.dryRun}
	// A request that ran out of time while the socket was not there says
	// why the dial failed, not that the time was up.
	case deadline && a.socket != nil:
		err = cmp.Or(a.socket.failed(), err)
	}

	return &connectError{target: a.target, err: err}
}

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
		return "the server at " + e.target + " did not " + what + ": " + causeOf(e.cause) + ".\n" + again + "."
	}

	return "the server at " + e.target + " did not " + what + " in " + e.timeout.String() + ".\n" +
		again + ", or wait longer with HEADSCALE_CLI_TIMEOUT or cli.timeout."
}

// writeError is a write that was sent and got no answer: the server may
// have made the change.
type writeError struct {
	target string
	err    error
}

func (e *writeError) Error() string {
	return "the server at " + e.target + " did not answer the change: " + causeOf(e.err) + ".\n" +
		"The change may have been made: look before you run the command again."
}

func (e *writeError) Unwrap() error { return e.err }

// MayBeMade is err with look after it when err is a write whose answer
// was lost: what a person runs to see whether the change was made. Any
// other error is err.
func MayBeMade(err error, look string) error {
	if _, ok := errors.AsType[*writeError](err); !ok {
		return err
	}

	return fmt.Errorf("%s\n%s", sentence(err), look) //nolint:err113 // a sentence of the CLI
}

// each is what every request of a run gets, whichever method made it:
// cli.timeout bounds the dial, the answer and its body. The time of a
// command is the sum of its requests, so a walk is not cut while its pages
// arrive. A timeout of 0 bounds nothing.
type each struct {
	next    http.RoundTripper
	timeout time.Duration
}

func (t each) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.timeout <= 0 {
		return t.next.RoundTrip(req)
	}

	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)

	resp, err := t.next.RoundTrip(req.WithContext(ctx))
	if err != nil {
		cancel()

		return nil, err
	}

	resp.Body = cancelOnClose{resp.Body, cancel}

	return resp, nil
}

// cancelOnClose ends the time of a request when its body is read.
type cancelOnClose struct {
	io.ReadCloser

	cancel context.CancelFunc
}

func (c cancelOnClose) Close() error {
	defer c.cancel()

	return c.ReadCloser.Close()
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
// without the operation and the address that the message already names. A
// TLS error can quote a name from the server's certificate, so it is made
// visible.
func causeOf(err error) string {
	return table.Visible(cause(err), "")
}

func cause(err error) string {
	var (
		errno syscall.Errno
		uerr  *url.Error
	)

	switch {
	case errors.As(err, &errno):
		return errno.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	// The server, or something on the way, ended the connection.
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "the connection was closed"
	case errors.As(err, &uerr):
		return uerr.Err.Error()
	}

	return err.Error()
}

func (e *connectError) Unwrap() error { return e.err }

// maxPage is the most rows v0 gives on one page; a walk asks for it, so a
// list of up to 1000 rows is one call.
const maxPage = 1000

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

	if env.Sent != nil {
		base = told{next: base, sent: env.Sent}
	}

	check := &versionCheck{next: base, own: env.Version, target: target, server: server, warn: env.Stderr}

	a := &API{}

	c, err := clientv0.NewClient(server,
		clientv0.WithHTTPClient(&http.Client{Transport: each{next: check, timeout: cfg.CLI.Timeout}}),
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

	size := int64(env.PageSize)
	if size == 0 {
		size = maxPage
	}

	a.c, a.target, a.answered, a.socket, a.pageSize, a.check, a.timeout = c, target, env.Answered, sock, size, check, cfg.CLI.Timeout

	return a, nil
}

// told tells sent of every request as it leaves, below the version check
// and any other step, so a test sees what goes over the wire: each request,
// answered or not, with its headers.
type told struct {
	next http.RoundTripper
	sent func(req *http.Request)
}

func (t told) RoundTrip(req *http.Request) (*http.Response, error) {
	t.sent(req)

	return t.next.RoundTrip(req)
}

// revision is the guard of a write on the target of a command: what the
// CLI read or showed of it, which the server compares before it writes,
// so a change made in between is not lost. One kind per run: the target's
// revision, sent in If-Match and refused with precondition_failed, or the
// token a question handed over (Prompt.Guard), sent as expect and refused
// with the spec's Changed. The builder refuses a spec that would need both.
type revision struct {
	id, rev string
	token   bool
}

// ifMatch is the If-Match of a write on the entity id: the revision the
// builder read for the target, when id is the target; nil, which sends
// none, for another. Every call whose operation takes If-Match passes it
// (TestEveryGuardIsSent); a command never does.
func (a *API) ifMatch(id string) *string {
	g := a.guard.Load()
	if g == nil || g.token || g.id != id {
		return nil
	}

	return new(strconv.Quote(g.rev))
}

// expect is the token of a dry run that a write on the entity id sends
// back, so the server refuses it when what the question showed changed:
// the Guard of the Prompt, which the builder keeps as it keeps a revision;
// nil for another entity, and for the dry run itself, which the builder
// asks before any Guard is set. Every call whose operation takes expect
// passes it (TestEveryGuardIsSent).
func (a *API) expect(id string) *string {
	g := a.guard.Load()
	if g == nil || !g.token || g.id != id {
		return nil
	}

	return &g.rev
}

// guardOf is the revision of the target of in: its first argument that is
// an entity, when that entity has an id and a revision. A command does not
// send it itself; the builder sets it before Run, so no write can leave it
// out.
func guardOf[In any](in In) *revision {
	e, ok := target(reflect.ValueOf(in))
	if !ok {
		return nil
	}

	rev := jsonText(e, "revision")
	if rev == "" {
		return nil
	}

	return &revision{id: jsonText(e, "id"), rev: rev}
}

// target is the field of the target in the input struct v, when it holds
// one: see targetType.
func target(v reflect.Value) (reflect.Value, bool) {
	_, i := targetType(v.Type())
	if i < 0 || jsonText(v.Field(i), "id") == "" {
		return reflect.Value{}, false
	}

	return v.Field(i), true
}

// targetType is the type of the target of the input struct t, and its
// field: the first argument that is an entity, a struct with a text id.
func targetType(t reflect.Type) (reflect.Type, int) {
	if t.Kind() != reflect.Struct {
		return nil, -1
	}

	for f := range t.Fields() {
		if f.Tag.Get("arg") != "" && f.Type.Kind() == reflect.Struct && hasJSON(f.Type, "id") {
			return f.Type, f.Index[0]
		}
	}

	return nil, -1
}

// hasJSON reports whether struct t has a text field under the JSON key
// name.
func hasJSON(t reflect.Type, name string) bool {
	for f := range t.Fields() {
		tag, _, _ := strings.Cut(f.Tag.Get("json"), ",")
		if tag == name && f.Type.Kind() == reflect.String {
			return true
		}
	}

	return false
}

// jsonText is the string field of struct v under the JSON key name; "" for
// none.
func jsonText(v reflect.Value, name string) string {
	for i := range v.NumField() {
		tag, _, _ := strings.Cut(v.Type().Field(i).Tag.Get("json"), ",")
		if tag == name && v.Field(i).Kind() == reflect.String {
			return v.Field(i).String()
		}
	}

	return ""
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
// time of the request is up: a command run right after the server starts
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

	// A dry run asks what a write would do, and does nothing.
	write := req.Method != http.MethodGet && req.URL.Query().Get("dryRun") != "true"

	// A request may reach the server once a connection is in hand; before
	// that, nothing was sent.
	var sent atomic.Bool

	trace := &httptrace.ClientTrace{GotConn: func(httptrace.GotConnInfo) { sent.Store(true) }}

	resp, err := v.next.RoundTrip(req.WithContext(httptrace.WithClientTrace(req.Context(), trace)))
	if err != nil {
		if sent.Load() {
			return nil, &unanswered{err: err, write: write, dryRun: req.Method != http.MethodGet && !write}
		}

		return nil, err
	}

	// v0 answers no redirect. A client that followed one would send the
	// request again, a secret in its path or its body among it, to wherever
	// the answer points; and a 301 or 302 would turn a write into a read.
	if resp.StatusCode/100 == 3 {
		resp.Body.Close()

		return nil, redirectOf(v.target, req.URL, resp)
	}

	server := resp.Header.Get("Headscale-Version")
	if server == "" {
		resp.Body.Close()

		return nil, &versionError{tooOld: resp.StatusCode == http.StatusNotFound, status: table.Visible(resp.Status, ""), target: v.target}
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

	// The answer is not in until its body is read whole.
	resp.Body = &answerBody{ReadCloser: resp.Body, write: write, dryRun: req.Method != http.MethodGet && !write}

	return resp, nil
}

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

// redirectOf is the error of resp, a redirect of a request to from. A
// Location on the same scheme and host names no other address.
func redirectOf(target string, from *url.URL, resp *http.Response) error {
	to, err := resp.Location()
	if err != nil || to.Host == "" || to.Scheme == from.Scheme && to.Host == from.Host {
		return &redirectError{target: target}
	}

	return &redirectError{target: target, to: table.Visible(to.Scheme+"://"+to.Host, "")}
}

// unanswered is a request that was sent and whose answer did not come
// whole: a write may have been made, a dry run and a read changed nothing.
type unanswered struct {
	err           error
	write, dryRun bool
}

func (e *unanswered) Error() string { return e.err.Error() }
func (e *unanswered) Unwrap() error { return e.err }

// answerBody is the body of an answer: an error while it is read is an
// answer that did not come whole.
type answerBody struct {
	io.ReadCloser

	write, dryRun bool
}

func (b *answerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = &unanswered{err: err, write: b.write, dryRun: b.dryRun}
	}

	return n, err
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
// build knows it. Both can come from the server's headers.
func named(version, commit string) string {
	version, commit = table.Visible(version, ""), table.Visible(commit, "")
	if commit == "" {
		return version
	}

	return version + " (" + commit + ")"
}
