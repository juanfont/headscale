package client

import (
	"cmp"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/cenkalti/backoff/v5"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"golang.org/x/mod/semver"
)

// each is what every request gets, whichever method made it: the timeout
// bounds the dial, the answer and its body. 0 bounds nothing.
type each struct {
	next    http.RoundTripper
	timeout time.Duration
}

func (t each) RoundTrip(req *http.Request) (*http.Response, error) {
	if t.timeout <= 0 {
		return bodied(t.next.RoundTrip(req))
	}

	ctx, cancel := context.WithTimeout(req.Context(), t.timeout)

	resp, err := bodied(t.next.RoundTrip(req.WithContext(ctx)))
	if err != nil {
		cancel()

		return nil, err
	}

	resp.Body = cancelOnClose{resp.Body, cancel}

	return resp, nil
}

// bodied is an answer with a body to read and close: a transport of the
// caller's may answer a 204 with none, which net/http fills in only for
// its own.
func bodied(resp *http.Response, err error) (*http.Response, error) {
	if err == nil && resp.Body == nil {
		resp.Body = http.NoBody
	}

	return resp, err
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

// told tells sent of every request as it leaves, below the version check
// and any other step: each request, answered or not, with its headers.
type told struct {
	next http.RoundTripper
	sent func(req *http.Request)
}

func (t told) RoundTrip(req *http.Request) (*http.Response, error) {
	t.sent(req)

	return t.next.RoundTrip(req)
}

var errNoSocket = errors.New("the unix socket is empty")

// socket is the unix socket of a local server, with the error of the last
// dial that failed.
type socket struct {
	path string
	// timeout is Options.Timeout: the transport dials apart from the
	// request, so its end does not stop the retries.
	timeout time.Duration

	mu   sync.Mutex
	last error
}

// dial connects to the socket, and tries again until it appears or the
// time is up: a call made right after the server starts can come before
// the socket. A socket the caller may not open does not get better by
// waiting. A dial that ran out of time says why the last try failed.
func (s *socket) dial(ctx context.Context) (net.Conn, error) {
	if s.path == "" {
		return nil, errNoSocket
	}

	b := backoff.NewExponentialBackOff()
	b.InitialInterval = 50 * time.Millisecond
	b.MaxInterval = time.Second

	conn, err := backoff.Retry(ctx, func() (net.Conn, error) {
		var d net.Dialer

		conn, err := d.DialContext(ctx, "unix", s.path)
		if err != nil {
			s.mu.Lock()
			s.last = err
			s.mu.Unlock()
		}

		if errors.Is(err, syscall.EACCES) || errors.Is(err, syscall.EPERM) {
			return nil, backoff.Permanent(err)
		}

		return conn, err
	}, backoff.WithBackOff(b), backoff.WithMaxElapsedTime(cmp.Or(s.timeout, backoff.DefaultMaxElapsedTime)))

	return conn, err
}

// failed is the error of the last dial that failed; nil for none.
func (s *socket) failed() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	return s.last
}

// versionCheck compares the Headscale-Version of every answer with the
// caller's own before a body is read, so no answer of another version is
// decoded. A write that would be the first request asks GET /version
// first, so no write reaches a server of another version and no new
// secret is lost.
type versionCheck struct {
	next http.RoundTripper
	// sock is the unix socket; nil for a remote server.
	sock *socket
	opts Options
	// server is the base URL, for GET /version.
	server string
	// checked is set once an answer has passed the check; succeeded once
	// a success has, which a write waits for.
	checked, succeeded atomic.Bool
	warned             sync.Once
}

func (v *versionCheck) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && !v.succeeded.Load() {
		err := v.probe(req)
		if err != nil {
			return nil, err
		}
	}

	// A dry run asks what a write would do, and does nothing.
	write := req.Method != http.MethodGet && req.URL.Query().Get("dryRun") != "true"
	dryRun := req.Method != http.MethodGet && !write

	// A request may reach the server once a connection is in hand; before
	// that, nothing was sent.
	var sent atomic.Bool

	trace := &httptrace.ClientTrace{
		GotConn: func(httptrace.GotConnInfo) { sent.Store(true) },
	}

	resp, err := v.next.RoundTrip(
		req.WithContext(httptrace.WithClientTrace(req.Context(), trace)),
	)
	if err != nil {
		// A request that ran out of time while the socket was not there
		// says why the dial failed: the transport answers with the time.
		if v.sock != nil && !sent.Load() && errors.Is(err, context.DeadlineExceeded) {
			last := v.sock.failed()
			if last != nil {
				err = &DialError{Err: err, Last: last}
			}
		}

		return nil, &RequestError{
			Err:     err,
			Sent:    sent.Load(),
			Reached: v.checked.Load(),
			Write:   write,
			DryRun:  dryRun,
		}
	}

	// v0 answers no redirect. A client that followed one would send the
	// request again, a secret in its path or its body among it, to wherever
	// the answer points; and a 301 or 302 would turn a write into a read.
	if resp.StatusCode/100 == 3 {
		resp.Body.Close()

		return nil, redirectOf(req.URL, resp)
	}

	// A write was answered: a refusal of its answer leaves the change
	// unknown.
	refuse := func(err error) (*http.Response, error) {
		resp.Body.Close()

		if write {
			return nil, &RequestError{Err: err, Sent: true, Reached: true, Write: true}
		}

		return nil, err
	}

	server := resp.Header.Get("Headscale-Version")
	if server == "" {
		return refuse(&VersionError{
			Missing: true,
			TooOld:  resp.StatusCode == http.StatusNotFound,
			Status:  resp.Status,
		})
	}

	own, ownCommit := v.opts.Version, ShortCommit(v.opts.Commit)
	serverCommit := resp.Header.Get("Headscale-Commit")

	switch {
	case IsRelease(own) && IsRelease(server):
		if semver.MajorMinor(canonical(own)) != semver.MajorMinor(canonical(server)) {
			return refuse(&VersionError{
				OwnVersion:    own,
				OwnCommit:     ownCommit,
				ServerVersion: server,
				ServerCommit:  serverCommit,
			})
		}
	case ownCommit != "" && serverCommit != "" && ownCommit != serverCommit &&
		v.opts.Warn != nil:
		v.warned.Do(func() { v.opts.Warn(own, ownCommit, server, serverCommit) })
	}

	v.checked.Store(true)

	// The probe's own answer is a success only once probe has read it.
	if _, probing := req.Context().Value(probeKey{}).(bool); resp.StatusCode/100 == 2 &&
		!probing {
		v.succeeded.Store(true)
	}

	// The answer is not in until its body is read whole.
	resp.Body = &answerBody{ReadCloser: resp.Body, write: write, dryRun: dryRun}

	return resp, nil
}

// probe asks GET /version before the first write req. A server that does
// not answer it gets no write, nor does one whose success is not the
// answer of GET /version: the error is a *ProbeError.
func (v *versionCheck) probe(req *http.Request) error {
	first, err := clientv0.NewGetVersionRequest(v.server)
	if err != nil {
		return err
	}

	// Headscale needs none, a proxy in front that guards every path does.
	if auth := req.Header.Get("Authorization"); auth != "" {
		first.Header.Set("Authorization", auth)
	}

	//nolint:bodyclose // ParseGetVersionResponse closes it
	resp, err := v.RoundTrip(
		first.WithContext(context.WithValue(req.Context(), probeKey{}, true)),
	)
	if err != nil {
		return err
	}

	got, err := clientv0.ParseGetVersionResponse(resp)
	if err == nil {
		_, err = got.Result()
	}

	if _, ok := errors.AsType[*RequestError](err); ok {
		return err
	}

	if err != nil {
		return &ProbeError{Err: err}
	}

	v.succeeded.Store(true)

	return nil
}

// probeKey marks the request of the probe, whose answer is no success
// until it is read as the answer of GET /version.
type probeKey struct{}

// redirectOf is the error of resp, a redirect of a request to from. A
// Location on the same scheme and host names no other address.
func redirectOf(from *url.URL, resp *http.Response) error {
	to, err := resp.Location()
	if err != nil || to.Host == "" || to.Scheme == from.Scheme && to.Host == from.Host {
		return &RedirectError{}
	}

	return &RedirectError{To: to.Scheme + "://" + to.Host}
}

// answerBody is the body of an answer: an error while it is read is an
// answer that did not come whole.
type answerBody struct {
	io.ReadCloser

	write, dryRun bool
}

func (b *answerBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err != nil && !errors.Is(err, io.EOF) {
		err = &RequestError{
			Err:     err,
			Sent:    true,
			Reached: true,
			Write:   b.write,
			DryRun:  b.dryRun,
		}
	}

	return n, err
}
