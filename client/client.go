// Package client builds the generated client of the Headscale API v0
// (gen/client/headscale/v0) with what every caller needs on the way to the
// server: the check that the server is of the caller's version, a time for
// each request, the unix socket of a local server, the refusal of a
// redirect, and errors that say whether a write was sent. Callers then
// call the generated client directly; its paging, Result and strict
// decoding are generated.
package client

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// Options say which server to call, and how.
type Options struct {
	// Address is the base URL of a remote server, such as
	// https://headscale.example.com; with no scheme it is https. "" calls
	// the unix socket Socket.
	Address string
	// Socket is the unix socket of a local server, for an empty Address.
	Socket string
	// APIKey is sent as the bearer token of every request; "" sends none.
	APIKey string
	// Insecure skips the check of a remote server's certificate.
	Insecure bool
	// Transport carries the requests to Address in place of the default.
	Transport http.RoundTripper
	// Timeout bounds each request: the dial, the answer and its body. The
	// time of a walk of a list is the sum of its pages. 0 bounds nothing
	// but the dial of the unix socket, which tries again for at most the
	// default of backoff (15 minutes) while the socket is not there.
	Timeout time.Duration

	// Version and Commit are the caller's build. A server whose release has
	// another major or minor version is refused with a *VersionError; one
	// of another commit is said to Warn, once.
	Version, Commit string
	// Warn hears of a server of another commit, as the version and commit
	// of each side; nil hears nothing.
	Warn func(ownVersion, ownCommit, serverVersion, serverCommit string)

	// Sent, when set, is told every request as it leaves, with its
	// headers: GET /version before a first write, and a request that gets
	// no answer, too.
	Sent func(req *http.Request)
	// Answered, when set, is told the body of every answer the caller
	// reads whole, after the version check; not the answer of the GET
	// /version the client asks before a first write.
	Answered func(resp *http.Response, body []byte)
}

// ErrNoAPIKey is a remote server with no API key to call it with.
var ErrNoAPIKey = errors.New("a remote server needs an API key")

// New is the client of v0 that opts describe. A write that would be the
// first request of the client asks GET /version first, so no write
// reaches a server of another version.
func New(opts Options) (*clientv0.ClientWithResponses, error) {
	var (
		base   = opts.Transport
		server = "http://headscale"
		sock   *socket
	)

	if opts.Address == "" {
		sock = &socket{path: opts.Socket, timeout: opts.Timeout}
		base = &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return sock.dial(ctx)
			},
		}
	} else {
		if opts.APIKey == "" {
			return nil, ErrNoAPIKey
		}

		server = opts.Address
		if !strings.Contains(server, "://") {
			server = "https://" + server
		}

		if base == nil {
			// The caller asks for it with Insecure.
			//nolint:gosec
			base = &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: opts.Insecure},
			}
		}
	}

	if opts.Sent != nil {
		base = told{next: base, sent: opts.Sent}
	}

	// GET /version and the client resolve their paths against the server:
	// without a closing slash the last element of a mount is dropped.
	server = strings.TrimSuffix(server, "/") + "/"

	// Each request gets its own time, GET /version before a first write too.
	var rt http.RoundTripper = &versionCheck{
		next:   each{next: base, timeout: opts.Timeout},
		sock:   sock,
		opts:   opts,
		server: server,
	}

	if opts.Answered != nil {
		rt = answered{next: rt, answered: opts.Answered}
	}

	return clientv0.NewClientWithResponses(server,
		// v0 answers no redirect: versionCheck refuses one before the
		// http.Client could follow it.
		clientv0.WithHTTPClient(&http.Client{Transport: rt}),
		clientv0.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			if opts.APIKey != "" {
				req.Header.Set("Authorization", "Bearer "+opts.APIKey)
			}

			return nil
		}),
	)
}

// VersionError is a server that the caller must not talk to: one of
// another major or minor release, or one that answered without
// Headscale-Version, which is no Headscale with v0.
type VersionError struct {
	OwnVersion, OwnCommit       string
	ServerVersion, ServerCommit string
	// Missing is an answer without Headscale-Version, of Status; TooOld is
	// one that was a 404, as a server with no v0 answers.
	Missing, TooOld bool
	Status          string
}

func (e *VersionError) Error() string {
	if e.Missing {
		return "the server answered " + e.Status + " without Headscale-Version"
	}

	return "this client is " + e.OwnVersion + ", the server is " + e.ServerVersion +
		": the major and minor versions differ"
}

// ProbeError is an error answer to GET /version before a first write,
// which was not sent then.
type ProbeError struct{ Err error }

func (e *ProbeError) Error() string { return "GET /version before a write: " + e.Err.Error() }
func (e *ProbeError) Unwrap() error { return e.Err }

// RedirectError is an answer that points elsewhere, as a proxy answers an
// address it moved. To is the scheme and host it points to, and only
// those: the rest of the Location may hold what was sent; "" for the
// server's own scheme and host, or none.
type RedirectError struct{ To string }

func (e *RedirectError) Error() string {
	if e.To == "" {
		return "the server answered with a redirect"
	}

	return "the server answered with a redirect to " + e.To
}

// RequestError is a request that failed on the way: Sent once the request
// had a connection, so it may have reached the server; Reached when the
// server answered a request of this client before. A Write that was Sent
// may have been made, whatever went wrong after, until its answer is read
// whole. A DryRun asks what a write would do, and does nothing.
type RequestError struct {
	Err           error
	Sent, Reached bool
	Write, DryRun bool
}

func (e *RequestError) Error() string { return e.Err.Error() }
func (e *RequestError) Unwrap() error { return e.Err }

// DialError is a dial of the unix socket that ran out of time: Last is
// why the last try failed.
type DialError struct{ Err, Last error }

func (e *DialError) Error() string   { return e.Last.Error() }
func (e *DialError) Unwrap() []error { return []error{e.Err, e.Last} }

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

// ShortCommit is a commit as a version names it: its first 7 characters;
// "" for "unknown".
func ShortCommit(c string) string {
	if c == "unknown" {
		return ""
	}

	return c[:min(len(c), 7)]
}

// answered tells every answer body, once it is read whole.
type answered struct {
	next     http.RoundTripper
	answered func(resp *http.Response, body []byte)
}

func (a answered) RoundTrip(req *http.Request) (*http.Response, error) {
	resp, err := a.next.RoundTrip(req)
	if err != nil {
		return nil, err
	}

	resp.Body = &recorded{
		ReadCloser: resp.Body,
		done:       func(b []byte) { a.answered(resp, b) },
	}

	return resp, nil
}

// recorded keeps what is read, and tells it at the end of the body.
type recorded struct {
	io.ReadCloser

	buf  []byte
	done func([]byte)
	told bool
}

func (r *recorded) Read(p []byte) (int, error) {
	n, err := r.ReadCloser.Read(p)
	r.buf = append(r.buf, p[:n]...)

	if errors.Is(err, io.EOF) && !r.told {
		r.told = true
		r.done(r.buf)
	}

	return n, err
}
