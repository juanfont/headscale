package hscontrol_test

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol"
	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tsnet"
	"tailscale.com/types/logger"
)

// tailsqlPolicy is the policy config-example.yaml documents, plus a
// network-only grant for bob.
const tailsqlPolicy = `{
	"tagOwners": { "tag:tailsql": [] },
	"grants": [
		{
			"src": ["alice@"],
			"dst": ["tag:tailsql"],
			"ip":  ["tcp:80", "tcp:443"],
			"app": { "tailscale.com/cap/tailsql": [{ "src": ["headscale"] }] }
		},
		{ "src": ["bob@"], "dst": ["tag:tailsql"], "ip": ["tcp:80"] }
	]
}`

type tailsqlEnv struct {
	srv  *servertest.TestServer
	dial func(ctx context.Context, network, addr string) (net.Conn, error)
	ip   string
}

// startTailSQL runs tailsql on srv's tailnet under tailsqlPolicy and waits
// for its node to register.
func startTailSQL(t *testing.T, srv *servertest.TestServer) *tailsqlEnv {
	t.Helper()

	controlAddr := strings.TrimPrefix(srv.URL, "http://")
	env := &tailsqlEnv{srv: srv}

	env.dial = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr == controlAddr {
			return srv.MemNet().Dial(ctx, network, addr)
		}

		return new(net.Dialer).DialContext(ctx, network, addr)
	}

	changed, err := srv.State().SetPolicy([]byte(tailsqlPolicy))
	require.NoError(t, err)

	if changed {
		changes, err := srv.State().ReloadPolicy()
		require.NoError(t, err)
		srv.App.Change(changes...)
	}

	dbPath := filepath.Join(t.TempDir(), "headscale.db")
	dbURL, err := sqliteconfig.Default(dbPath).ToURL()
	require.NoError(t, err)

	db, err := sql.Open("sqlite", dbURL)
	require.NoError(t, err)

	_, err = db.ExecContext(t.Context(), "CREATE TABLE t (v INTEGER)")
	require.NoError(t, err)
	require.NoError(t, db.Close())

	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Minute)
	t.Cleanup(cancel)

	go func() {
		err := hscontrol.RunTailSQLService(ctx, srv.State(), env.dial, srv.URL, t.TempDir(), dbPath)
		assert.NoError(t, err)
	}()

	require.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, nv := range srv.State().ListNodes().All() {
			if nv.HasTag("tag:tailsql") && nv.IPv4().Valid() {
				env.ip = nv.IPv4().Get().String()
			}
		}

		assert.NotEmpty(c, env.ip)
	}, 30*time.Second, 100*time.Millisecond)

	return env
}

// client joins a node for user and returns an HTTP client on the tailnet.
func (env *tailsqlEnv) client(t *testing.T, name string, user *types.User) *http.Client {
	t.Helper()

	ts := &tsnet.Server{
		Dir:        t.TempDir(),
		Hostname:   name,
		ControlURL: env.srv.URL,
		AuthKey:    env.srv.CreatePreAuthKey(t, types.UserID(user.ID)),
		SystemDial: env.dial,
		Logf:       logger.Discard,
	}
	t.Cleanup(func() { ts.Close() })

	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()

	_, err := ts.Up(ctx)
	require.NoError(t, err)

	hc := ts.HTTPClient()
	hc.Timeout = 5 * time.Second

	return hc
}

// get returns the status code and Location header of a tailsql request.
func (env *tailsqlEnv) get(ctx context.Context, hc *http.Client, path string) (int, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("http://%s%s", env.ip, path), nil)
	if err != nil {
		return 0, "", err
	}

	req.Header.Set("Sec-Tailsql", "1")

	resp, err := hc.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()

	return resp.StatusCode, resp.Header.Get("Location"), nil
}

const tailsqlQueryPath = "/json?src=headscale&q=select+count(*)+from+t"

// TestTailSQLAccess proves the documented policy is accepted and is the only
// way in: the app capability allows a query, network access alone is refused,
// and no grant cannot connect.
func TestTailSQLAccess(t *testing.T) {
	srv := servertest.NewServer(t)
	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	carol := srv.CreateUser(t, "carol")
	env := startTailSQL(t, srv)

	status := func(c *assert.CollectT, hc *http.Client, want int) {
		code, _, err := env.get(t.Context(), hc, tailsqlQueryPath)
		if assert.NoError(c, err) {
			assert.Equal(c, want, code)
		}
	}

	t.Run("app_capability_allows", func(t *testing.T) {
		hc := env.client(t, "alice-laptop", alice)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status(c, hc, http.StatusOK)
		}, 60*time.Second, 500*time.Millisecond)
	})

	t.Run("network_only_is_forbidden", func(t *testing.T) {
		hc := env.client(t, "bob-laptop", bob)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status(c, hc, http.StatusForbidden)
		}, 60*time.Second, 500*time.Millisecond)
	})

	t.Run("no_grant_cannot_connect", func(t *testing.T) {
		hc := env.client(t, "carol-laptop", carol)

		_, _, err := env.get(t.Context(), hc, tailsqlQueryPath)
		assert.Error(t, err)
	})
}

// TestTailSQLHTTPSRedirect proves tailsql moves to HTTPS by itself when
// headscale issues node certificates: port 80 redirects to the cert domain.
// Issuing the certificate needs ACME, so 443 itself is not exercised.
func TestTailSQLHTTPSRedirect(t *testing.T) {
	const domain = "ts.example.com"

	srv := servertest.NewServer(t,
		servertest.WithMagicDNS(domain),
		servertest.WithCertificates(&dnstest.Provider{}),
	)
	alice := srv.CreateUser(t, "alice")
	env := startTailSQL(t, srv)

	hc := env.client(t, "alice-laptop", alice)
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		code, location, err := env.get(t.Context(), hc, tailsqlQueryPath)
		if !assert.NoError(c, err) {
			return
		}

		assert.Equal(c, http.StatusPermanentRedirect, code)
		assert.Equal(c, "https://tailsql."+domain+tailsqlQueryPath, location)
	}, 60*time.Second, 500*time.Millisecond)
}
