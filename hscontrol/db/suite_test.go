package db

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"zombiezen.com/go/postgrestest"
)

// newSQLiteTestDB is a database in a directory of t's, closed when t ends.
func newSQLiteTestDB(t *testing.T) (*HSDatabase, error) {
	t.Helper()

	db, err := NewHeadscaleDatabase(
		&types.Config{
			Database: types.DatabaseConfig{
				Type: types.DatabaseSqlite,
				Sqlite: types.SqliteConfig{
					Path: t.TempDir() + "/headscale_test.db",
					// WAL as in production: a commit then needs no fsync.
					WriteAheadLog: true,
				},
			},
			Policy: types.PolicyConfig{
				Mode: types.PolicyModeDB,
			},
		},
	)
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() { _ = db.Close() })

	return db, nil
}

func newPostgresTestDB(t *testing.T) *HSDatabase {
	t.Helper()

	return newHeadscaleDBFromPostgresURL(t, newPostgresDBForTest(t))
}

// testPostgres is the one PostgreSQL server of the package's tests; each
// test gets a database of its own on it. [TestMain] stops it.
var testPostgres = &pgServer{start: postgrestest.Start}

// pgServer starts a PostgreSQL server for the first caller and hands it to
// every later one. A machine without PostgreSQL's programs stays without
// them; any other failure to start is the caller's, and the next caller
// tries again.
type pgServer struct {
	start func(context.Context) (*postgrestest.Server, error)

	mu      sync.Mutex
	srv     *postgrestest.Server
	missing error
}

func (p *pgServer) get() (*postgrestest.Server, error) {
	p.mu.Lock()
	defer p.mu.Unlock()

	switch {
	case p.srv != nil:
		return p.srv, nil
	case p.missing != nil:
		return nil, p.missing
	}

	// Not a test's context: the server outlives the test that starts it.
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()

	srv, err := p.start(ctx)
	if errors.Is(err, exec.ErrNotFound) {
		p.missing = err
	}

	if err != nil {
		return nil, err
	}

	p.srv = srv

	return srv, nil
}

func (p *pgServer) stop() {
	p.mu.Lock()
	defer p.mu.Unlock()

	if p.srv != nil {
		p.srv.Cleanup()
		p.srv = nil
	}
}

// newPostgresDBForTest is a fresh database on [testPostgres]. Only a machine
// without PostgreSQL skips the test; a server that does not start fails it,
// so a database's half of the tests is never dropped unseen.
func newPostgresDBForTest(t *testing.T) *url.URL {
	t.Helper()

	srv, err := testPostgres.get()

	switch {
	case errors.Is(err, exec.ErrNotFound):
		t.Skipf("no PostgreSQL here: %s", err)
	case err != nil:
		t.Fatalf("start postgres: %s", err)
	}

	u, err := srv.CreateDatabase(t.Context())
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("created local postgres: %s", u)
	pu, _ := url.Parse(u)

	return pu
}

func newHeadscaleDBFromPostgresURL(t *testing.T, pu *url.URL) *HSDatabase {
	t.Helper()

	db, err := NewHeadscaleDatabase(postgresTestConfig(pu))
	if err != nil {
		t.Fatal(err)
	}

	t.Cleanup(func() { _ = db.Close() })

	return db
}

// TestSharedPostgresStart: a failure to start the server is the asking
// test's alone, and the next test starts one; a machine without PostgreSQL's
// programs is asked once.
var errStartOnce = errors.New("initdb: a failure that passes")

func TestSharedPostgresStart(t *testing.T) {
	t.Run("a failed start is tried again", func(t *testing.T) {
		calls := 0
		p := &pgServer{start: func(ctx context.Context) (*postgrestest.Server, error) {
			calls++
			if calls == 1 {
				return nil, errStartOnce
			}

			return postgrestest.Start(ctx)
		}}
		t.Cleanup(p.stop)

		_, err := p.get()
		require.Error(t, err)
		require.NotErrorIs(t, err, exec.ErrNotFound)

		srv, err := p.get()
		if errors.Is(err, exec.ErrNotFound) {
			t.Skipf("no PostgreSQL here: %s", err)
		}

		require.NoError(t, err)
		require.NotNil(t, srv)
		require.Equal(t, 2, calls)
	})

	t.Run("no PostgreSQL is remembered", func(t *testing.T) {
		calls := 0
		p := &pgServer{start: func(context.Context) (*postgrestest.Server, error) {
			calls++

			return nil, fmt.Errorf("start postgres: initdb: %w", &exec.Error{Name: "initdb", Err: exec.ErrNotFound})
		}}

		for range 2 {
			_, err := p.get()
			require.ErrorIs(t, err, exec.ErrNotFound)
		}

		require.Equal(t, 1, calls)
	})
}

// postgresTestConfig is the config of the test database at pu.
func postgresTestConfig(pu *url.URL) *types.Config {
	pass, _ := pu.User.Password()
	port, _ := strconv.Atoi(pu.Port())

	return &types.Config{
		Database: types.DatabaseConfig{
			Type: types.DatabasePostgres,
			Postgres: types.PostgresConfig{
				Host: pu.Hostname(),
				User: pu.User.Username(),
				Name: strings.TrimLeft(pu.Path, "/"),
				Pass: types.Secret(pass),
				Port: port,
				Ssl:  "disable",
			},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
	}
}
