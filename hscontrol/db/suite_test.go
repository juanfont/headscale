package db

import (
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
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

func newPostgresDBForTest(t *testing.T) *url.URL {
	t.Helper()

	ctx := t.Context()

	srv, err := postgrestest.Start(ctx)
	if err != nil {
		t.Skipf("start postgres: %s", err)
	}

	t.Cleanup(srv.Cleanup)

	u, err := srv.CreateDatabase(ctx)
	if err != nil {
		t.Fatal(err)
	}

	t.Logf("created local postgres: %s", u)
	pu, _ := url.Parse(u)

	return pu
}

func newHeadscaleDBFromPostgresURL(t *testing.T, pu *url.URL) *HSDatabase {
	t.Helper()

	pass, _ := pu.User.Password()
	port, _ := strconv.Atoi(pu.Port())

	db, err := NewHeadscaleDatabase(
		&types.Config{
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
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return db
}
