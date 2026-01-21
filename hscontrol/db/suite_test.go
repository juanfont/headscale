package db

import (
	"log"
	"net/url"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog"
	"zombiezen.com/go/postgrestest"
)

func newSQLiteTestDB() (*HSDatabase, error) {
	tmpDir, err := os.MkdirTemp("", "headscale-db-test-*")
	if err != nil {
		return nil, err
	}

	log.Printf("database path: %s", tmpDir+"/headscale_test.db")
	zerolog.SetGlobalLevel(zerolog.Disabled)

	db, err := NewHeadscaleDatabase(
		&types.Config{
			Database: types.DatabaseConfig{
				Type: types.DatabaseSqlite,
				Sqlite: types.SqliteConfig{
					Path: tmpDir + "/headscale_test.db",
				},
			},
			Policy: types.PolicyConfig{
				Mode: types.PolicyModeDB,
			},
		},
		emptyCache(),
	)
	if err != nil {
		return nil, err
	}

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
		t.Fatal(err)
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
					Pass: pass,
					Port: port,
					Ssl:  "disable",
				},
			},
			Policy: types.PolicyConfig{
				Mode: types.PolicyModeDB,
			},
		},
		emptyCache(),
	)
	if err != nil {
		t.Fatal(err)
	}

	return db
}
