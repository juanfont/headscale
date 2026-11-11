package hscontrol

import (
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	"github.com/juanfont/headscale/hscontrol/db/sqliteconfig"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/tailsql/server/tailsql"
)

// TestTailSQLReadOnly runs what a tailsql user could send through the same
// check and connection tailsql uses: nothing may change the database or
// create a file.
func TestTailSQLReadOnly(t *testing.T) {
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "headscale.db")

	rwURL, err := sqliteconfig.Default(dbPath).ToURL()
	require.NoError(t, err)

	rw, err := sql.Open("sqlite", rwURL)
	require.NoError(t, err)

	defer rw.Close()

	_, err = rw.ExecContext(t.Context(), "CREATE TABLE t (v INTEGER); INSERT INTO t VALUES (1)")
	require.NoError(t, err)

	roURL, err := sqliteconfig.ReadOnly(dbPath).ToURL()
	require.NoError(t, err)

	ro, err := sql.Open("sqlite", roURL)
	require.NoError(t, err)

	defer ro.Close()

	conn, err := ro.Conn(t.Context())
	require.NoError(t, err)

	defer conn.Close()

	attachPath := filepath.Join(dir, "attached.db")
	vacuumPath := filepath.Join(dir, "copy.db")

	writes := []string{
		"INSERT INTO t VALUES (2)",
		"UPDATE t SET v = 3",
		"DELETE FROM t",
		"DROP TABLE t",
		"CREATE TABLE x (a)",
		"pragma query_only = 0",
		"SELECT 1; PRAGMA query_only=0",
		"ATTACH DATABASE 'file:" + attachPath + "?mode=rwc' AS x",
		"attach '" + attachPath + "' as x",
		"VACUUM INTO '" + vacuumPath + "'",
		"DELETE FROM t",
	}
	for _, q := range writes {
		_, err := checkTailSQLQuery(tailsql.Query{Source: "headscale", Query: q})
		if err != nil {
			continue
		}

		_, err = conn.ExecContext(t.Context(), q)
		require.Error(t, err, "%q passed the check and ran on the read-only connection", q)
	}

	var n int

	require.NoError(t, conn.QueryRowContext(t.Context(), "SELECT count(*) FROM t WHERE v = 1").Scan(&n))
	require.Equal(t, 1, n, "table changed")

	for _, p := range []string{attachPath, vacuumPath} {
		_, err := os.Stat(p)
		require.ErrorIs(t, err, os.ErrNotExist, "read-only path created %s", p)
	}

	reads := []string{
		"select * from sqlite_schema",
		"SELECT * FROM pragma_table_info('t')",
	}
	for _, q := range reads {
		_, err := checkTailSQLQuery(tailsql.Query{Source: "headscale", Query: q})
		require.NoError(t, err, q)

		var rows int

		err = conn.QueryRowContext(t.Context(), "SELECT count(*) FROM ("+q+")").Scan(&rows)
		require.NoError(t, err, q)
	}
}
