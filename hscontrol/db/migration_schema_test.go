package db

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/go-gormigrate/gormigrate/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestMigrationsKeepTheirSchema runs the migrations from a released database
// up to each one in turn and holds the schema it leaves to the one pinned in
// testdata/migrations. A committed migration never changes, and neither does
// what it creates: a later column comes by a migration of its own, never by
// editing DDL an older migration shares. HEADSCALE_UPDATE_GOLDEN=1 writes the
// schema of a migration that has none yet, and never rewrites one.
func TestMigrationsKeepTheirSchema(t *testing.T) {
	t.Parallel()

	for _, dialect := range []string{"sqlite", "postgres"} {
		pinned, err := os.ReadDir(filepath.Join("testdata", "migrations", dialect))
		require.NoError(t, err)

		for _, e := range pinned {
			require.True(t, slices.ContainsFunc(migrationList(), func(m *gormigrate.Migration) bool { return m.ID == e.Name() }),
				"testdata/migrations/%s/%s pins a migration the list no longer has", dialect, e.Name())
		}
	}

	t.Run("sqlite", func(t *testing.T) {
		t.Parallel()

		for _, m := range migrationList() {
			path := filepath.Join(t.TempDir(), "headscale.db")
			require.NoError(t, createSQLiteFromSQLFile("testdata/sqlite/headscale_0.29.3_dump.sql", path))

			cfg := types.DatabaseConfig{Type: types.DatabaseSqlite, Sqlite: types.SqliteConfig{Path: path}}
			db, err := openDB(cfg, path)
			require.NoError(t, err)

			holdSchema(t, db, "sqlite", m.ID, `SELECT type || ' ' || name || char(10) || coalesce(sql, '')
				FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type, name`)

			sqlDB, err := db.DB()
			require.NoError(t, err)
			require.NoError(t, sqlDB.Close())
		}
	})

	t.Run("postgres", func(t *testing.T) {
		t.Parallel()

		for _, m := range migrationList() {
			u := newPostgresDBForTest(t)
			restorePostgresFixture(t, u, "testdata/postgres/headscale_0.29.3.pssql",
				`SELECT setval('pre_auth_keys_id_seq', 9)`)

			db, err := openDB(postgresTestConfig(u).Database, "")
			require.NoError(t, err)

			holdSchema(t, db, "postgres", m.ID, `SELECT line FROM (
				SELECT 'column ' || table_name || '.' || column_name || ' ' || data_type ||
					CASE WHEN is_nullable = 'NO' THEN ' not null' ELSE '' END ||
					coalesce(' default ' || column_default, '') AS line
				FROM information_schema.columns WHERE table_schema = 'public'
				UNION ALL
				SELECT 'constraint ' || conrelid::regclass || ' ' || conname || ' ' || pg_get_constraintdef(oid)
				FROM pg_constraint WHERE connamespace = 'public'::regnamespace AND contype <> 'n'
				UNION ALL
				SELECT 'index ' || indexdef FROM pg_indexes WHERE schemaname = 'public'
			) s ORDER BY line`)

			sqlDB, err := db.DB()
			require.NoError(t, err)
			require.NoError(t, sqlDB.Close())
		}
	})
}

// holdSchema migrates db up to id and compares what query reads of its
// schema, one row per line, to testdata/migrations/<dialect>/<id>.
func holdSchema(t *testing.T, db *gorm.DB, dialect, id, query string) {
	t.Helper()

	require.NoError(t, gormigrate.New(db, gormigrate.DefaultOptions, migrationList()).MigrateTo(id), id)

	var rows []string
	require.NoError(t, db.Raw(query).Scan(&rows).Error)

	got := strings.Join(rows, "\n") + "\n"
	golden := filepath.Join("testdata", "migrations", dialect, id)

	want, err := os.ReadFile(golden)
	if errors.Is(err, fs.ErrNotExist) && os.Getenv("HEADSCALE_UPDATE_GOLDEN") == "1" {
		require.NoError(t, os.MkdirAll(filepath.Dir(golden), 0o755))
		require.NoError(t, os.WriteFile(golden, []byte(got), 0o600))

		return
	}

	require.NoError(t, err, "every migration has its schema pinned: run with HEADSCALE_UPDATE_GOLDEN=1 once it is committed")
	require.Equal(t, string(want), got, "migration %s changed what it leaves; add a migration instead", id)
}
