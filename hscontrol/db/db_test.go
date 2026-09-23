package db

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestSQLiteMigrationAndDataValidation tests specific SQLite migration scenarios
// and validates data integrity after migration. All migrations that require data validation
// should be added here.
func TestSQLiteMigrationAndDataValidation(t *testing.T) {
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
	}{
		// Test for the null-tags user_id recovery migration. Databases that
		// already upgraded to 0.29.0 had user_id wrongly cleared on untagged
		// nodes with tags='null'. The recovery migration re-derives user_id
		// from the node's pre-auth key where one exists.
		// Fixes: https://github.com/juanfont/headscale/issues/3323
		{
			dbPath: "testdata/sqlite/recover_null_tags_user_id_migration_test.sql",
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()

				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				require.Len(t, nodes, 4, "should have all 4 nodes")

				byHostname := make(map[string]*types.Node, len(nodes))
				for _, n := range nodes {
					byHostname[n.Hostname] = n
				}

				// Node 1: authkey-registered, orphaned by the bug. The recovery
				// migration restores user_id from its pre-auth key (user2).
				node1 := byHostname["node1"]
				require.NotNil(t, node1, "node1 should exist")
				require.NotNil(t, node1.UserID, "node1 user_id should be recovered")
				assert.Equal(t, uint(2), *node1.UserID, "node1 should be recovered to user2")

				// Node 2: genuinely tagged, correctly cleared. Must stay cleared.
				node2 := byHostname["node2"]
				require.NotNil(t, node2, "node2 should exist")
				assert.True(t, node2.IsTagged(), "node2 should be tagged")
				assert.Nil(t, node2.UserID, "node2 (tagged) must remain cleared")

				// Node 3: CLI-registered, no pre-auth key. Unrecoverable.
				node3 := byHostname["node3"]
				require.NotNil(t, node3, "node3 should exist")
				assert.Nil(t, node3.UserID, "node3 has no pre-auth key to recover from")

				// Node 4: never orphaned; user_id must be untouched.
				node4 := byHostname["node4"]
				require.NotNil(t, node4, "node4 should exist")
				require.NotNil(t, node4.UserID, "node4 user_id should be untouched")
				assert.Equal(t, uint(1), *node4.UserID, "node4 should still belong to user1")
			},
		},
		// Test for the clear-tagged-node-expiry migration
		// (202607241200-clear-tagged-node-expiry). A buggy handleLogout stamped
		// a key expiry on tagged nodes, which never expire (KB 1068), leaving
		// them permanently Expired. The migration clears expiry on tagged rows
		// only, preserving user-owned nodes' expiry.
		// Fixes: https://github.com/juanfont/headscale/issues/3371
		{
			dbPath: "testdata/sqlite/clear_tagged_node_expiry_migration_test.sql",
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()

				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				require.Len(t, nodes, 5, "should have all 5 nodes")

				byHostname := make(map[string]*types.Node, len(nodes))
				for _, n := range nodes {
					byHostname[n.Hostname] = n
				}

				// Node 1: tagged with a stale PAST expiry (the bug). Cleared.
				node1 := byHostname["node1"]
				require.NotNil(t, node1, "node1 should exist")
				assert.True(t, node1.IsTagged(), "node1 should be tagged")
				assert.Nil(t, node1.Expiry, "node1 (tagged) stale expiry should be cleared")
				assert.False(t, node1.IsExpired(), "node1 must not be reported expired")

				// Node 2: tagged with a FUTURE expiry. Tagged nodes never expire,
				// so this is cleared too.
				node2 := byHostname["node2"]
				require.NotNil(t, node2, "node2 should exist")
				assert.True(t, node2.IsTagged(), "node2 should be tagged")
				assert.Nil(t, node2.Expiry, "node2 (tagged) expiry should be cleared")

				// Node 3: tagged, expiry already NULL. Stays NULL.
				node3 := byHostname["node3"]
				require.NotNil(t, node3, "node3 should exist")
				assert.True(t, node3.IsTagged(), "node3 should be tagged")
				assert.Nil(t, node3.Expiry, "node3 (tagged) NULL expiry should be preserved")

				// Node 4: untagged (tags='null') with a PAST expiry. PRESERVED —
				// the migration must not touch user-owned nodes.
				node4 := byHostname["node4"]
				require.NotNil(t, node4, "node4 should exist")
				assert.False(t, node4.IsTagged(), "node4 (tags='null') should be untagged")
				require.NotNil(t, node4.Expiry, "node4 (user-owned) expiry must be preserved")
				assert.Equal(t, 2020, node4.Expiry.UTC().Year(), "node4 past expiry preserved")

				// Node 5: untagged (tags='[]') with a FUTURE expiry. PRESERVED.
				node5 := byHostname["node5"]
				require.NotNil(t, node5, "node5 should exist")
				assert.False(t, node5.IsTagged(), "node5 (tags='[]') should be untagged")
				require.NotNil(t, node5.Expiry, "node5 (user-owned) expiry must be preserved")
				assert.Equal(t, 2099, node5.Expiry.UTC().Year(), "node5 future expiry preserved")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dbPath, func(t *testing.T) {
			if !strings.HasSuffix(tt.dbPath, ".sql") {
				t.Fatalf("TestSQLiteMigrationAndDataValidation only supports .sql files, got: %s", tt.dbPath)
			}

			hsdb := dbForTestWithPath(t, tt.dbPath)
			if tt.wantFunc != nil {
				tt.wantFunc(t, hsdb)
			}
		})
	}
}

func createSQLiteFromSQLFile(sqlFilePath, dbPath string) error {
	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		return err
	}
	defer db.Close()

	schemaContent, err := os.ReadFile(sqlFilePath)
	if err != nil {
		return err
	}

	_, err = db.ExecContext(context.Background(), string(schemaContent))

	return err
}

// requireConstraintFailed checks if the error is a constraint failure with
// either SQLite and PostgreSQL error messages.
func requireConstraintFailed(t *testing.T, err error) {
	t.Helper()
	require.Error(t, err)

	if !strings.Contains(err.Error(), "UNIQUE constraint failed:") && !strings.Contains(err.Error(), "violates unique constraint") {
		require.Failf(t, "expected error to contain a constraint failure, got: %s", err.Error())
	}
}

func TestConstraints(t *testing.T) {
	tests := []struct {
		name string
		run  func(*testing.T, *gorm.DB)
	}{
		{
			name: "no-duplicate-username-if-no-oidc",
			run: func(t *testing.T, db *gorm.DB) { //nolint:thelper
				_, err := CreateUser(db, types.User{Name: "user1"})
				require.NoError(t, err)
				_, err = CreateUser(db, types.User{Name: "user1"})
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "no-oidc-duplicate-username-and-id",
			run: func(t *testing.T, db *gorm.DB) { //nolint:thelper
				user := types.User{
					ID:   1,
					Name: "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err := db.Save(&user).Error
				require.NoError(t, err)

				user = types.User{
					ID:   2,
					Name: "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err = db.Save(&user).Error
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "no-oidc-duplicate-id",
			run: func(t *testing.T, db *gorm.DB) { //nolint:thelper
				user := types.User{
					ID:   1,
					Name: "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err := db.Save(&user).Error
				require.NoError(t, err)

				user = types.User{
					ID:   2,
					Name: "user1.1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err = db.Save(&user).Error
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "allow-duplicate-username-cli-then-oidc",
			run: func(t *testing.T, db *gorm.DB) { //nolint:thelper
				_, err := CreateUser(db, types.User{Name: "user1"}) // Create CLI username
				require.NoError(t, err)

				user := types.User{
					Name:               "user1",
					ProviderIdentifier: sql.NullString{String: "http://test.com/user1", Valid: true},
				}

				err = db.Save(&user).Error
				require.NoError(t, err)
			},
		},
		{
			name: "allow-duplicate-username-oidc-then-cli",
			run: func(t *testing.T, db *gorm.DB) { //nolint:thelper
				user := types.User{
					Name:               "user1",
					ProviderIdentifier: sql.NullString{String: "http://test.com/user1", Valid: true},
				}

				err := db.Save(&user).Error
				require.NoError(t, err)

				_, err = CreateUser(db, types.User{Name: "user1"}) // Create CLI username
				require.NoError(t, err)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name+"-postgres", func(t *testing.T) {
			db := newPostgresTestDB(t)
			tt.run(t, db.DB.Debug())
		})
		t.Run(tt.name+"-sqlite", func(t *testing.T) {
			db, err := newSQLiteTestDB()
			if err != nil {
				t.Fatalf("creating database: %s", err)
			}

			tt.run(t, db.DB.Debug())
		})
	}
}

// TestPostgresMigrationAndDataValidation tests specific PostgreSQL migration scenarios
// and validates data integrity after migration. All migrations that require data validation
// should be added here.
//
// TODO(kradalby): Convert to use plain text SQL dumps instead of binary .pssql dumps for consistency
// with SQLite tests and easier version control.
func TestPostgresMigrationAndDataValidation(t *testing.T) {
	tests := []struct {
		name     string
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
	}{}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := newPostgresDBForTest(t)

			pgRestorePath, err := exec.LookPath("pg_restore")
			if err != nil {
				t.Fatal("pg_restore not found in PATH. Please install it and ensure it is accessible.")
			}

			// Construct the pg_restore command
			cmd := exec.CommandContext(context.Background(), pgRestorePath, "--verbose", "--if-exists", "--clean", "--no-owner", "--dbname", u.String(), tt.dbPath)

			// Set the output streams
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			// Execute the command
			err = cmd.Run()
			if err != nil {
				t.Fatalf("failed to restore postgres database: %s", err)
			}

			db := newHeadscaleDBFromPostgresURL(t, u)

			if tt.wantFunc != nil {
				tt.wantFunc(t, db)
			}
		})
	}
}

func dbForTest(t *testing.T) *HSDatabase {
	t.Helper()
	return dbForTestWithPath(t, "")
}

func dbForTestWithPath(t *testing.T, sqlFilePath string) *HSDatabase {
	t.Helper()

	dbPath := t.TempDir() + "/headscale_test.db"

	// If SQL file path provided, validate and create database from it
	if sqlFilePath != "" {
		// Validate that the file is a SQL text file
		if !strings.HasSuffix(sqlFilePath, ".sql") {
			t.Fatalf("dbForTestWithPath only accepts .sql files, got: %s", sqlFilePath)
		}

		err := createSQLiteFromSQLFile(sqlFilePath, dbPath)
		if err != nil {
			t.Fatalf("setting up database from SQL file %s: %s", sqlFilePath, err)
		}
	}

	db, err := NewHeadscaleDatabase(
		&types.Config{
			Database: types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: dbPath,
				},
			},
			Policy: types.PolicyConfig{
				Mode: types.PolicyModeDB,
			},
		},
	)
	if err != nil {
		t.Fatalf("setting up database: %s", err)
	}

	if sqlFilePath != "" {
		t.Logf("database set up from %s at: %s", sqlFilePath, dbPath)
	} else {
		t.Logf("database set up at: %s", dbPath)
	}

	return db
}

// TestSQLiteRejectsPre029Database ensures a real pre-0.29 database is refused
// rather than silently skipping the migrations that were removed.
func TestSQLiteRejectsPre029Database(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	err := createSQLiteFromSQLFile("testdata/sqlite_too_old/headscale_0.26.1_dump.sql", dbPath)
	require.NoError(t, err)

	_, err = NewHeadscaleDatabase(&types.Config{
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: dbPath},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	})
	require.ErrorIs(t, err, errDatabaseTooOld)
}

// TestSQLiteAllTestdataMigrations tests migration compatibility across all SQLite schemas
// in the testdata directory. It verifies they can be successfully migrated to the current
// schema version. This test only validates migration success, not data integrity.
//
// All test database files are SQL dumps (created with `sqlite3 headscale.db .dump`) generated
// with old Headscale binaries on empty databases (no user/node data). These dumps include the
// migration history in the `migrations` table, which allows the migration system to correctly
// skip already-applied migrations and only run new ones.
func TestSQLiteAllTestdataMigrations(t *testing.T) {
	t.Parallel()

	schemas, err := os.ReadDir("testdata/sqlite")
	require.NoError(t, err)

	t.Logf("loaded %d schemas", len(schemas))

	for _, schema := range schemas {
		if schema.IsDir() {
			continue
		}

		t.Logf("validating: %s", schema.Name())

		t.Run(schema.Name(), func(t *testing.T) {
			t.Parallel()

			dbPath := t.TempDir() + "/headscale_test.db"

			// Setup a database with the old schema
			schemaPath := filepath.Join("testdata/sqlite", schema.Name())
			err := createSQLiteFromSQLFile(schemaPath, dbPath)
			require.NoError(t, err)

			_, err = NewHeadscaleDatabase(
				&types.Config{
					Database: types.DatabaseConfig{
						Type: "sqlite3",
						Sqlite: types.SqliteConfig{
							Path: dbPath,
						},
					},
					Policy: types.PolicyConfig{
						Mode: types.PolicyModeDB,
					},
				},
			)
			require.NoError(t, err)
		})
	}
}
