package db

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// legacyPlaintextKey is the pre-0.28 plaintext pre-auth key (id 5) seeded in
// both 0.29.3 fixtures.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
const legacyPlaintextKey = "plaintextlegacykey0000000000000000000000000000"

// TestSQLiteMigrationAndDataValidation tests specific SQLite migration scenarios
// and validates data integrity after migration. All migrations that require data validation
// should be added here.
func TestSQLiteMigrationAndDataValidation(t *testing.T) {
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
	}{
		// TODO(kradalby): remove in 0.31 with the credentials migration.
		// Real v0.29.3 database: the supported upgrade path into the unified
		// credentials table. Key strings are listed in the fixture header.
		{
			dbPath: "testdata/sqlite/headscale_0.29.3_dump.sql",
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()

				for _, table := range []string{"pre_auth_keys", "api_keys", "oauth_clients", "oauth_access_tokens"} {
					assert.False(t, hsdb.DB.Migrator().HasTable(table), "%s must be dropped", table)
				}

				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				require.Len(t, nodes, 5)

				// Pre-auth key ids are preserved, so every node keeps its key.
				for _, n := range nodes {
					require.NotNil(t, n.AuthKeyID, "node %d", n.ID)
					assert.Equal(t, uint64(n.ID), *n.AuthKeyID, "node %d", n.ID)
					require.NotNil(t, n.AuthKey, "node %d", n.ID)
					assert.Equal(t, types.CredentialPreAuthKey, n.AuthKey.Kind)
				}

				used, err := hsdb.GetPreAuthKeyByID(2)
				require.NoError(t, err)
				assert.True(t, used.Used)
				assert.False(t, used.Reusable)

				tagged, err := hsdb.GetPreAuthKeyByID(4)
				require.NoError(t, err)
				assert.Equal(t, []string{"tag:server"}, tagged.Tags)
				assert.Nil(t, tagged.UserID)
				require.NotNil(t, tagged.Expiration)

				// The legacy plaintext key is hashed, keeps authenticating
				// and still backs its ephemeral node.
				legacy, err := hsdb.GetPreAuthKey(legacyPlaintextKey)
				require.NoError(t, err)
				assert.Equal(t, uint64(5), legacy.ID)
				assert.Equal(t, legacyAuthKeyIdentifier(legacyPlaintextKey), legacy.Prefix)
				assert.Equal(t, hashSecret(legacyPlaintextKey), legacy.Hash)
				assert.Nil(t, legacy.Revoked)
				require.NoError(t, legacy.Validate())

				ephemeral, err := hsdb.ListEphemeralNodes()
				require.NoError(t, err)

				ephemeralIDs := make([]types.NodeID, 0, len(ephemeral))
				for _, n := range ephemeral {
					ephemeralIDs = append(ephemeralIDs, n.ID)
				}

				assert.ElementsMatch(t, []types.NodeID{3, 5}, ephemeralIDs)

				// The SQLite nodes rebuild keeps the id counter past the
				// deleted node 6.
				var seq int64
				require.NoError(t, hsdb.DB.Raw(`SELECT seq FROM sqlite_sequence WHERE name = 'nodes'`).Scan(&seq).Error)
				assert.Equal(t, int64(6), seq)

				// bcrypt keys authenticate and are upgraded to SHA-256.
				apiKey, err := hsdb.AuthenticateAPIKey(
					"hskey-api-ZRVzG0vKkUb4-dqem7jxt7Aun0JqfZpbsvrBDYdQV-RK8S9qbiAAniiuTxIj73LeDUDukVYJBqmDh")
				require.NoError(t, err)
				assert.Greater(t, apiKey.ID, uint64(5), "API keys are renumbered after pre-auth keys")

				pak, err := hsdb.GetPreAuthKey(
					"hskey-auth-H3XVw1W-6s4J-KTmfCUFG_4gJ8CuI5j3W67DX8eMnQJi6W8ToVK0esXMrPK5YTm_p8THq6VnH22-K")
				require.NoError(t, err)
				assert.Equal(t, uint64(1), pak.ID)

				stored, err := hsdb.GetPreAuthKeyByID(1)
				require.NoError(t, err)
				assert.True(t, strings.HasPrefix(string(stored.Hash), hashPrefixSHA256))

				// New credentials never collide with migrated ids.
				_, newKey, err := hsdb.CreateAPIKey(nil)
				require.NoError(t, err)
				assert.Greater(t, newKey.ID, apiKey.ID)
			},
		},
		// TODO(kradalby): remove in 0.31 with the 0.29.x migrations.
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
		// TODO(kradalby): remove in 0.31 with the 0.29.x migrations.
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
		preSQL   []string // run after restore, before migrating
		wantFunc func(*testing.T, *HSDatabase)
	}{
		// TODO(kradalby): remove in 0.31 with the credentials migration.
		// Real v0.29.3 Postgres database (pg_dump -Fc), same shape as the
		// SQLite 0.29.3 fixture: exercises the explicit-id backfill, the
		// sequence reset and the in-place foreign key swap.
		{
			name:   "0.29.3",
			dbPath: "testdata/postgres/headscale_0.29.3.pssql",
			// Keys 6-9 were created and deleted before the upgrade.
			preSQL: []string{`SELECT setval('pre_auth_keys_id_seq', 9)`},
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()

				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				require.Len(t, nodes, 5)

				for _, n := range nodes {
					require.NotNil(t, n.AuthKey, "node %d", n.ID)
					assert.Equal(t, uint64(n.ID), n.AuthKey.ID, "node %d", n.ID)
				}

				legacy, err := hsdb.GetPreAuthKey(legacyPlaintextKey)
				require.NoError(t, err)
				assert.Equal(t, uint64(5), legacy.ID)
				require.NoError(t, legacy.Validate())

				ephemeral, err := hsdb.ListEphemeralNodes()
				require.NoError(t, err)
				assert.Len(t, ephemeral, 2)

				apiKey, err := hsdb.AuthenticateAPIKey(
					"hskey-api-SdBE2-ozHMyK-HjrXcK0p7TYzcbylruVbFWlyt6HjcHwo7x_GLPLhAalGRfqet4IrZU-q91oeYeEN")
				require.NoError(t, err)
				assert.Greater(t, apiKey.ID, uint64(5))

				_, err = hsdb.GetPreAuthKey(
					"hskey-auth-RsYnjtPRQ36o-diMamZSeVhqfNiuKCp8sogtHIbfYfAkZ9iQm7e4naK-Wm2uUK-kHd56_IKGQQNTo")
				require.NoError(t, err)

				// The sequence was advanced past the explicit pre-auth ids.
				_, newKey, err := hsdb.CreateAPIKey(nil)
				require.NoError(t, err)
				assert.Greater(t, newKey.ID, apiKey.ID)

				requireCredentialConstraints(t, hsdb.DB)

				// Ids of keys deleted before the upgrade are not reused.
				pak, err := hsdb.CreatePreAuthKey(nil, false, false, nil, []string{"tag:x"})
				require.NoError(t, err)
				assert.Greater(t, pak.ID, uint64(9))
			},
		},
	}

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

			if len(tt.preSQL) > 0 {
				raw, err := sql.Open("pgx", u.String())
				require.NoError(t, err)

				for _, stmt := range tt.preSQL {
					_, err := raw.ExecContext(context.Background(), stmt)
					require.NoError(t, err, stmt)
				}

				require.NoError(t, raw.Close())
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

// TestSQLiteMigrationDanglingCredentialOwner covers API keys and OAuth clients
// whose user was deleted: their user_id never had a foreign key, so the
// backfill into credentials must null it instead of failing the upgrade.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func TestSQLiteMigrationDanglingCredentialOwner(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	require.NoError(t, createSQLiteFromSQLFile("testdata/sqlite/headscale_0.29.3_dump.sql", dbPath))

	// Bring the dump to the pre-credentials development schema by hand, with
	// rows owned by a user id that does not exist.
	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	for _, stmt := range []string{
		`ALTER TABLE api_keys ADD COLUMN user_id integer`,
		`UPDATE api_keys SET user_id = 99`,
		`ALTER TABLE pre_auth_keys ADD COLUMN description text`,
		`ALTER TABLE pre_auth_keys ADD COLUMN revoked datetime`,
		`CREATE TABLE oauth_clients(id integer PRIMARY KEY AUTOINCREMENT, client_id text, secret_hash blob, scopes text, tags text, description text, user_id integer, created_at datetime, revoked datetime)`,
		`CREATE UNIQUE INDEX idx_oauth_clients_client_id ON oauth_clients(client_id)`,
		`INSERT INTO oauth_clients(client_id, secret_hash, scopes, tags, user_id, created_at) VALUES('client000001', '$sha256$00', '[]', '["tag:ci"]', 99, '2026-01-01 00:00:00')`,
		`CREATE TABLE oauth_access_tokens(id integer PRIMARY KEY AUTOINCREMENT, prefix text, hash blob, client_id text, scopes text, tags text, expiration datetime, created_at datetime)`,
		`CREATE UNIQUE INDEX idx_oauth_access_tokens_prefix ON oauth_access_tokens(prefix)`,
		`INSERT OR IGNORE INTO migrations VALUES('202606181200-recover-null-tags-node-user-id'), ('202606191500-api-key-user-id'), ('202606191501-pre-auth-key-description'), ('202606201200-pre-auth-key-revoked'), ('202606211200-oauth-clients-and-tokens'), ('202607241200-clear-tagged-node-expiry')`,
	} {
		_, err := raw.ExecContext(context.Background(), stmt)
		require.NoError(t, err, stmt)
	}

	require.NoError(t, raw.Close())

	hsdb, err := NewHeadscaleDatabase(&types.Config{
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: dbPath},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	})
	require.NoError(t, err)

	keys, err := hsdb.ListAPIKeys()
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Nil(t, keys[0].UserID)

	client, err := hsdb.GetOAuthClientByClientID("client000001")
	require.NoError(t, err)
	assert.Nil(t, client.UserID)
}

// TestSQLiteMigrationToCredentialsIsAtomic fails the credentials migration at
// its last DDL step and asserts nothing was committed, so a retry succeeds.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func TestSQLiteMigrationToCredentialsIsAtomic(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	require.NoError(t, createSQLiteFromSQLFile("testdata/sqlite/headscale_0.29.3_dump.sql", dbPath))

	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	defer raw.Close()

	// An index of the same name makes the migration's final CREATE INDEX fail
	// after the backfill and the nodes rebuild have run.
	_, err = raw.ExecContext(context.Background(), `CREATE INDEX idx_nodes_auth_key_id ON users(id)`)
	require.NoError(t, err)

	cfg := &types.Config{
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: dbPath},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	}

	_, err = NewHeadscaleDatabase(cfg)
	require.Error(t, err)

	var paks, nodes int

	require.NoError(t, raw.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM pre_auth_keys`).Scan(&paks))
	require.NoError(t, raw.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM nodes`).Scan(&nodes))
	assert.Equal(t, 5, paks, "pre_auth_keys must be untouched")
	assert.Equal(t, 5, nodes, "nodes must be untouched")

	_, err = raw.ExecContext(context.Background(), `DROP INDEX idx_nodes_auth_key_id`)
	require.NoError(t, err)

	hsdb, err := NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	pak, err := hsdb.GetPreAuthKeyByID(1)
	require.NoError(t, err)
	assert.True(t, pak.Reusable)
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

// TestCredentialTableRoundTrip confirms the unified credentials table is created
// by migration (newSQLiteTestDB validates the schema with squibble) and stores
// and reads back a credential of each kind.
func TestCredentialTableRoundTrip(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	now := time.Now().UTC()
	creds := []types.Credential{
		{Kind: types.CredentialAPIKey, Identifier: "apikey000001", Hash: []byte("$h1"), CreatedAt: &now},
		{Kind: types.CredentialPreAuthKey, Identifier: "authkey00001", Hash: []byte("$h2"), Reusable: true, Tags: []string{"tag:a"}, CreatedAt: &now},
		{Kind: types.CredentialOAuthClient, Identifier: "client000001", Hash: []byte("$h3"), Scopes: []string{"devices:read"}, CreatedAt: &now},
		{Kind: types.CredentialOAuthToken, Identifier: "oauthtok0001", Hash: []byte("$h4"), ClientID: "client000001", CreatedAt: &now},
	}

	for i := range creds {
		require.NoError(t, db.DB.Save(&creds[i]).Error)
	}

	var got []types.Credential
	require.NoError(t, db.DB.Order("id").Find(&got).Error)
	require.Len(t, got, 4)
	assert.Equal(t, types.CredentialPreAuthKey, got[1].Kind)
	assert.Equal(t, []string{"tag:a"}, got[1].Tags)
	assert.Equal(t, "client000001", got[3].ClientID)

	// The composite (kind, identifier) index permits the same identifier under a
	// different kind but rejects a duplicate within a kind.
	require.NoError(t, db.DB.Save(&types.Credential{
		Kind: types.CredentialAPIKey, Identifier: "client000001", Hash: []byte("$h5"), CreatedAt: &now,
	}).Error)

	err = db.DB.Save(&types.Credential{
		Kind: types.CredentialAPIKey, Identifier: "apikey000001", Hash: []byte("$dup"), CreatedAt: &now,
	}).Error
	require.Error(t, err, "duplicate (kind, identifier) must be rejected")
}

// requireCredentialConstraints asserts the credentials table rejects rows the
// application must never write: an unknown kind, a hash in no known format,
// and a missing hash on a usable (unrevoked) row.
func requireCredentialConstraints(t *testing.T, db *gorm.DB) {
	t.Helper()

	now := time.Now().UTC()

	bad := map[string]types.Credential{
		"unknown kind":        {Kind: "bogus", Identifier: "chk000000001", Hash: []byte("$sha256$00")},
		"hash format":         {Kind: types.CredentialAPIKey, Identifier: "chk000000002", Hash: []byte("plain")},
		"missing hash usable": {Kind: types.CredentialAPIKey, Identifier: "chk000000003"},
	}
	for name, cred := range bad {
		require.Error(t, db.Create(&cred).Error, name)
	}

	// Only the migration writes hashless rows, as NULL.
	require.NoError(t, db.Exec(
		`INSERT INTO credentials (kind, identifier, hash, revoked) VALUES (?, ?, NULL, ?)`,
		types.CredentialPreAuthKey, "chk000000004", now,
	).Error, "a revoked row may lack a hash")
}

func TestCredentialConstraints(t *testing.T) {
	t.Run("fresh sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		requireCredentialConstraints(t, db.DB)
	})

	// TODO(kradalby): remove in 0.31 with the credentials migration.
	t.Run("migrated sqlite", func(t *testing.T) {
		hsdb := dbForTestWithPath(t, "testdata/sqlite/headscale_0.29.3_dump.sql")
		requireCredentialConstraints(t, hsdb.DB)
	})

	t.Run("fresh postgres", func(t *testing.T) {
		requireCredentialConstraints(t, newPostgresTestDB(t).DB)
	})
}

// TestNodeAuthKeyOnlyResolvesPreAuthKeys points a node at a credential of
// another kind, which the shared table's foreign key permits, and asserts it
// is not loaded as the node's pre-auth key.
func TestNodeAuthKeyOnlyResolvesPreAuthKeys(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("kind-filter")
	node := db.CreateNodeForTest(user, "kind-filter")

	_, apiKey, err := db.CreateAPIKey(nil)
	require.NoError(t, err)

	require.NoError(t, db.DB.Model(&types.Node{}).Where("id = ?", node.ID).
		Update("auth_key_id", apiKey.ID).Error)

	got, err := db.GetNodeByID(node.ID)
	require.NoError(t, err)
	assert.Nil(t, got.AuthKey, "an API key must not load as a node's pre-auth key")
}

func sqliteTestConfig(path string) *types.Config {
	return &types.Config{
		Database: types.DatabaseConfig{
			Type:   "sqlite3",
			Sqlite: types.SqliteConfig{Path: path},
		},
		Policy: types.PolicyConfig{Mode: types.PolicyModeDB},
	}
}

// TestSQLiteMigrationKeepsPreAuthKeySequence deletes keys before the upgrade
// (the old table's AUTOINCREMENT remembers them) and asserts their ids are
// not handed out again, so a stale request by id cannot hit a new key.
//
// TODO(kradalby): remove in 0.31 with the credentials migration.
func TestSQLiteMigrationKeepsPreAuthKeySequence(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	require.NoError(t, createSQLiteFromSQLFile("testdata/sqlite/headscale_0.29.3_dump.sql", dbPath))

	raw, err := sql.Open("sqlite", dbPath)
	require.NoError(t, err)

	_, err = raw.ExecContext(context.Background(), `UPDATE sqlite_sequence SET seq = 9 WHERE name = 'pre_auth_keys'`)
	require.NoError(t, err)
	require.NoError(t, raw.Close())

	hsdb, err := NewHeadscaleDatabase(sqliteTestConfig(dbPath))
	require.NoError(t, err)

	pak, err := hsdb.CreatePreAuthKey(nil, false, false, nil, []string{"tag:x"})
	require.NoError(t, err)
	assert.Greater(t, pak.ID, uint64(9))
}

// TestRevokedKeysBackingNodesSurviveCollection revokes the keys behind the
// migrated ephemeral nodes, runs the collector past the retention window and
// reloads: keys still backing a node must survive, so the nodes stay
// ephemeral, while unreferenced revoked keys are reaped.
//
// TODO(kradalby): seed without the 0.29.3 fixture in 0.31, when the
// credentials migration is dropped.
func TestRevokedKeysBackingNodesSurviveCollection(t *testing.T) {
	dbPath := t.TempDir() + "/headscale_test.db"

	require.NoError(t, createSQLiteFromSQLFile("testdata/sqlite/headscale_0.29.3_dump.sql", dbPath))

	hsdb, err := NewHeadscaleDatabase(sqliteTestConfig(dbPath))
	require.NoError(t, err)

	unused, err := hsdb.CreatePreAuthKey(nil, false, false, nil, []string{"tag:x"})
	require.NoError(t, err)

	for _, id := range []uint64{3, 5, unused.ID} {
		require.NoError(t, hsdb.RevokePreAuthKey(id))
	}

	reaped, err := hsdb.DestroyRevokedPreAuthKeysBefore(time.Now().Add(24 * time.Hour))
	require.NoError(t, err)
	assert.Equal(t, 1, reaped, "only the unreferenced revoked key is reaped")

	require.NoError(t, hsdb.Close())

	hsdb, err = NewHeadscaleDatabase(sqliteTestConfig(dbPath))
	require.NoError(t, err)

	ephemeral, err := hsdb.ListEphemeralNodes()
	require.NoError(t, err)

	ids := make([]types.NodeID, 0, len(ephemeral))
	for _, n := range ephemeral {
		ids = append(ids, n.ID)
	}

	assert.ElementsMatch(t, []types.NodeID{3, 5}, ids)
}

// TestInterruptedInitSchemaRecovers simulates a first start that created the
// schema but died before gormigrate recorded the migrations, and asserts the
// next start completes instead of failing on the existing credentials table.
func TestInterruptedInitSchemaRecovers(t *testing.T) {
	t.Run("sqlite", func(t *testing.T) {
		dbPath := t.TempDir() + "/headscale_test.db"

		hsdb, err := NewHeadscaleDatabase(sqliteTestConfig(dbPath))
		require.NoError(t, err)
		require.NoError(t, hsdb.DB.Exec(`DELETE FROM migrations`).Error)
		require.NoError(t, hsdb.Close())

		hsdb, err = NewHeadscaleDatabase(sqliteTestConfig(dbPath))
		require.NoError(t, err)

		_, _, err = hsdb.CreateAPIKey(nil)
		require.NoError(t, err)
	})

	t.Run("postgres", func(t *testing.T) {
		u := newPostgresDBForTest(t)

		hsdb := newHeadscaleDBFromPostgresURL(t, u)
		require.NoError(t, hsdb.DB.Exec(`DELETE FROM migrations`).Error)
		require.NoError(t, hsdb.Close())

		hsdb = newHeadscaleDBFromPostgresURL(t, u)

		_, _, err := hsdb.CreateAPIKey(nil)
		require.NoError(t, err)
	})
}
