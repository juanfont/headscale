package db

import (
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
	"zgo.at/zcache/v2"
)

// TestSQLiteMigrationAndDataValidation tests specific SQLite migration scenarios
// and validates data integrity after migration. All migrations that require data validation
// should be added here.
func TestSQLiteMigrationAndDataValidation(t *testing.T) {
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
	}{
		// at 14:15:06 ❯ go run ./cmd/headscale preauthkeys list
		// ID | Key      | Reusable | Ephemeral | Used  | Expiration | Created    | Tags
		// 1  | 09b28f.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:derp
		// 2  | 3112b9.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:derp
		{
			dbPath: "testdata/sqlite/failing-node-preauth-constraint_dump.sql",
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()
				// Comprehensive data preservation validation for node-preauth constraint issue
				// Expected data from dump: 1 user, 2 api_keys, 6 nodes

				// Verify users data preservation
				users, err := Read(hsdb.DB, func(rx *gorm.DB) ([]types.User, error) {
					return ListUsers(rx)
				})
				require.NoError(t, err)
				assert.Len(t, users, 1, "should preserve all 1 user from original schema")

				// Verify api_keys data preservation
				var apiKeyCount int
				err = hsdb.DB.Raw("SELECT COUNT(*) FROM api_keys").Scan(&apiKeyCount).Error
				require.NoError(t, err)
				assert.Equal(t, 2, apiKeyCount, "should preserve all 2 api_keys from original schema")

				// Verify nodes data preservation and field validation
				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				assert.Len(t, nodes, 6, "should preserve all 6 nodes from original schema")

				for _, node := range nodes {
					assert.Falsef(t, node.MachineKey.IsZero(), "expected non zero machinekey")
					assert.Contains(t, node.MachineKey.String(), "mkey:")
					assert.Falsef(t, node.NodeKey.IsZero(), "expected non zero nodekey")
					assert.Contains(t, node.NodeKey.String(), "nodekey:")
					assert.Falsef(t, node.DiscoKey.IsZero(), "expected non zero discokey")
					assert.Contains(t, node.DiscoKey.String(), "discokey:")
					assert.Nil(t, node.AuthKey)
					assert.Nil(t, node.AuthKeyID)
				}
			},
		},
		// Test for RequestTags migration (202601121700-migrate-hostinfo-request-tags)
		// and forced_tags->tags rename migration (202511131445-node-forced-tags-to-tags)
		//
		// This test validates that:
		// 1. The forced_tags column is renamed to tags
		// 2. RequestTags from host_info are validated against policy tagOwners
		// 3. Authorized tags are migrated to the tags column
		// 4. Unauthorized tags are rejected
		// 5. Existing tags are preserved
		// 6. Group membership is evaluated for tag authorization
		{
			dbPath: "testdata/sqlite/request_tags_migration_test.sql",
			wantFunc: func(t *testing.T, hsdb *HSDatabase) {
				t.Helper()

				nodes, err := Read(hsdb.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)
				require.Len(t, nodes, 7, "should have all 7 nodes")

				// Helper to find node by hostname
				findNode := func(hostname string) *types.Node {
					for _, n := range nodes {
						if n.Hostname == hostname {
							return n
						}
					}

					return nil
				}

				// Node 1: user1 has RequestTags for tag:server (authorized)
				// Expected: tags = ["tag:server"]
				node1 := findNode("node1")
				require.NotNil(t, node1, "node1 should exist")
				assert.Contains(t, node1.Tags, "tag:server", "node1 should have tag:server migrated from RequestTags")

				// Node 2: user1 has RequestTags for tag:unauthorized (NOT authorized)
				// Expected: tags = [] (unchanged)
				node2 := findNode("node2")
				require.NotNil(t, node2, "node2 should exist")
				assert.Empty(t, node2.Tags, "node2 should have empty tags (unauthorized tag rejected)")

				// Node 3: user2 has RequestTags for tag:client (authorized) + existing tag:existing
				// Expected: tags = ["tag:client", "tag:existing"]
				node3 := findNode("node3")
				require.NotNil(t, node3, "node3 should exist")
				assert.Contains(t, node3.Tags, "tag:client", "node3 should have tag:client migrated from RequestTags")
				assert.Contains(t, node3.Tags, "tag:existing", "node3 should preserve existing tag")

				// Node 4: user1 has RequestTags for tag:server which already exists
				// Expected: tags = ["tag:server"] (no duplicates)
				node4 := findNode("node4")
				require.NotNil(t, node4, "node4 should exist")
				assert.Equal(t, []string{"tag:server"}, node4.Tags, "node4 should have tag:server without duplicates")

				// Node 5: user2 has no RequestTags
				// Expected: tags = [] (unchanged)
				node5 := findNode("node5")
				require.NotNil(t, node5, "node5 should exist")
				assert.Empty(t, node5.Tags, "node5 should have empty tags (no RequestTags)")

				// Node 6: admin1 has RequestTags for tag:admin (authorized via group:admins)
				// Expected: tags = ["tag:admin"]
				node6 := findNode("node6")
				require.NotNil(t, node6, "node6 should exist")
				assert.Contains(t, node6.Tags, "tag:admin", "node6 should have tag:admin migrated via group membership")

				// Node 7: user1 has RequestTags for tag:server (authorized) and tag:forbidden (unauthorized)
				// Expected: tags = ["tag:server"] (only authorized tag)
				node7 := findNode("node7")
				require.NotNil(t, node7, "node7 should exist")
				assert.Contains(t, node7.Tags, "tag:server", "node7 should have tag:server migrated")
				assert.NotContains(t, node7.Tags, "tag:forbidden", "node7 should NOT have tag:forbidden (unauthorized)")
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

func emptyCache() *zcache.Cache[types.RegistrationID, types.RegisterNode] {
	return zcache.New[types.RegistrationID, types.RegisterNode](time.Minute, time.Hour)
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

	_, err = db.Exec(string(schemaContent))

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
			run: func(t *testing.T, db *gorm.DB) {
				_, err := CreateUser(db, types.User{Name: "user1"})
				require.NoError(t, err)
				_, err = CreateUser(db, types.User{Name: "user1"})
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "no-oidc-duplicate-username-and-id",
			run: func(t *testing.T, db *gorm.DB) {
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err := db.Save(&user).Error
				require.NoError(t, err)

				user = types.User{
					Model: gorm.Model{ID: 2},
					Name:  "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err = db.Save(&user).Error
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "no-oidc-duplicate-id",
			run: func(t *testing.T, db *gorm.DB) {
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  "user1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err := db.Save(&user).Error
				require.NoError(t, err)

				user = types.User{
					Model: gorm.Model{ID: 2},
					Name:  "user1.1",
				}
				user.ProviderIdentifier = sql.NullString{String: "http://test.com/user1", Valid: true}

				err = db.Save(&user).Error
				requireConstraintFailed(t, err)
			},
		},
		{
			name: "allow-duplicate-username-cli-then-oidc",
			run: func(t *testing.T, db *gorm.DB) {
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
			run: func(t *testing.T, db *gorm.DB) {
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
			cmd := exec.Command(pgRestorePath, "--verbose", "--if-exists", "--clean", "--no-owner", "--dbname", u.String(), tt.dbPath)

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
		emptyCache(),
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
				emptyCache(),
			)
			require.NoError(t, err)
		})
	}
}
