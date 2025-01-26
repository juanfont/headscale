package db

import (
	"database/sql"
	"fmt"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"zgo.at/zcache/v2"
)

// TestMigrationsSQLite is the main function for testing migrations,
// we focus on SQLite correctness as it is the main database used in headscale.
// All migrations that are worth testing should be added here.
func TestMigrationsSQLite(t *testing.T) {
	ipp := func(p string) netip.Prefix {
		return netip.MustParsePrefix(p)
	}
	r := func(id uint64, p string, a, e, i bool) types.Route {
		return types.Route{
			NodeID:     id,
			Prefix:     ipp(p),
			Advertised: a,
			Enabled:    e,
			IsPrimary:  i,
		}
	}
	tests := []struct {
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
		wantErr  string
	}{
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-are-dropped-2063.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				require.NoError(t, err)

				assert.Len(t, routes, 10)
				want := types.Routes{
					r(1, "0.0.0.0/0", true, true, false),
					r(1, "::/0", true, true, false),
					r(1, "10.9.110.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, true, true),
					r(26, "172.100.100.0/24", true, false, false),
					r(31, "0.0.0.0/0", true, true, false),
					r(31, "0.0.0.0/0", true, false, false),
					r(31, "::/0", true, true, false),
					r(31, "::/0", true, false, false),
					r(32, "192.168.0.24/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), util.PrefixComparer); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
		{
			dbPath: "testdata/0-22-3-to-0-23-0-routes-fail-foreign-key-2076.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				routes, err := Read(h.DB, func(rx *gorm.DB) (types.Routes, error) {
					return GetRoutes(rx)
				})
				require.NoError(t, err)

				assert.Len(t, routes, 4)
				want := types.Routes{
					// These routes exists, but have no nodes associated with them
					// when the migration starts.
					// r(1, "0.0.0.0/0", true, true, false),
					// r(1, "::/0", true, true, false),
					// r(3, "0.0.0.0/0", true, true, false),
					// r(3, "::/0", true, true, false),
					// r(5, "0.0.0.0/0", true, true, false),
					// r(5, "::/0", true, true, false),
					// r(6, "0.0.0.0/0", true, true, false),
					// r(6, "::/0", true, true, false),
					// r(6, "10.0.0.0/8", true, false, false),
					// r(7, "0.0.0.0/0", true, true, false),
					// r(7, "::/0", true, true, false),
					// r(7, "10.0.0.0/8", true, false, false),
					// r(9, "0.0.0.0/0", true, true, false),
					// r(9, "::/0", true, true, false),
					// r(9, "10.0.0.0/8", true, true, false),
					// r(11, "0.0.0.0/0", true, true, false),
					// r(11, "::/0", true, true, false),
					// r(11, "10.0.0.0/8", true, true, true),
					// r(12, "0.0.0.0/0", true, true, false),
					// r(12, "::/0", true, true, false),
					// r(12, "10.0.0.0/8", true, false, false),
					//
					// These nodes exists, so routes should be kept.
					r(13, "10.0.0.0/8", true, false, false),
					r(13, "0.0.0.0/0", true, true, false),
					r(13, "::/0", true, true, false),
					r(13, "10.18.80.2/32", true, true, true),
				}
				if diff := cmp.Diff(want, routes, cmpopts.IgnoreFields(types.Route{}, "Model", "Node"), util.PrefixComparer); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}
			},
		},
		// at 14:15:06 ❯ go run ./cmd/headscale preauthkeys list
		// ID | Key      | Reusable | Ephemeral | Used  | Expiration | Created    | Tags
		// 1  | 09b28f.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:derp
		// 2  | 3112b9.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:derp
		// 3  | 7c23b9.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:derp,tag:merp
		// 4  | f20155.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:test
		// 5  | b212b9.. | false    | false     | false | 2024-09-27 | 2024-09-27 | tag:test,tag:woop,tag:dedu
		{
			dbPath: "testdata/0-23-0-to-0-24-0-preauthkey-tags-table.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				keys, err := Read(h.DB, func(rx *gorm.DB) ([]types.PreAuthKey, error) {
					kratest, err := ListPreAuthKeysByUser(rx, 1) // kratest
					if err != nil {
						return nil, err
					}

					testkra, err := ListPreAuthKeysByUser(rx, 2) // testkra
					if err != nil {
						return nil, err
					}

					return append(kratest, testkra...), nil
				})
				require.NoError(t, err)

				assert.Len(t, keys, 5)
				want := []types.PreAuthKey{
					{
						ID:   1,
						Tags: []string{"tag:derp"},
					},
					{
						ID:   2,
						Tags: []string{"tag:derp"},
					},
					{
						ID:   3,
						Tags: []string{"tag:derp", "tag:merp"},
					},
					{
						ID:   4,
						Tags: []string{"tag:test"},
					},
					{
						ID:   5,
						Tags: []string{"tag:test", "tag:woop", "tag:dedu"},
					},
				}

				if diff := cmp.Diff(want, keys, cmp.Comparer(func(a, b []string) bool {
					sort.Sort(sort.StringSlice(a))
					sort.Sort(sort.StringSlice(b))
					return slices.Equal(a, b)
				}), cmpopts.IgnoreFields(types.PreAuthKey{}, "Key", "UserID", "User", "CreatedAt", "Expiration")); diff != "" {
					t.Errorf("TestMigrations() mismatch (-want +got):\n%s", diff)
				}

				if h.DB.Migrator().HasTable("pre_auth_key_acl_tags") {
					t.Errorf("TestMigrations() table pre_auth_key_acl_tags should not exist")
				}
			},
		},
		{
			dbPath: "testdata/0-23-0-to-0-24-0-no-more-special-types.sqlite",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				nodes, err := Read(h.DB, func(rx *gorm.DB) (types.Nodes, error) {
					return ListNodes(rx)
				})
				require.NoError(t, err)

				for _, node := range nodes {
					assert.Falsef(t, node.MachineKey.IsZero(), "expected non zero machinekey")
					assert.Contains(t, node.MachineKey.String(), "mkey:")
					assert.Falsef(t, node.NodeKey.IsZero(), "expected non zero nodekey")
					assert.Contains(t, node.NodeKey.String(), "nodekey:")
					assert.Falsef(t, node.DiscoKey.IsZero(), "expected non zero discokey")
					assert.Contains(t, node.DiscoKey.String(), "discokey:")
					assert.NotNil(t, node.IPv4)
					assert.NotNil(t, node.IPv4)
					assert.Len(t, node.Endpoints, 1)
					assert.NotNil(t, node.Hostinfo)
					assert.NotNil(t, node.MachineKey)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.dbPath, func(t *testing.T) {
			dbPath, err := testCopyOfDatabase(tt.dbPath)
			if err != nil {
				t.Fatalf("copying db for test: %s", err)
			}

			hsdb, err := NewHeadscaleDatabase(types.DatabaseConfig{
				Type: "sqlite3",
				Sqlite: types.SqliteConfig{
					Path: dbPath,
				},
			}, "", emptyCache())
			if err != nil && tt.wantErr != err.Error() {
				t.Errorf("TestMigrations() unexpected error = %v, wantErr %v", err, tt.wantErr)
			}

			if tt.wantFunc != nil {
				tt.wantFunc(t, hsdb)
			}
		})
	}
}

func testCopyOfDatabase(src string) (string, error) {
	sourceFileStat, err := os.Stat(src)
	if err != nil {
		return "", err
	}

	if !sourceFileStat.Mode().IsRegular() {
		return "", fmt.Errorf("%s is not a regular file", src)
	}

	source, err := os.Open(src)
	if err != nil {
		return "", err
	}
	defer source.Close()

	tmpDir, err := os.MkdirTemp("", "hsdb-test-*")
	if err != nil {
		return "", err
	}

	fn := filepath.Base(src)
	dst := filepath.Join(tmpDir, fn)

	destination, err := os.Create(dst)
	if err != nil {
		return "", err
	}
	defer destination.Close()
	_, err = io.Copy(destination, source)
	return dst, err
}

func emptyCache() *zcache.Cache[types.RegistrationID, types.RegisterNode] {
	return zcache.New[types.RegistrationID, types.RegisterNode](time.Minute, time.Hour)
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

func TestMigrationsPostgres(t *testing.T) {
	tests := []struct {
		name     string
		dbPath   string
		wantFunc func(*testing.T, *HSDatabase)
	}{
		{
			name:   "user-idx-breaking",
			dbPath: "testdata/pre-24-postgresdb.pssql.dump",
			wantFunc: func(t *testing.T, h *HSDatabase) {
				users, err := Read(h.DB, func(rx *gorm.DB) ([]types.User, error) {
					return ListUsers(rx)
				})
				require.NoError(t, err)

				for _, user := range users {
					assert.NotEmpty(t, user.Name)
					assert.Empty(t, user.ProfilePicURL)
					assert.Empty(t, user.Email)
				}
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
			cmd := exec.Command(pgRestorePath, "--verbose", "--if-exists", "--clean", "--no-owner", "--dbname", u.String(), tt.dbPath)

			// Set the output streams
			cmd.Stdout = os.Stdout
			cmd.Stderr = os.Stderr

			// Execute the command
			err = cmd.Run()
			if err != nil {
				t.Fatalf("failed to restore postgres database: %s", err)
			}

			db = newHeadscaleDBFromPostgresURL(t, u)

			if tt.wantFunc != nil {
				tt.wantFunc(t, db)
			}
		})
	}
}
