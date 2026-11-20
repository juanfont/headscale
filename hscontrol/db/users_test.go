package db

import (
	"database/sql"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// destroyUser deletes a user as State.DeleteUser does in the database: it
// refuses a user that owns nodes.
func destroyUser(hsdb *HSDatabase, uid types.UserID) error {
	return hsdb.Write(func(tx *gorm.DB) error {
		c, err := LockUserContents(tx, uid)
		if err != nil {
			return err
		}

		if len(c.Nodes) > 0 {
			return &UserHasNodesError{Nodes: c.Nodes}
		}

		return DestroyUserContents(tx, c)
	})
}

func TestDestroyUserKeepsTaggedNodeEphemeral(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("tagged-ephemeral-user")
	pak, err := db.CreatePreAuthKey(
		user.TypedID(),
		true,
		true,
		nil,
		[]string{"tag:server"},
	)
	require.NoError(t, err)

	node := &types.Node{
		Hostname:  "tagged-ephemeral-node",
		Tags:      []string{"tag:server"},
		AuthKeyID: &pak.ID,
		Ephemeral: true,
	}
	require.NoError(t, db.DB.Create(node).Error)
	require.NoError(t, destroyUser(db, types.UserID(user.ID)))
	nodes, err := db.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.True(t, nodes[0].IsTagged())
	require.True(t, nodes[0].IsEphemeral())

	retained, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	require.Nil(t, retained.Revoked, "a tagged key outlives the user that made it")
	require.Nil(t, retained.UserID)
}

func TestCreateAndDestroyUser(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	assert.Equal(t, "test", user.Name)

	users, err := db.ListUsers(nil)
	require.NoError(t, err)
	assert.Len(t, users, 1)

	err = destroyUser(db, types.UserID(user.ID))
	require.NoError(t, err)

	_, err = db.GetUserByID(types.UserID(user.ID))
	assert.Error(t, err)
}

func TestDestroyUserErrors(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "error_user_not_found",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				err := destroyUser(db, 9998)
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "success_deletes_preauthkeys",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user := db.CreateUserForTest("test")

				pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
				require.NoError(t, err)

				err = destroyUser(db, types.UserID(user.ID))
				require.NoError(t, err)

				// Verify preauth key credential was deleted.
				var foundPak types.Credential

				result := db.DB.First(&foundPak, "kind = ? AND id = ?", types.CredentialPreAuthKey, pak.ID)
				assert.ErrorIs(t, result.Error, gorm.ErrRecordNotFound)
			},
		},
		{
			// A tagged key belongs to its tags, so it outlives the user that
			// made it and only loses the reference.
			name: "success_keeps_tagged_preauthkeys",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user := db.CreateUserForTest("test")

				tagged, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, []string{"tag:ci"})
				require.NoError(t, err)

				err = destroyUser(db, types.UserID(user.ID))
				require.NoError(t, err)

				got, err := db.GetPreAuthKeyByID(tagged.ID)
				require.NoError(t, err)
				assert.Nil(t, got.UserID)
				assert.Equal(t, []string{"tag:ci"}, got.Tags)
			},
		},
		{
			name: "error_user_has_nodes",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				pak, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, nil)
				require.NoError(t, err)

				pakID := pak.ID

				node := types.Node{
					ID:             0,
					Hostname:       "testnode",
					UserID:         &user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					AuthKeyID:      &pakID,
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)

				err = destroyUser(db, types.UserID(user.ID))
				require.ErrorIs(t, err, ErrUserStillHasNodes)
				// The error names the blocking node so it can be found.
				require.ErrorContains(t, err, fmt.Sprintf("%d (testnode)", node.ID))
			},
		},
		{
			// https://github.com/juanfont/headscale/issues/3077
			// Tagged nodes have user_id = NULL, so they do not block
			// user deletion and are unaffected by ON DELETE CASCADE.
			name: "success_user_only_has_tagged_nodes",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				// Create a tagged node with no user_id (the rule for tagged nodes).
				node := types.Node{
					ID:             0,
					Hostname:       "tagged-node",
					RegisterMethod: util.RegisterMethodAuthKey,
					Tags:           []string{"tag:server"},
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)

				err = destroyUser(db, types.UserID(user.ID))
				require.NoError(t, err)

				// User is gone.
				_, err = db.GetUserByID(types.UserID(user.ID))
				require.ErrorIs(t, err, ErrUserNotFound)

				// Tagged node survives.
				var survivingNode types.Node

				result := db.DB.First(&survivingNode, "id = ?", node.ID)
				require.NoError(t, result.Error)
				assert.Nil(t, survivingNode.UserID)
				assert.Equal(t, []string{"tag:server"}, survivingNode.Tags.List())
			},
		},
		{
			// A user who has both tagged and user-owned nodes cannot
			// be deleted; the user-owned nodes still block deletion.
			name: "error_user_has_tagged_and_owned_nodes",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				// Tagged node: no user_id.
				taggedNode := types.Node{
					ID:             0,
					Hostname:       "tagged-node",
					RegisterMethod: util.RegisterMethodAuthKey,
					Tags:           []string{"tag:server"},
				}
				trx := db.DB.Save(&taggedNode)
				require.NoError(t, trx.Error)

				// User-owned node: has user_id.
				ownedNode := types.Node{
					ID:             0,
					Hostname:       "owned-node",
					UserID:         &user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
				}
				trx = db.DB.Save(&ownedNode)
				require.NoError(t, trx.Error)

				err = destroyUser(db, types.UserID(user.ID))
				require.ErrorIs(t, err, ErrUserStillHasNodes)
			},
		},
		{
			// Regression test for https://github.com/juanfont/headscale/issues/3154
			// DestroyUser must only delete the target user's pre-auth keys,
			// not all pre-auth keys in the database.
			name: "success_only_deletes_own_preauthkeys",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				userA := db.CreateUserForTest("usera")
				userB := db.CreateUserForTest("userb")

				// Create 2 keys for userA, 1 key for userB.
				_, err := db.CreatePreAuthKey(userA.TypedID(), false, false, nil, nil)
				require.NoError(t, err)
				_, err = db.CreatePreAuthKey(userA.TypedID(), false, false, nil, nil)
				require.NoError(t, err)
				_, err = db.CreatePreAuthKey(userB.TypedID(), false, false, nil, nil)
				require.NoError(t, err)

				// Sanity check: 3 keys exist.
				allKeys, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				require.Len(t, allKeys, 3)

				// Delete userB.
				err = destroyUser(db, types.UserID(userB.ID))
				require.NoError(t, err)

				// Only userA's 2 keys should remain.
				remaining, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				assert.Len(t, remaining, 2,
					"expected 2 keys for userA, got %d — DestroyUser deleted keys from other users",
					len(remaining))

				for _, key := range remaining {
					assert.NotNil(t, key.UserID)
					assert.Equal(t, userA.ID, *key.UserID,
						"remaining key should belong to userA")
				}
			},
		},
	}

	// User deletion depends on foreign-key actions that differ between the
	// hand-written SQLite schema and the GORM-generated Postgres schema, so
	// run every case on both. The Postgres variant skips when no local
	// server can be started.
	for _, tt := range tests {
		t.Run(tt.name+"-sqlite", func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			tt.test(t, db)
		})
		t.Run(tt.name+"-postgres", func(t *testing.T) {
			tt.test(t, newPostgresTestDB(t))
		})
	}
}

func TestGetUserErrorPropagation(t *testing.T) {
	lookups := []struct {
		name string
		get  func(*HSDatabase) (*types.User, error)
	}{
		{
			name: "by_id",
			get:  func(db *HSDatabase) (*types.User, error) { return db.GetUserByID(1) },
		},
		{
			name: "by_oidc_identifier",
			get:  func(db *HSDatabase) (*types.User, error) { return db.GetUserByOIDCIdentifier("oidc-id") },
		},
	}

	tests := []struct {
		name    string
		closeDB bool
		wantErr error
	}{
		{name: "missing_row_is_not_found", wantErr: ErrUserNotFound},
		{name: "query_failure_is_returned", closeDB: true},
	}

	for _, lookup := range lookups {
		for _, tt := range tests {
			t.Run(lookup.name+"/"+tt.name, func(t *testing.T) {
				db, err := newSQLiteTestDB()
				require.NoError(t, err)

				if tt.closeDB {
					sqlDB, err := db.DB.DB()
					require.NoError(t, err)
					require.NoError(t, sqlDB.Close())
				}

				user, err := lookup.get(db)

				// A swallowed error surfaces as a zero user and a nil error.
				require.Error(t, err)
				assert.Nil(t, user)

				if tt.wantErr != nil {
					assert.ErrorIs(t, err, tt.wantErr)
				} else {
					assert.NotErrorIs(t, err, ErrUserNotFound)
				}
			})
		}
	}
}

// TestDuplicateUserNameIsTyped pins the root cause: a unique-index violation
// must reach callers as a typed error on every backend, not as driver text.
func TestDuplicateUserNameIsTyped(t *testing.T) {
	backends := map[string]func(t *testing.T) *HSDatabase{
		"sqlite": func(t *testing.T) *HSDatabase {
			t.Helper()

			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			return db
		},
		"postgres": newPostgresTestDB,
	}

	for name, open := range backends {
		t.Run(name+"/create", func(t *testing.T) {
			db := open(t)
			db.CreateUserForTest("dup")

			_, err := db.CreateUser(types.User{Name: "dup"})
			require.ErrorIs(t, err, gorm.ErrDuplicatedKey)
		})

		t.Run(name+"/rename", func(t *testing.T) {
			db := open(t)
			db.CreateUserForTest("dup")
			other := db.CreateUserForTest("other")

			err := db.RenameUser(types.UserID(other.ID), "dup")
			require.ErrorIs(t, err, gorm.ErrDuplicatedKey)
		})
	}
}

func TestRenameUser(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "success_rename",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				userTest := db.CreateUserForTest("test")
				assert.Equal(t, "test", userTest.Name)

				users, err := db.ListUsers(nil)
				require.NoError(t, err)
				assert.Len(t, users, 1)

				err = db.RenameUser(types.UserID(userTest.ID), "test-renamed")
				require.NoError(t, err)

				users, err = db.ListUsers(&types.User{Name: "test"})
				require.NoError(t, err)
				assert.Empty(t, users)

				users, err = db.ListUsers(&types.User{Name: "test-renamed"})
				require.NoError(t, err)
				assert.Len(t, users, 1)
			},
		},
		{
			name: "error_user_not_found",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				err := db.RenameUser(99988, "test")
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "error_duplicate_name",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				userTest := db.CreateUserForTest("test")
				userTest2 := db.CreateUserForTest("test2")

				assert.Equal(t, "test", userTest.Name)
				assert.Equal(t, "test2", userTest2.Name)

				err := db.RenameUser(types.UserID(userTest2.ID), "test")
				require.ErrorIs(t, err, gorm.ErrDuplicatedKey)
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			tt.test(t, db)
		})
	}
}

func TestListUsersPage(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	users := db.CreateUsersForTest(5, "page")

	_, err = db.CreateUser(types.User{Name: "page-1", Email: "oidc@example.com", ProviderIdentifier: sql.NullString{String: "/oidc", Valid: true}})
	require.NoError(t, err)

	ids := func(us []types.User) []uint {
		out := make([]uint, len(us))
		for i, u := range us {
			out[i] = u.ID
		}

		return out
	}

	got, err := ListUsersPage(db.DB, &types.User{}, 0, 2)
	require.NoError(t, err)
	assert.Equal(t, []uint{users[0].ID, users[1].ID}, ids(got))

	got, err = ListUsersPage(db.DB, &types.User{}, types.UserID(users[1].ID), 2)
	require.NoError(t, err)
	assert.Equal(t, []uint{users[2].ID, users[3].ID}, ids(got))

	got, err = ListUsersPage(db.DB, &types.User{Name: "page-1"}, 0, 10)
	require.NoError(t, err)
	assert.Len(t, got, 2, "an OIDC user may share a local user's name")

	got, err = ListUsersPage(db.DB, &types.User{Name: "page-1", Email: "oidc@example.com"}, 0, 10)
	require.NoError(t, err)
	assert.Len(t, got, 1, "all filters must match")

	got, err = ListUsersPage(db.DB, &types.User{Name: "page-1"}, types.UserID(users[1].ID), 10)
	require.NoError(t, err)
	assert.Len(t, got, 1)
}

// eachDB runs test on SQLite and on PostgreSQL.
func eachDB(t *testing.T, test func(t *testing.T, db *HSDatabase)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// TestDestroyUserContents: the delete of a user takes its nodes, its auth
// keys and its API keys, revoked ones too, and nothing of another user;
// what it made and what it owned before tags stay and forget it.
func TestDestroyUserContents(t *testing.T) {
	eachDB(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := db.CreateUserForTest("alice")
		bob := db.CreateUserForTest("bob")
		aliceID := types.UserID(alice.ID)

		authKey, err := db.CreatePreAuthKey(alice.TypedID(), true, false, nil, nil)
		require.NoError(t, err)
		revokedKey, err := db.CreatePreAuthKey(alice.TypedID(), false, false, nil, nil)
		require.NoError(t, err)
		require.NoError(t, db.RevokePreAuthKey(revokedKey.ID))
		legacyTagged, err := db.CreatePreAuthKey(alice.TypedID(), true, false, nil, []string{"tag:ci"})
		require.NoError(t, err)
		bobKey, err := db.CreatePreAuthKey(bob.TypedID(), true, false, nil, nil)
		require.NoError(t, err)

		var madeTagged, apiKey, revokedAPIKey *types.Credential

		require.NoError(t, db.Write(func(tx *gorm.DB) error {
			k, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{Tags: []string{"tag:ci"}, CreatedBy: &aliceID})
			require.NoError(t, err)

			madeTagged = &types.Credential{ID: k.ID}

			apiKey, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &aliceID})
			require.NoError(t, err)

			revokedAPIKey, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &aliceID})

			return err
		}))
		require.NoError(t, db.RevokeAPIKey(revokedAPIKey.ID))

		_, client, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", &alice.ID)
		require.NoError(t, err)

		owned := &types.Node{Hostname: "owned", UserID: &alice.ID, AuthKeyID: &authKey.ID}
		// A node alice registered that has tags since: it keeps her key.
		tagged := &types.Node{Hostname: "tagged", Tags: []string{"tag:ci"}, AuthKeyID: &authKey.ID, CreatedByUserID: &alice.ID}
		bobs := &types.Node{Hostname: "bobs", UserID: &bob.ID, AuthKeyID: &bobKey.ID}

		for _, n := range []*types.Node{owned, tagged, bobs} {
			require.NoError(t, db.DB.Save(n).Error)
		}

		var c *UserContents

		require.NoError(t, db.Write(func(tx *gorm.DB) error {
			var err error

			c, err = LockUserContents(tx, aliceID)
			if err != nil {
				return err
			}

			return DestroyUserContents(tx, c)
		}))

		assert.Equal(t, []types.NodeID{owned.ID}, []types.NodeID{c.Nodes[0].ID})
		assert.Len(t, c.Nodes, 1)
		assert.Equal(t, []uint64{authKey.ID, revokedKey.ID}, c.AuthKeys)
		assert.Equal(t, []uint64{apiKey.ID, revokedAPIKey.ID}, c.APIKeys)

		_, err = db.GetUserByID(aliceID)
		require.ErrorIs(t, err, ErrUserNotFound)

		var left int64

		require.NoError(t, db.DB.Model(&types.Credential{}).Where("user_id = ? OR created_by_user_id = ?", alice.ID, alice.ID).Count(&left).Error)
		assert.Zero(t, left, "no credential names alice")
		require.NoError(t, db.DB.Model(&types.Node{}).Where("user_id = ? OR created_by_user_id = ?", alice.ID, alice.ID).Count(&left).Error)
		assert.Zero(t, left, "no node names alice")

		for _, id := range []uint64{legacyTagged.ID, madeTagged.ID} {
			k, err := db.GetPreAuthKeyByID(id)
			require.NoError(t, err, "a tagged key she made stays")
			assert.Nil(t, k.Revoked)
		}

		got, err := db.GetOAuthClientCredential(client.ClientID)
		require.NoError(t, err, "a client she made stays")
		assert.Nil(t, got.UserID)

		stays, err := GetNodeByID(db.DB, tagged.ID)
		require.NoError(t, err, "a tagged node stays")
		assert.Nil(t, stays.AuthKeyID, "and loses her key")

		bobsNode, err := GetNodeByID(db.DB, bobs.ID)
		require.NoError(t, err)
		assert.Equal(t, bobKey.ID, *bobsNode.AuthKeyID, "bob keeps his")
	})
}

// TestUserWritesWaitForADelete: a write that names a user, as its owner or
// as its maker, while a delete of the user holds what it read, waits for
// the delete and then finds the user gone: an owned key is refused and a
// made one forgets its maker, so nothing names a user that is gone and the
// delete removed all it read. On PostgreSQL the wait is on the user's row;
// SQLite has one connection.
func TestUserWritesWaitForADelete(t *testing.T) {
	writes := map[string]struct {
		write func(tx *gorm.DB, uid types.UserID) error
		err   error
	}{
		"auth key of the user": {func(tx *gorm.DB, uid types.UserID) error {
			_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{User: &uid})

			return err
		}, ErrUserNotFound},
		"tagged key the legacy APIs file under its maker": {func(tx *gorm.DB, uid types.UserID) error {
			_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{User: &uid, Tags: []string{"tag:ci"}})

			return err
		}, ErrUserNotFound},
		"tagged key the user made": {func(tx *gorm.DB, uid types.UserID) error {
			_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{Tags: []string{"tag:ci"}, CreatedBy: &uid})

			return err
		}, nil},
		"API key of the user": {func(tx *gorm.DB, uid types.UserID) error {
			_, _, err := CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})

			return err
		}, ErrUserNotFound},
		"OAuth client the user made": {func(tx *gorm.DB, uid types.UserID) error {
			_, _, err := CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid})

			return err
		}, nil},
	}

	eachDB(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		for name, w := range writes {
			user := db.CreateUserForTest(strings.ReplaceAll(name, " ", "-"))
			uid := types.UserID(user.ID)

			var c *UserContents

			err := whileHeldThen(t, db,
				func(tx *gorm.DB) error {
					var err error

					c, err = LockUserContents(tx, uid)

					return err
				},
				func() error { return db.Write(func(tx *gorm.DB) error { return w.write(tx, uid) }) },
				func(tx *gorm.DB) error { return DestroyUserContents(tx, c) })
			if w.err != nil {
				require.ErrorIs(t, err, w.err, name)
			} else {
				require.NoError(t, err, name)
			}

			var left int64

			require.NoError(t, db.DB.Model(&types.Credential{}).Where("user_id = ? OR created_by_user_id = ?", user.ID, user.ID).Count(&left).Error)
			require.Zero(t, left, "%s: nothing names the user it was made for", name)
		}
	})
}

// TestUserDeleteLockOrder: a delete of a user and the credentials its own
// API key makes for it at once never deadlock: both lock the user before a
// credential. Only PostgreSQL locks rows; SQLite runs one writer at a time.
func TestUserDeleteLockOrder(t *testing.T) {
	db := newPostgresTestDB(t)

	for round := range 30 {
		user := db.CreateUserForTest("u" + strconv.Itoa(round))
		uid := types.UserID(user.ID)

		var key *types.Credential

		require.NoError(t, db.Write(func(tx *gorm.DB) error {
			var err error

			key, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})

			return err
		}))

		ops := make([]func() error, 0, 9)
		ops = append(ops, func() error { return destroyUser(db, uid) })

		for range 4 {
			ops = append(ops,
				func() error {
					return db.Write(func(tx *gorm.DB) error {
						_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{User: &uid, Maker: key.ID})

						return err
					})
				},
				func() error {
					return db.Write(func(tx *gorm.DB) error {
						_, _, err := CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid, Maker: key.ID})

						return err
					})
				})
		}

		errs := make(chan error, len(ops))

		var wg sync.WaitGroup
		for _, op := range ops {
			wg.Go(func() { errs <- op() })
		}

		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				require.NotContains(t, err.Error(), "deadlock", "round %d", round)
			}
		}
	}
}

// TestUserDeleteStorm: on PostgreSQL, the delete of a user runs at once with
// the hourly removal, creates by the user's own key, a mint from a client the
// user made, the revoke of such a client and the revoke of a key of the
// user, while revoked rows the user made and owns wait for the removal. No
// statement may be aborted as a deadlock.
func TestUserDeleteStorm(t *testing.T) {
	db := newPostgresTestDB(t)

	for round := range 40 {
		user := db.CreateUserForTest("s" + strconv.Itoa(round))
		uid := types.UserID(user.ID)

		var key, spare, minting, revoking, made, owned *types.Credential

		require.NoError(t, db.Write(func(tx *gorm.DB) error {
			var err error

			made, _, err = CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid})
			if err != nil {
				return err
			}

			owned, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})
			if err != nil {
				return err
			}

			key, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})
			if err != nil {
				return err
			}

			spare, _, err = CreateAPIKeyFrom(tx, NewAPIKey{Owner: &uid})
			if err != nil {
				return err
			}

			minting, _, err = CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid, Maker: key.ID})
			if err != nil {
				return err
			}

			revoking, _, err = CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid, Maker: key.ID})

			return err
		}))
		require.NoError(t, db.DB.Model(&types.Credential{}).Where("id IN ?", []uint64{made.ID, owned.ID}).
			Update("revoked", time.Now().Add(-48*time.Hour).UTC()).Error)

		ops := make([]func() error, 0, 9)
		ops = append(ops,
			func() error { return destroyUser(db, uid) },
			func() error { _, err := db.DestroyRevokedCredentialsBefore(time.Now()); return err },
			func() error {
				_, _, err := db.MintAccessToken(minting.Identifier, []string{"auth_keys"}, []string{"tag:ci"}, new(time.Now().Add(time.Hour)))

				return err
			},
			func() error { return db.RevokeOAuthClient(revoking.Identifier) },
			func() error { return db.RevokeAPIKey(spare.ID) },
		)

		for range 2 {
			ops = append(ops,
				func() error {
					return db.Write(func(tx *gorm.DB) error {
						_, _, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{User: &uid, Maker: key.ID})

						return err
					})
				},
				func() error {
					return db.Write(func(tx *gorm.DB) error {
						_, _, err := CreateOAuthClientFrom(tx, NewOAuthClient{Scopes: []string{"auth_keys"}, Tags: []string{"tag:ci"}, CreatedBy: &uid, Maker: key.ID})

						return err
					})
				})
		}

		errs := make(chan error, len(ops))

		var wg sync.WaitGroup
		for _, op := range ops {
			wg.Go(func() { errs <- op() })
		}

		wg.Wait()
		close(errs)

		for err := range errs {
			if err != nil {
				require.NotContains(t, err.Error(), "deadlock", "round %d", round)
			}
		}
	}
}

// TestUserContentsTokenInAnyZone: the token holds the user's creation
// time, read back from the database; a server east or west of UTC, or in
// another zone than when the user was made, gives the same token.
func TestUserContentsTokenInAnyZone(t *testing.T) {
	zones := []*time.Location{
		time.UTC, time.FixedZone("east", 9*60*60), time.FixedZone("west", -5*60*60), time.FixedZone("south", -(3*60+30)*60),
	}

	local := time.Local //nolint:gosmopolitan // the server's zone is what the test varies

	t.Cleanup(func() { time.Local = local }) //nolint:gosmopolitan // the server's zone is what the test varies

	eachDB(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		token := func(uid types.UserID) string {
			c, err := Read(db.DB, func(rx *gorm.DB) (*UserContents, error) { return LockUserContents(rx, uid) })
			require.NoError(t, err)

			return c.Token()
		}

		for i, made := range zones {
			time.Local = made //nolint:gosmopolitan // the server's zone is what the test varies
			uid := types.UserID(db.CreateUserForTest("zone" + strconv.Itoa(i)).ID)

			want := token(uid)

			for _, at := range zones {
				time.Local = at //nolint:gosmopolitan // the server's zone is what the test varies
				require.Equal(t, want, token(uid), "made in %s, read in %s", made, at)
			}
		}
	})
}
