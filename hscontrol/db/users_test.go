package db

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

func TestCreateAndDestroyUser(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test")
	assert.Equal(t, "test", user.Name)

	users, err := db.ListUsers(nil)
	require.NoError(t, err)
	assert.Len(t, users, 1)

	err = db.DestroyUser(types.UserID(user.ID))
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

				err := db.DestroyUser(9998)
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

				err = db.DestroyUser(types.UserID(user.ID))
				require.NoError(t, err)

				// Verify preauth key was deleted (need to search by prefix for new keys)
				var foundPak types.PreAuthKey

				result := db.DB.First(&foundPak, "id = ?", pak.ID)
				assert.ErrorIs(t, result.Error, gorm.ErrRecordNotFound)
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

				err = db.DestroyUser(types.UserID(user.ID))
				assert.ErrorIs(t, err, ErrUserStillHasNodes)
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

				err = db.DestroyUser(types.UserID(user.ID))
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

				err = db.DestroyUser(types.UserID(user.ID))
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
				err = db.DestroyUser(types.UserID(userB.ID))
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

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			tt.test(t, db)
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
				require.Error(t, err)
				assert.Contains(t, err.Error(), "UNIQUE constraint failed")
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

func TestSetUserProfile(t *testing.T) {
	// seeded is the starting point for every case: all three presentational
	// fields populated, so both "change" and "clear" are observable.
	seeded := func(t *testing.T, db *HSDatabase) *types.User {
		t.Helper()

		user := db.CreateUserForTest("test")

		updated, err := Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
			return SetUserProfile(tx, types.UserID(user.ID), types.UserProfileUpdate{
				DisplayName:   new("Original"),
				Email:         new("original@example.com"),
				ProfilePicURL: new("https://example.com/original.png"),
			})
		})
		require.NoError(t, err)

		return updated
	}

	tests := []struct {
		name    string
		update  types.UserProfileUpdate
		wantErr error
		want    types.UserProfileUpdate // expected end state, all fields set
	}{
		{
			name: "set_all_fields",
			update: types.UserProfileUpdate{
				DisplayName:   new("Vika"),
				Email:         new("vika@example.com"),
				ProfilePicURL: new("https://example.com/vika.png"),
			},
			want: types.UserProfileUpdate{
				DisplayName:   new("Vika"),
				Email:         new("vika@example.com"),
				ProfilePicURL: new("https://example.com/vika.png"),
			},
		},
		{
			// The interesting case: GORM's struct-based Updates would drop
			// these because they are zero values.
			name: "empty_string_clears_field",
			update: types.UserProfileUpdate{
				DisplayName:   new(""),
				ProfilePicURL: new(""),
			},
			want: types.UserProfileUpdate{
				DisplayName:   new(""),
				Email:         new("original@example.com"),
				ProfilePicURL: new(""),
			},
		},
		{
			name:   "absent_field_is_untouched",
			update: types.UserProfileUpdate{ProfilePicURL: new("https://example.com/new.png")},
			want: types.UserProfileUpdate{
				DisplayName:   new("Original"),
				Email:         new("original@example.com"),
				ProfilePicURL: new("https://example.com/new.png"),
			},
		},
		{
			name:    "empty_update_rejected",
			update:  types.UserProfileUpdate{},
			wantErr: types.ErrEmptyUserProfileUpdate,
		},
		{
			name:    "relative_picture_url_rejected",
			update:  types.UserProfileUpdate{ProfilePicURL: new("/avatar.png")},
			wantErr: types.ErrInvalidProfilePicURL,
		},
		{
			name:    "javascript_picture_url_rejected",
			update:  types.UserProfileUpdate{ProfilePicURL: new("javascript:alert(1)")},
			wantErr: types.ErrInvalidProfilePicURL,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			user := seeded(t, db)

			got, err := Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
				return SetUserProfile(tx, types.UserID(user.ID), tt.update)
			})

			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)

			// The returned user and the persisted row must agree; a returned
			// value that is not what was written would be the worst failure.
			stored, err := db.GetUserByID(types.UserID(user.ID))
			require.NoError(t, err)

			for _, u := range []*types.User{got, stored} {
				assert.Equal(t, *tt.want.DisplayName, u.DisplayName)
				assert.Equal(t, *tt.want.Email, u.Email)
				assert.Equal(t, *tt.want.ProfilePicURL, u.ProfilePicURL)
			}
		})
	}

	t.Run("error_user_not_found", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)

		_, err = Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
			return SetUserProfile(tx, 99988, types.UserProfileUpdate{
				DisplayName: new("nobody"),
			})
		})
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	// OIDC re-applies its claims on every login, so an edit here would be
	// silently reverted. Refuse it, exactly as RenameUser does.
	t.Run("error_oidc_user", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)

		user := db.CreateUserForTest("oidc")
		user.Provider = util.RegisterMethodOIDC
		require.NoError(t, db.DB.Save(user).Error)

		_, err = Write(db.DB, func(tx *gorm.DB) (*types.User, error) {
			return SetUserProfile(tx, types.UserID(user.ID), types.UserProfileUpdate{
				DisplayName: new("Manual"),
			})
		})
		assert.ErrorIs(t, err, ErrCannotChangeOIDCUser)
	})
}
