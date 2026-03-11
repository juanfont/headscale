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

	users, err := db.ListUsers()
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

				// Create a tagged node with no user_id (the invariant).
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
				assert.Equal(t, []string{"tag:server"}, survivingNode.Tags)
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

				users, err := db.ListUsers()
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
