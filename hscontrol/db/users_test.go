package db

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/types/ptr"
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

				pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
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

				pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
				require.NoError(t, err)

				node := types.Node{
					ID:             0,
					Hostname:       "testnode",
					UserID:         user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					AuthKeyID:      ptr.To(pak.ID),
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)

				err = db.DestroyUser(types.UserID(user.ID))
				assert.ErrorIs(t, err, ErrUserStillHasNodes)
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

func TestAssignNodeToUser(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "success_reassign_node",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				oldUser := db.CreateUserForTest("old")
				newUser := db.CreateUserForTest("new")

				pak, err := db.CreatePreAuthKey(types.UserID(oldUser.ID), false, false, nil, nil)
				require.NoError(t, err)

				node := types.Node{
					ID:             12,
					Hostname:       "testnode",
					UserID:         oldUser.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					AuthKeyID:      ptr.To(pak.ID),
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)
				assert.Equal(t, oldUser.ID, node.UserID)

				err = db.Write(func(tx *gorm.DB) error {
					return AssignNodeToUser(tx, 12, types.UserID(newUser.ID))
				})
				require.NoError(t, err)

				// Reload node from database to see updated values
				updatedNode, err := db.GetNodeByID(12)
				require.NoError(t, err)
				assert.Equal(t, newUser.ID, updatedNode.UserID)
				assert.Equal(t, newUser.Name, updatedNode.User.Name)
			},
		},
		{
			name: "error_user_not_found",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				oldUser := db.CreateUserForTest("old")

				pak, err := db.CreatePreAuthKey(types.UserID(oldUser.ID), false, false, nil, nil)
				require.NoError(t, err)

				node := types.Node{
					ID:             12,
					Hostname:       "testnode",
					UserID:         oldUser.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					AuthKeyID:      ptr.To(pak.ID),
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)

				err = db.Write(func(tx *gorm.DB) error {
					return AssignNodeToUser(tx, 12, 9584849)
				})
				assert.ErrorIs(t, err, ErrUserNotFound)
			},
		},
		{
			name: "success_reassign_to_same_user",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user := db.CreateUserForTest("user")

				pak, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, nil)
				require.NoError(t, err)

				node := types.Node{
					ID:             12,
					Hostname:       "testnode",
					UserID:         user.ID,
					RegisterMethod: util.RegisterMethodAuthKey,
					AuthKeyID:      ptr.To(pak.ID),
				}
				trx := db.DB.Save(&node)
				require.NoError(t, trx.Error)

				err = db.Write(func(tx *gorm.DB) error {
					return AssignNodeToUser(tx, 12, types.UserID(user.ID))
				})
				require.NoError(t, err)

				// Reload node from database again to see updated values
				finalNode, err := db.GetNodeByID(12)
				require.NoError(t, err)
				assert.Equal(t, user.ID, finalNode.UserID)
				assert.Equal(t, user.Name, finalNode.User.Name)
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
