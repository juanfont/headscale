package db

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// groupsTestDBs runs fn against a fresh SQLite and, when available, Postgres
// database, so the explicit DDL and queries are exercised on both dialects.
func groupsTestDBs(t *testing.T, fn func(t *testing.T, db *HSDatabase)) {
	t.Helper()

	t.Run("sqlite", func(t *testing.T) {
		fn(t, dbForTest(t))
	})
	t.Run("postgres", func(t *testing.T) {
		fn(t, newPostgresTestDB(t))
	})
}

func setUserGroups(t *testing.T, db *HSDatabase, uid types.UserID, source types.GroupSource, groups ...string) bool {
	t.Helper()

	changed, err := Write(db.DB, func(tx *gorm.DB) (bool, error) {
		return SetUserGroups(tx, uid, source, groups)
	})
	require.NoError(t, err)

	return changed
}

func userGroupNames(t *testing.T, db *HSDatabase, uid types.UserID) []string {
	t.Helper()

	u, err := db.GetUserByID(uid)
	require.NoError(t, err)

	return u.GroupNames()
}

func TestSetUserGroups(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		bob := types.UserID(db.CreateUserForTest("bob").ID)

		assert.True(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com", "ops@example.com", "eng@example.com"))
		assert.Equal(t, []string{"eng@example.com", "ops@example.com"}, userGroupNames(t, db, alice))

		// Re-asserting the same set is not a change.
		assert.False(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, "ops@example.com", "eng@example.com"))

		// Groups are shared between users, not duplicated.
		assert.True(t, setUserGroups(t, db, bob, types.GroupSourceOIDC, "eng@example.com"))

		var groupCount int64
		require.NoError(t, db.DB.Model(&types.Group{}).Count(&groupCount).Error)
		assert.EqualValues(t, 2, groupCount)

		// Replacing the set removes memberships the source no longer asserts.
		assert.True(t, setUserGroups(t, db, alice, types.GroupSourceOIDC, "sec@example.com"))
		assert.Equal(t, []string{"sec@example.com"}, userGroupNames(t, db, alice))
		assert.Equal(t, []string{"eng@example.com"}, userGroupNames(t, db, bob))

		// An empty set clears the source's memberships: this is what revokes
		// access when the identity provider removes a user's last group.
		assert.True(t, setUserGroups(t, db, alice, types.GroupSourceOIDC))
		assert.Empty(t, userGroupNames(t, db, alice))
		assert.False(t, setUserGroups(t, db, alice, types.GroupSourceOIDC))
	})
}

func TestSetUserGroupsIsolatesSources(t *testing.T) {
	const other types.GroupSource = "other"

	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)

		setUserGroups(t, db, alice, other, "eng@example.com", "hr@example.com")
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com", "ops@example.com")

		// Clearing one source leaves the other's memberships, including a
		// group both sources assert.
		setUserGroups(t, db, alice, types.GroupSourceOIDC)
		assert.Equal(t, []string{"eng@example.com", "hr@example.com"}, userGroupNames(t, db, alice))
	})
}

func TestUserGroupsPreloaded(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := db.CreateUserForTest("alice")
		node := db.CreateRegisteredNodeForTest(alice, "alice-node")
		setUserGroups(t, db, types.UserID(alice.ID), types.GroupSourceOIDC, "eng@example.com")

		users, err := db.ListUsers(nil)
		require.NoError(t, err)
		require.Len(t, users, 1)
		assert.Equal(t, []string{"eng@example.com"}, users[0].GroupNames())

		byName, err := db.GetUserByName("alice")
		require.NoError(t, err)
		assert.Equal(t, []string{"eng@example.com"}, byName.GroupNames())

		got, err := db.GetNodeByID(node.ID)
		require.NoError(t, err)
		assert.Equal(t, []string{"eng@example.com"}, got.User.GroupNames())
	})
}

// TestUserSaveDoesNotWriteMemberships guards the read-only association: a
// stale in-memory user must never write its memberships back, or a save
// racing a sync could re-grant a revoked group.
func TestUserSaveDoesNotWriteMemberships(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com")

		stale, err := db.GetUserByID(alice)
		require.NoError(t, err)
		require.NotEmpty(t, stale.Memberships)

		setUserGroups(t, db, alice, types.GroupSourceOIDC)

		stale.DisplayName = "Alice"
		require.NoError(t, db.DB.Save(stale).Error)
		require.NoError(t, db.DB.Updates(stale).Error)

		assert.Empty(t, userGroupNames(t, db, alice))
	})
}

func TestDestroyUserCascadesMemberships(t *testing.T) {
	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com")

		require.NoError(t, db.DestroyUser(alice))

		var memberships int64
		require.NoError(t, db.DB.Model(&types.UserGroup{}).Count(&memberships).Error)
		assert.Zero(t, memberships)
	})
}

func TestPruneGroupMemberships(t *testing.T) {
	const other types.GroupSource = "other"

	groupsTestDBs(t, func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice := types.UserID(db.CreateUserForTest("alice").ID)
		setUserGroups(t, db, alice, types.GroupSourceOIDC, "eng@example.com", "eng@old.example")
		setUserGroups(t, db, alice, other, "hr@old.example")

		prune := func(domain string) int64 {
			n, err := Write(db.DB, func(tx *gorm.DB) (int64, error) {
				return PruneGroupMemberships(tx, types.GroupSourceOIDC, domain)
			})
			require.NoError(t, err)

			return n
		}

		// A domain change drops only the source's memberships in other domains.
		assert.EqualValues(t, 1, prune("Example.com"))
		assert.Equal(t, []string{"eng@example.com", "hr@old.example"}, userGroupNames(t, db, alice))
		assert.Zero(t, prune("example.com"))

		// Disabling sync (no domain) drops all of the source's memberships.
		assert.EqualValues(t, 1, prune(""))
		assert.Equal(t, []string{"hr@old.example"}, userGroupNames(t, db, alice))
	})
}
