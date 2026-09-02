package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newStateWithUserAndNode returns a started State holding one user who owns one
// registered node, which is what makes the NodeStore staleness observable.
func newStateWithUserAndNode(t *testing.T) (*State, types.UserID, types.NodeID) {
	t.Helper()

	const userName = "vika"

	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest(userName)
	node := database.CreateRegisteredNodeForTest(user, userName+"-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	return s, types.UserID(user.ID), node.ID
}

// TestSetUserProfilePropagatesToNodeStore is the load-bearing test for the
// feature: types.Node embeds its owning types.User, and the mapper reads the
// owner from the NodeStore snapshot rather than the database. If the write path
// only updated the database row, a new avatar would never reach an
// already-connected client, which is the entire point of the feature.
func TestSetUserProfilePropagatesToNodeStore(t *testing.T) {
	s, userID, nodeID := newStateWithUserAndNode(t)

	_, c, err := s.SetUserProfile(userID, types.UserProfileUpdate{
		DisplayName:   new("Vika"),
		ProfilePicURL: new("https://example.com/vika.png"),
	})
	require.NoError(t, err)

	// A full update is what carries MapResponse.UserProfiles, so anything less
	// leaves connected clients showing the old profile.
	assert.True(t, c.IsFull(),
		"a visible profile change must produce a full update, got %+v", c)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)

	owner := node.Owner()
	require.True(t, owner.Valid())
	assert.Equal(t, "Vika", owner.DisplayName())
	assert.Equal(t, "https://example.com/vika.png", owner.ProfilePicURL())

	// The value the client actually receives.
	profile := owner.TailscaleUserProfile()
	assert.Equal(t, "Vika", profile.DisplayName)
	assert.Equal(t, "https://example.com/vika.png", profile.ProfilePicURL)
}

// TestSetUserProfileClearsFields proves an explicit empty string removes a
// value. GORM's struct-based Updates skips zero values, so without the
// column-map write path an avatar could be set but never removed.
func TestSetUserProfileClearsFields(t *testing.T) {
	s, userID, nodeID := newStateWithUserAndNode(t)

	_, _, err := s.SetUserProfile(userID, types.UserProfileUpdate{
		DisplayName:   new("Vika"),
		ProfilePicURL: new("https://example.com/vika.png"),
	})
	require.NoError(t, err)

	// Clear the picture, leave the display name alone.
	user, _, err := s.SetUserProfile(userID, types.UserProfileUpdate{
		ProfilePicURL: new(""),
	})
	require.NoError(t, err)
	assert.Empty(t, user.ProfilePicURL)
	assert.Equal(t, "Vika", user.DisplayName, "an absent field must be untouched")

	stored, err := s.GetUserByID(userID)
	require.NoError(t, err)
	assert.Empty(t, stored.ProfilePicURL)
	assert.Equal(t, "Vika", stored.DisplayName)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Empty(t, node.Owner().ProfilePicURL())
}

// TestSetUserProfileNoVisibleChangeDoesNotBroadcast guards a performance
// regression rather than a correctness one: OIDC re-applies its claims on every
// single login through the same publish path, and sending a full update to every
// node on every login would be expensive.
func TestSetUserProfileNoVisibleChangeDoesNotBroadcast(t *testing.T) {
	s, userID, _ := newStateWithUserAndNode(t)

	_, _, err := s.SetUserProfile(userID, types.UserProfileUpdate{
		DisplayName: new("Vika"),
	})
	require.NoError(t, err)

	// Writing the same value again changes nothing a client can see.
	_, c, err := s.SetUserProfile(userID, types.UserProfileUpdate{
		DisplayName: new("Vika"),
	})
	require.NoError(t, err)
	assert.False(t, c.IsFull(),
		"a write that changes nothing visible must not force a full update, got %+v", c)
}

func TestSetUserProfileErrors(t *testing.T) {
	t.Run("unknown user", func(t *testing.T) {
		s, _, _ := newStateWithUserAndNode(t)

		_, _, err := s.SetUserProfile(99988, types.UserProfileUpdate{
			DisplayName: new("Nobody"),
		})
		assert.ErrorIs(t, err, db.ErrUserNotFound)
	})

	t.Run("empty update", func(t *testing.T) {
		s, userID, _ := newStateWithUserAndNode(t)

		_, _, err := s.SetUserProfile(userID, types.UserProfileUpdate{})
		assert.ErrorIs(t, err, types.ErrEmptyUserProfileUpdate)
	})

	t.Run("invalid picture url", func(t *testing.T) {
		s, userID, _ := newStateWithUserAndNode(t)

		_, _, err := s.SetUserProfile(userID, types.UserProfileUpdate{
			ProfilePicURL: new("not-a-url"),
		})
		assert.ErrorIs(t, err, types.ErrInvalidProfilePicURL)
	})

	t.Run("oidc user", func(t *testing.T) {
		s, userID, _ := newStateWithUserAndNode(t)

		_, _, err := s.UpdateUser(userID, func(u *types.User) error {
			u.Provider = util.RegisterMethodOIDC

			return nil
		})
		require.NoError(t, err)

		_, _, err = s.SetUserProfile(userID, types.UserProfileUpdate{
			DisplayName: new("Manual"),
		})
		assert.ErrorIs(t, err, db.ErrCannotChangeOIDCUser)
	})
}

// TestRenameUserPropagatesToNodeStore covers the same staleness fix on the
// pre-existing rename path: the login name a peer sees comes from the node's
// cached owner too.
func TestRenameUserPropagatesToNodeStore(t *testing.T) {
	s, userID, nodeID := newStateWithUserAndNode(t)

	_, c, err := s.RenameUser(userID, "vika-renamed")
	require.NoError(t, err)
	assert.True(t, c.IsFull(), "a rename must refresh user profiles, got %+v", c)

	node, ok := s.GetNodeByID(nodeID)
	require.True(t, ok)
	assert.Equal(t, "vika-renamed", node.Owner().Name())
	assert.Equal(t, "vika-renamed", node.Owner().TailscaleUserProfile().LoginName)
}
