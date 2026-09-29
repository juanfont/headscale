package state

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
)

// TestNewStatePrunesOIDCGroupMemberships checks that a configuration change
// revokes OIDC group access at startup rather than at each user's next login:
// disabling sync removes every OIDC membership, and changing the domain
// removes those outside it. Memberships from other sources are kept.
func TestNewStatePrunesOIDCGroupMemberships(t *testing.T) {
	const other types.GroupSource = "other"

	tests := []struct {
		name   string
		groups types.OIDCGroupsConfig
		want   []string
	}{
		{
			name:   "enabled keeps the configured domain",
			groups: types.OIDCGroupsConfig{Enabled: true, Claim: "groups", Domain: "example.com"},
			want:   []string{"eng@example.com", "hr@old.example"},
		},
		{
			name:   "disabled removes all oidc memberships",
			groups: types.OIDCGroupsConfig{Claim: "groups", Domain: "example.com"},
			want:   []string{"hr@old.example"},
		},
		{
			name:   "domain change removes the old domain",
			groups: types.OIDCGroupsConfig{Enabled: true, Claim: "groups", Domain: "new.example"},
			want:   []string{"hr@old.example"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := persistTestConfig(t.TempDir() + "/headscale.db")

			database, err := db.NewHeadscaleDatabase(cfg)
			require.NoError(t, err)

			uid := types.UserID(database.CreateUserForTest("alice").ID)

			_, err = db.Write(database.DB, func(tx *gorm.DB) (bool, error) {
				_, err := db.SetUserGroups(tx, uid, types.GroupSourceOIDC, []string{"eng@example.com"})
				if err != nil {
					return false, err
				}

				return db.SetUserGroups(tx, uid, other, []string{"hr@old.example"})
			})
			require.NoError(t, err)
			require.NoError(t, database.Close())

			cfg.OIDC.Groups = tt.groups

			s, err := NewState(cfg)
			require.NoError(t, err)
			t.Cleanup(func() { _ = s.Close() })

			user, err := s.GetUserByID(uid)
			require.NoError(t, err)
			assert.Equal(t, tt.want, user.GroupNames())
		})
	}
}

// TestSetUserGroupsReportsPolicyChange checks that a membership change the
// policy references produces a change to broadcast, and that re-asserting the
// same memberships does not.
func TestSetUserGroupsReportsPolicyChange(t *testing.T) {
	cfg := persistTestConfig(t.TempDir() + "/headscale.db")

	database, err := db.NewHeadscaleDatabase(cfg)
	require.NoError(t, err)

	user := database.CreateUserForTest("alice")
	database.CreateRegisteredNodeForTest(user, "alice-node")
	require.NoError(t, database.Close())

	s, err := NewState(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { _ = s.Close() })

	_, err = s.SetPolicy([]byte(`{
		"acls": [{"action": "accept", "src": ["group:eng@example.com"], "dst": ["*:22"]}]
	}`))
	require.NoError(t, err)

	uid := types.UserID(user.ID)

	c, err := s.SetUserGroups(uid, types.GroupSourceOIDC, []string{"eng@example.com"})
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "gaining a referenced group must broadcast a change")

	c, err = s.SetUserGroups(uid, types.GroupSourceOIDC, []string{"eng@example.com"})
	require.NoError(t, err)
	assert.True(t, c.IsEmpty(), "unchanged memberships must not broadcast")

	nodes := s.ListNodesByUser(uid)
	require.Equal(t, 1, nodes.Len())
	assert.Equal(t, []string{"eng@example.com"}, nodes.At(0).User().GroupNames(),
		"the node's copy of its user must show the current groups")

	c, err = s.SetUserGroups(uid, types.GroupSourceOIDC, nil)
	require.NoError(t, err)
	assert.False(t, c.IsEmpty(), "losing a referenced group must broadcast a change")
	assert.Empty(t, s.ListNodesByUser(uid).At(0).User().GroupNames())
}
