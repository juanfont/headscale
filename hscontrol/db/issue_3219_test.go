package db

import (
	"database/sql"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetUserByNameMatchesOIDCEmail is a regression test for
// https://github.com/juanfont/headscale/issues/3219: "headscale nodes list -u
// <username>" failed for OIDC users. "headscale users list" shows the email as
// the username (User.Username returns the Email for OIDC users), but
// GetUserByName only matched the local Name column, so filtering by the shown
// identifier returned "user not found". This mirrors the policy engine's
// Username.resolveUser, which already matches both Email and Name.
func TestGetUserByNameMatchesOIDCEmail(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	oidcUser := types.User{
		Name:               "alice",
		Email:              "alice@example.com",
		ProviderIdentifier: sql.NullString{String: "https://oidc.example.com/alice", Valid: true},
	}
	require.NoError(t, db.DB.Save(&oidcUser).Error)

	// The email is what "headscale users list" displays for an OIDC user, so
	// filtering by it must resolve the user.
	got, err := db.GetUserByName("alice@example.com")
	require.NoError(t, err)
	assert.Equal(t, oidcUser.ID, got.ID)

	// The local Name still resolves as before.
	got, err = db.GetUserByName("alice")
	require.NoError(t, err)
	assert.Equal(t, oidcUser.ID, got.ID)

	// Unknown identifiers still error out.
	_, err = db.GetUserByName("does-not-exist")
	assert.ErrorIs(t, err, ErrUserNotFound)
}
