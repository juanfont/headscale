package db

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestCredentialTableRoundTrip confirms the unified credentials table is created
// by migration (newSQLiteTestDB validates the schema with squibble) and stores
// and reads back a credential of each kind.
func TestCredentialTableRoundTrip(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	now := time.Now().UTC()
	creds := []types.Credential{
		{Kind: types.CredentialAPIKey, Identifier: "apikey000001", Hash: []byte("h1"), CreatedAt: &now},
		{Kind: types.CredentialPreAuthKey, Identifier: "authkey00001", Hash: []byte("h2"), Reusable: true, Tags: []string{"tag:a"}, CreatedAt: &now},
		{Kind: types.CredentialOAuthClient, Identifier: "client000001", Hash: []byte("h3"), Scopes: []string{"devices:read"}, CreatedAt: &now},
		{Kind: types.CredentialOAuthToken, Identifier: "oauthtok0001", Hash: []byte("h4"), ClientID: "client000001", CreatedAt: &now},
	}

	for i := range creds {
		require.NoError(t, db.DB.Save(&creds[i]).Error)
	}

	var got []types.Credential
	require.NoError(t, db.DB.Order("id").Find(&got).Error)
	require.Len(t, got, 4)
	assert.Equal(t, types.CredentialPreAuthKey, got[1].Kind)
	assert.Equal(t, []string{"tag:a"}, got[1].Tags)
	assert.Equal(t, "client000001", got[3].ClientID)

	// The composite (kind, identifier) index permits the same identifier under a
	// different kind but rejects a duplicate within a kind.
	require.NoError(t, db.DB.Save(&types.Credential{
		Kind: types.CredentialAPIKey, Identifier: "client000001", Hash: []byte("h5"), CreatedAt: &now,
	}).Error)

	err = db.DB.Save(&types.Credential{
		Kind: types.CredentialAPIKey, Identifier: "apikey000001", Hash: []byte("dup"), CreatedAt: &now,
	}).Error
	require.Error(t, err, "duplicate (kind, identifier) must be rejected")
}
