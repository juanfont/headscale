package db

import (
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestCredentialsEndAlike: auth keys, API keys and OAuth clients end the same
// way. A revoke refuses the credential at once and keeps its record with the
// first time; a revoke of nothing is the kind's not found; the removal takes
// every kind revoked before its cutoff, and keeps an auth key a node refers
// to.
func TestCredentialsEndAlike(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		user, err := db.CreateUser(types.User{Name: "ends"})
		require.NoError(t, err)

		future := new(time.Now().Add(time.Hour))

		type kind struct {
			name     string
			create   func() (revoke func() error, refused func() error, id uint64)
			notFound func() error
			want     error
		}

		kinds := []kind{
			{
				name: "auth key",
				create: func() (func() error, func() error, uint64) {
					made, err := db.CreatePreAuthKey(user.TypedID(), true, false, future, nil)
					require.NoError(t, err)

					return func() error { return db.RevokePreAuthKey(made.ID) },
						func() error {
							k, err := db.GetPreAuthKey(made.Key)
							require.NoError(t, err)

							return k.Validate()
						}, made.ID
				},
				notFound: func() error { return db.RevokePreAuthKey(99999) },
				want:     ErrPreAuthKeyNotFound,
			},
			{
				name: "API key",
				create: func() (func() error, func() error, uint64) {
					secret, made, err := db.CreateAPIKey(future)
					require.NoError(t, err)

					return func() error { return db.RevokeAPIKey(made.ID) },
						func() error {
							_, err := db.AuthenticateAPIKey(secret)

							return err
						}, made.ID
				},
				notFound: func() error { return db.RevokeAPIKey(99999) },
				want:     ErrAPIKeyNotFound,
			},
			{
				name: "OAuth client",
				create: func() (func() error, func() error, uint64) {
					secret, made, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
					require.NoError(t, err)

					return func() error { return db.RevokeOAuthClient(made.ClientID) },
						func() error {
							_, err := db.AuthenticateOAuthClient(secret)

							return err
						}, made.ID
				},
				notFound: func() error { return db.RevokeOAuthClient("000000000000") },
				want:     ErrOAuthClientNotFound,
			},
		}

		revokedAt := func(id uint64) *time.Time {
			var c types.Credential
			require.NoError(t, db.DB.First(&c, "id = ?", id).Error)

			return c.Revoked
		}

		ids := make([]uint64, 0, len(kinds))

		var latest time.Time

		for _, k := range kinds {
			revoke, refused, id := k.create()
			require.NoError(t, refused(), "%s: valid before the revoke", k.name)
			require.NoError(t, revoke())
			require.Error(t, refused(), "%s: refused at once", k.name)

			first := revokedAt(id)
			require.NotNil(t, first)
			require.Zero(t, first.Nanosecond()%int(time.Microsecond), "%s: microseconds at most", k.name)

			require.NoError(t, revoke(), "%s: a repeated revoke", k.name)
			require.True(t, first.Equal(*revokedAt(id)), "%s: keeps its first time", k.name)

			require.ErrorIs(t, k.notFound(), k.want, k.name)

			ids = append(ids, id)
			latest = *first
		}

		inUse, err := db.CreatePreAuthKey(user.TypedID(), true, false, future, nil)
		require.NoError(t, err)
		require.NoError(t, db.DB.Create(&types.Node{Hostname: "joined", UserID: &user.ID, AuthKeyID: &inUse.ID}).Error)
		require.NoError(t, db.RevokePreAuthKey(inUse.ID))

		removed, err := db.DestroyRevokedCredentialsBefore(time.Now().Add(-time.Hour))
		require.NoError(t, err)
		require.Zero(t, removed, "revoked after the cutoff")

		removed, err = db.DestroyRevokedCredentialsBefore(latest.Add(time.Second))
		require.NoError(t, err)
		require.Equal(t, int64(len(ids)), removed, "every kind")

		for _, id := range ids {
			require.Nil(t, findCredential(t, db, id), "removed")
		}

		require.NotNil(t, revokedAt(inUse.ID), "a node refers to it")
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// findCredential is the credential with id, or nil once it is removed.
func findCredential(t *testing.T, db *HSDatabase, id uint64) *types.Credential {
	t.Helper()

	var cs []types.Credential
	require.NoError(t, db.DB.Find(&cs, "id = ?", id).Error)

	if len(cs) == 0 {
		return nil
	}

	return &cs[0]
}
