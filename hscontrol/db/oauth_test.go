package db

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestVerifySecretConcurrent runs more concurrent verifications than the Argon2
// concurrency semaphore admits, asserting the limiter releases correctly (no
// deadlock) and stays correct under contention. Run with -race.
func TestVerifySecretConcurrent(t *testing.T) {
	hash, err := hashSecret("s3cr3t")
	require.NoError(t, err)

	const n = 64

	var wg sync.WaitGroup

	errs := make([]error, n)

	for i := range n {
		wg.Add(1)

		go func(i int) {
			defer wg.Done()

			if i%2 == 0 {
				errs[i] = verifySecret(hash, "s3cr3t")
			} else {
				errs[i] = verifySecret(hash, "wrong")
			}
		}(i)
	}

	wg.Wait()

	for i, e := range errs {
		if i%2 == 0 {
			assert.NoError(t, e, "correct secret must verify")
		} else {
			assert.Error(t, e, "wrong secret must fail")
		}
	}
}

func TestOAuthClientCreateAndAuthenticate(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	secret, client, err := db.CreateOAuthClient(
		[]string{"auth_keys", "devices:core"},
		[]string{"tag:ci"},
		"my client",
		nil,
	)
	require.NoError(t, err)
	require.NotNil(t, client)

	// Secret carries the public client id as its middle segment, so it can be
	// derived from the secret alone (the Tailscale get-authkey trick).
	assert.True(t, strings.HasPrefix(secret, "hskey-client-"+client.ClientID+"-"))
	// Scopes/tags are deduplicated and sorted for stable storage.
	assert.Equal(t, []string{"auth_keys", "devices:core"}, client.Scopes)
	assert.Equal(t, []string{"tag:ci"}, client.Tags)
	// Only the Argon2id hash is stored, never the plaintext.
	assert.NotEmpty(t, client.SecretHash)
	assert.True(t, strings.HasPrefix(string(client.SecretHash), "$argon2id$"))

	// The secret authenticates, deriving the client id from the secret itself.
	got, err := db.AuthenticateOAuthClient(secret)
	require.NoError(t, err)
	assert.Equal(t, client.ClientID, got.ClientID)

	// A truncated/garbage secret does not.
	_, err = db.AuthenticateOAuthClient("hskey-client-deadbeef-nope")
	require.Error(t, err)

	// Wrong secret for a real client id is rejected by the constant-time compare.
	_, err = db.AuthenticateOAuthClient("hskey-client-" + client.ClientID + "-" + strings.Repeat("0", 64))
	require.Error(t, err)
}

func TestHashSecretRoundTrip(t *testing.T) {
	const secret = "a-high-entropy-credential-secret"

	encoded, err := hashSecret(secret)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(encoded), "$argon2id$v="))

	// The same secret hashes to a different value each time (random salt) yet
	// still verifies.
	encoded2, err := hashSecret(secret)
	require.NoError(t, err)
	assert.NotEqual(t, encoded, encoded2)

	require.NoError(t, verifySecret(encoded, secret))
	require.ErrorIs(t, verifySecret(encoded, "wrong-secret"), errSecretMismatch)
	require.ErrorIs(t, verifySecret([]byte("not-a-phc-string"), secret), errSecretHashMalformed)
}

func TestOAuthClientRevoke(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	secret, client, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	// A token minted by the client survives only until the client is revoked.
	_, _, err = db.MintAccessToken(client.ClientID, client.Scopes, client.Tags, nil)
	require.NoError(t, err)

	require.NoError(t, db.RevokeOAuthClient(client.ClientID))

	// The client no longer authenticates and a repeated revoke is a clean 404.
	_, err = db.AuthenticateOAuthClient(secret)
	require.Error(t, err)
	require.ErrorIs(t, db.RevokeOAuthClient(client.ClientID), ErrOAuthClientNotFound)
}

func TestOAuthAccessTokenMintAuthenticateExpire(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, client, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)
	tokenStr, token, err := db.MintAccessToken(
		client.ClientID,
		[]string{"auth_keys"},
		[]string{"tag:ci"},
		&future,
	)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(tokenStr, "hskey-oauthtok-"))

	got, err := db.AuthenticateAccessToken(tokenStr)
	require.NoError(t, err)
	assert.Equal(t, client.ClientID, got.ClientID)
	assert.Equal(t, []string{"auth_keys"}, got.Scopes)
	assert.Equal(t, []string{"tag:ci"}, got.Tags)

	// An expired token is rejected even though the row still exists.
	past := time.Now().Add(-time.Hour)
	expiredStr, _, err := db.MintAccessToken(client.ClientID, nil, nil, &past)
	require.NoError(t, err)
	_, err = db.AuthenticateAccessToken(expiredStr)
	require.ErrorIs(t, err, ErrAccessTokenExpired)

	// The reaper deletes the expired row; the live token is untouched.
	n, err := db.DeleteExpiredAccessTokens(time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	_ = token

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.NoError(t, err)
}

// TestAccessTokenRejectedWhenClientGone asserts a token whose issuing client no
// longer exists (orphaned by a delete/revoke race) is rejected, even though the
// token row itself is valid and unexpired.
func TestAccessTokenRejectedWhenClientGone(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, client, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	future := time.Now().Add(time.Hour)
	tokenStr, _, err := db.MintAccessToken(client.ClientID, []string{"auth_keys"}, []string{"tag:ci"}, &future)
	require.NoError(t, err)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.NoError(t, err)

	// Delete only the client row, leaving the token orphaned (the state a
	// mint/revoke race or manual deletion would produce).
	require.NoError(t, db.DB.Where("client_id = ?", client.ClientID).Delete(&types.OAuthClient{}).Error)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.ErrorIs(t, err, ErrAccessTokenClientRevoked)

	// A soft-revoked client (row present, Revoked set) is likewise rejected.
	_, client2, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	tokenStr2, _, err := db.MintAccessToken(client2.ClientID, []string{"auth_keys"}, []string{"tag:ci"}, &future)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, db.DB.Model(&types.OAuthClient{}).
		Where("client_id = ?", client2.ClientID).Update("revoked", now).Error)

	_, err = db.AuthenticateAccessToken(tokenStr2)
	require.ErrorIs(t, err, ErrAccessTokenClientRevoked)
}
