package db

import (
	"encoding/base64"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
)

// legacyArgon2idHash builds a PHC-encoded Argon2id hash in the form development
// builds stored secrets before the switch to SHA-256.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func legacyArgon2idHash(secret string, memory, time uint32, threads uint8) []byte {
	salt := []byte("0123456789abcdef")
	sum := argon2.IDKey([]byte(secret), salt, time, memory, threads, argon2KeyLen)

	return fmt.Appendf(nil, "$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, memory, time, threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(sum),
	)
}

func TestVerifySecret(t *testing.T) {
	const secret = "s3cr3t"

	bcryptHash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
	require.NoError(t, err)

	tests := []struct {
		name        string
		hash        []byte
		wantRehash  bool
		wantErr     error
		wrongSecret bool
	}{
		{name: "sha256", hash: hashSecret(secret)},
		{name: "sha256 wrong secret", hash: hashSecret(secret), wrongSecret: true, wantErr: errSecretMismatch},
		// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
		{name: "argon2id legacy", hash: legacyArgon2idHash(secret, 19*1024, 2, 1), wantRehash: true},
		{name: "argon2id wrong secret", hash: legacyArgon2idHash(secret, 19*1024, 2, 1), wrongSecret: true, wantErr: errSecretMismatch},
		{name: "bcrypt legacy", hash: bcryptHash, wantRehash: true},
		{name: "bcrypt wrong secret", hash: bcryptHash, wrongSecret: true, wantErr: errSecretMismatch},
		{name: "nil hash", hash: nil, wantErr: errSecretHashMalformed},
		{name: "garbage", hash: []byte("not-a-hash"), wantErr: errSecretHashMalformed},
		{name: "truncated bcrypt", hash: bcryptHash[:20], wantErr: errSecretHashMalformed},
		{name: "sha256 bad hex", hash: []byte("$sha256$zz"), wantErr: errSecretHashMalformed},
		// Parameters argon2 would panic on, or that would allocate unbounded
		// memory, must be rejected before hashing.
		{name: "argon2id t=0", hash: []byte("$argon2id$v=19$m=19456,t=0,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), wantErr: errSecretHashMalformed},
		{name: "argon2id p=0", hash: []byte("$argon2id$v=19$m=19456,t=2,p=0$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), wantErr: errSecretHashMalformed},
		{name: "argon2id huge memory", hash: []byte("$argon2id$v=19$m=4294967295,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"), wantErr: errSecretHashMalformed},
		{name: "argon2id empty key", hash: []byte("$argon2id$v=19$m=19456,t=2,p=1$MDEyMzQ1Njc4OWFiY2RlZg$"), wantErr: errSecretHashMalformed},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			presented := secret
			if tt.wrongSecret {
				presented = "wrong"
			}

			needsRehash, err := verifySecret(tt.hash, presented)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)
				assert.False(t, needsRehash)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.wantRehash, needsRehash)
		})
	}

	// A malformed hash must not leak a limiter slot: after more failures than
	// the limiter holds, a legacy verify still completes.
	for range cap(legacyHashLimiter) + 1 {
		_, _ = verifySecret([]byte("$argon2id$v=19$m=19456,t=0,p=1$MDEyMzQ1Njc4OWFiY2RlZg$AAAA"), secret)
	}

	_, err = verifySecret(bcryptHash, secret)
	require.NoError(t, err)
}

// TestVerifySecretConcurrent runs more concurrent legacy verifications than the
// limiter admits, asserting it releases correctly (no deadlock) and stays
// correct under contention. Run with -race.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func TestVerifySecretConcurrent(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.MinCost)
	require.NoError(t, err)

	const n = 64

	var wg sync.WaitGroup

	errs := make([]error, n)

	for i := range n {
		wg.Go(func() {
			if i%2 == 0 {
				_, errs[i] = verifySecret(hash, "s3cr3t")
			} else {
				_, errs[i] = verifySecret(hash, "wrong")
			}
		})
	}

	wg.Wait()

	for i, e := range errs {
		if i%2 == 0 {
			assert.NoError(t, e, "correct secret must verify")
		} else {
			assert.ErrorIs(t, e, errSecretMismatch, "wrong secret must fail")
		}
	}
}

// TestGenerateSecret verifies the unified key shape
// <prefix><identifier(12)>-<secret(64)> and that the stored hash verifies the
// secret without needing a rehash.
func TestGenerateSecret(t *testing.T) {
	full, identifier, hash := generateSecret("hskey-test-")

	require.Len(t, identifier, keyIdentifierLength)
	require.True(t, strings.HasPrefix(full, "hskey-test-"+identifier+"-"))

	secret := strings.TrimPrefix(full, "hskey-test-"+identifier+"-")
	require.Len(t, secret, keySecretLength)
	assert.True(t, strings.HasPrefix(string(hash), hashPrefixSHA256))
	assert.NotContains(t, string(hash), secret, "secret must not be stored")

	needsRehash, err := verifySecret(hash, secret)
	require.NoError(t, err)
	require.False(t, needsRehash)
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
	// Only the hash is stored, never the plaintext.
	assert.True(t, strings.HasPrefix(string(client.SecretHash), hashPrefixSHA256))

	// The secret authenticates, deriving the client id from the secret itself.
	got, err := db.AuthenticateOAuthClient(secret)
	require.NoError(t, err)
	assert.Equal(t, client.ClientID, got.ClientID)

	// A truncated/garbage secret does not.
	_, err = db.AuthenticateOAuthClient("hskey-client-deadbeef-nope")
	require.ErrorIs(t, err, ErrOAuthClientFailedToParse)

	// A wrong secret for a real client id reads as an unknown client.
	_, err = db.AuthenticateOAuthClient("hskey-client-" + client.ClientID + "-" + strings.Repeat("0", 64))
	require.ErrorIs(t, err, ErrOAuthClientNotFound)
	require.ErrorIs(t, err, errSecretMismatch)
}

// TestOAuthClientAuthenticateTailscalePrefix asserts the same stored client
// authenticates under the tskey-client- alias, and that only a leading prefix
// is recognised.
func TestOAuthClientAuthenticateTailscalePrefix(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	secret, client, err := db.CreateOAuthClient(
		[]string{"auth_keys"},
		[]string{"tag:ci"},
		"",
		nil,
	)
	require.NoError(t, err)

	rest := strings.TrimPrefix(secret, types.OAuthClientPrefix)
	tsSecret := types.TailscaleOAuthClientPrefix + rest

	for _, s := range []string{
		tsSecret,
		// Callers may pass the raw auth-key form; ?attributes are stripped.
		tsSecret + "?baseURL=http://127.0.0.1:8080&ephemeral=true",
	} {
		got, err := db.AuthenticateOAuthClient(s)
		require.NoError(t, err, s)
		assert.Equal(t, client.ClientID, got.ClientID)
	}

	// A wrong secret under the alias parses but fails verification.
	_, err = db.AuthenticateOAuthClient(
		types.TailscaleOAuthClientPrefix + client.ClientID + "-" + strings.Repeat("0", 64),
	)
	require.Error(t, err)
	require.NotErrorIs(t, err, ErrOAuthClientFailedToParse)

	for _, s := range []string{
		types.TailscaleOAuthClientPrefix,
		"tskey-auth-" + rest,
		"tskey-" + rest,
		"junk-" + tsSecret,
		"junk-" + secret,
		types.TailscaleOAuthClientPrefix + secret,
	} {
		_, err := db.AuthenticateOAuthClient(s)
		require.ErrorIs(t, err, ErrOAuthClientFailedToParse, s)
	}
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

	// Expired credentials of other kinds share the table; the reaper must
	// leave them alone.
	apiKeyStr, _, err := db.CreateAPIKey(&past)
	require.NoError(t, err)

	pak, err := db.CreatePreAuthKey(nil, false, false, &past, []string{"tag:ci"})
	require.NoError(t, err)

	// The reaper deletes the expired token row; the live token is untouched.
	n, err := db.DeleteExpiredAccessTokens(time.Now())
	require.NoError(t, err)
	assert.Equal(t, int64(1), n)

	_ = token

	_, err = db.AuthenticateAPIKey(apiKeyStr)
	require.ErrorIs(t, err, ErrAPIKeyExpired, "expired API key must survive the token reaper")

	_, err = db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err, "expired pre-auth key must survive the token reaper")

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
	require.NoError(t, db.DB.Where("kind = ? AND identifier = ?", types.CredentialOAuthClient, client.ClientID).Delete(&types.Credential{}).Error)

	_, err = db.AuthenticateAccessToken(tokenStr)
	require.ErrorIs(t, err, ErrAccessTokenClientRevoked)

	// A soft-revoked client (row present, Revoked set) is likewise rejected.
	_, client2, err := db.CreateOAuthClient([]string{"auth_keys"}, []string{"tag:ci"}, "", nil)
	require.NoError(t, err)

	tokenStr2, _, err := db.MintAccessToken(client2.ClientID, []string{"auth_keys"}, []string{"tag:ci"}, &future)
	require.NoError(t, err)

	now := time.Now()
	require.NoError(t, db.DB.Model(&types.Credential{}).
		Where("kind = ? AND identifier = ?", types.CredentialOAuthClient, client2.ClientID).Update("revoked", now).Error)

	_, err = db.AuthenticateAccessToken(tokenStr2)
	require.ErrorIs(t, err, ErrAccessTokenClientRevoked)
}

// TestOAuthClientCreateRejectsUnknownScopes asserts scopes are validated against
// the known vocabulary the same way tags are, instead of being stored verbatim.
func TestOAuthClientCreateRejectsUnknownScopes(t *testing.T) {
	tests := []struct {
		name   string
		scopes []string
		valid  bool
	}{
		{name: "known write and read scopes", scopes: []string{"auth_keys", "devices:core:read"}, valid: true},
		{name: "super scopes", scopes: []string{"all", "all:read"}, valid: true},
		{name: "arbitrary scope", scopes: []string{"EVIL:superuser"}},
		{name: "path traversal", scopes: []string{"../../etc/passwd"}},
		{name: "wildcard", scopes: []string{"*::*"}},
		{name: "empty scope", scopes: []string{""}},
		{name: "wrong case", scopes: []string{"AUTH_KEYS"}},
		{name: "one unknown among known", scopes: []string{"auth_keys", "devices:everything"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)

			_, client, err := db.CreateOAuthClient(tt.scopes, []string{"tag:ci"}, "", nil)
			if tt.valid {
				require.NoError(t, err)
				assert.ElementsMatch(t, tt.scopes, client.Scopes)

				return
			}

			require.ErrorIs(t, err, ErrOAuthClientScopeInvalid)
			assert.Nil(t, client)

			clients, err := db.ListOAuthClients()
			require.NoError(t, err)
			assert.Empty(t, clients, "rejected client must not be stored")
		})
	}
}

// TestOAuthClientCreateReportsEveryUnknownScope asserts validation does not stop
// at the first bad scope, so a caller can fix them all in one pass.
func TestOAuthClientCreateReportsEveryUnknownScope(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, _, err = db.CreateOAuthClient(
		[]string{"auth_keys", "devices:everything", "EVIL:superuser"},
		[]string{"tag:ci"},
		"",
		nil,
	)
	require.ErrorIs(t, err, ErrOAuthClientScopeInvalid)
	assert.Contains(t, err.Error(), "devices:everything")
	assert.Contains(t, err.Error(), "EVIL:superuser")
}
