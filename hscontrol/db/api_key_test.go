package db

import (
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

func TestCreateAPIKey(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	apiKeyStr, apiKey, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	// Did we get a valid key?
	assert.NotNil(t, apiKey.Prefix)
	assert.NotNil(t, apiKey.Hash)
	assert.NotEmpty(t, apiKeyStr)

	_, err = db.ListAPIKeys()
	require.NoError(t, err)

	keys, err := db.ListAPIKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 1)
}

func TestAPIKeyDoesNotExist(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	key, err := db.GetAPIKey("does-not-exist")
	require.Error(t, err)
	assert.Nil(t, key)
}

func TestValidateAPIKeyOk(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	nowPlus2 := time.Now().Add(2 * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowPlus2)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	require.NoError(t, err)
	assert.True(t, valid)
}

func TestValidateAPIKeyNotOk(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	nowMinus2 := time.Now().Add(time.Duration(-2) * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowMinus2)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	require.NoError(t, err)
	assert.False(t, valid)

	now := time.Now()
	apiKeyStrNow, apiKey, err := db.CreateAPIKey(&now)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	validNow, err := db.ValidateAPIKey(apiKeyStrNow)
	require.NoError(t, err)
	assert.False(t, validNow)

	validSilly, err := db.ValidateAPIKey("nota.validkey")
	require.Error(t, err)
	assert.False(t, validSilly)

	validWithErr, err := db.ValidateAPIKey("produceerrorkey")
	require.Error(t, err)
	assert.False(t, validWithErr)
}

func TestExpireAPIKey(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	nowPlus2 := time.Now().Add(2 * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowPlus2)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	require.NoError(t, err)
	assert.True(t, valid)

	err = db.ExpireAPIKey(apiKey)
	require.NoError(t, err)
	assert.NotNil(t, apiKey.Expiration)

	notValid, err := db.ValidateAPIKey(apiKeyStr)
	require.NoError(t, err)
	assert.False(t, notValid)
}

func TestAPIKeyWithPrefix(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "new_key_with_prefix",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				keyStr, apiKey, err := db.CreateAPIKey(nil)
				require.NoError(t, err)

				// Verify format: hskey-api-{12-char-prefix}-{64-char-secret}
				assert.True(t, strings.HasPrefix(keyStr, "hskey-api-"))

				_, prefixAndSecret, found := strings.Cut(keyStr, "hskey-api-")
				assert.True(t, found)
				assert.GreaterOrEqual(t, len(prefixAndSecret), 12+1+64)

				prefix := prefixAndSecret[:12]
				assert.Len(t, prefix, 12)
				assert.Equal(t, byte('-'), prefixAndSecret[12])
				secret := prefixAndSecret[13:]
				assert.Len(t, secret, 64)

				// Verify stored fields
				assert.Len(t, apiKey.Prefix, types.NewAPIKeyPrefixLength)
				assert.NotNil(t, apiKey.Hash)
			},
		},
		{
			name: "new_key_can_be_retrieved",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				keyStr, createdKey, err := db.CreateAPIKey(nil)
				require.NoError(t, err)

				// Validate the created key
				valid, err := db.ValidateAPIKey(keyStr)
				require.NoError(t, err)
				assert.True(t, valid)

				// Verify prefix is correct length
				assert.Len(t, createdKey.Prefix, types.NewAPIKeyPrefixLength)
			},
		},
		{
			name: "invalid_key_format_rejected",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				invalidKeys := []string{
					"",
					"hskey-api-short",
					"hskey-api-ABCDEFGHIJKL-tooshort",
					"hskey-api-ABC$EFGHIJKL-" + strings.Repeat("a", 64),
					"hskey-api-ABCDEFGHIJKL" + strings.Repeat("a", 64), // missing separator
				}

				for _, invalidKey := range invalidKeys {
					valid, err := db.ValidateAPIKey(invalidKey)
					require.Error(t, err, "key should be rejected: %s", invalidKey)
					assert.False(t, valid)
				}
			},
		},
		{
			name: "legacy_key_still_works",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				// Insert legacy API key directly (7-char prefix + 32-char secret)
				legacyPrefix := "abcdefg"
				legacySecret := strings.Repeat("x", 32)
				legacyKey := legacyPrefix + "." + legacySecret
				hash, err := bcrypt.GenerateFromPassword([]byte(legacySecret), bcrypt.DefaultCost)
				require.NoError(t, err)

				now := time.Now()
				err = db.DB.Exec(`
					INSERT INTO api_keys (prefix, hash, created_at)
					VALUES (?, ?, ?)
				`, legacyPrefix, hash, now).Error
				require.NoError(t, err)

				// Validate legacy key
				valid, err := db.ValidateAPIKey(legacyKey)
				require.NoError(t, err)
				assert.True(t, valid)
			},
		},
		{
			name: "wrong_secret_rejected",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				keyStr, _, err := db.CreateAPIKey(nil)
				require.NoError(t, err)

				// Tamper with the secret
				_, prefixAndSecret, _ := strings.Cut(keyStr, "hskey-api-")
				prefix := prefixAndSecret[:12]
				tamperedKey := "hskey-api-" + prefix + "-" + strings.Repeat("x", 64)

				valid, err := db.ValidateAPIKey(tamperedKey)
				require.Error(t, err)
				assert.False(t, valid)
			},
		},
		{
			name: "expired_key_rejected",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				// Create expired key
				expired := time.Now().Add(-1 * time.Hour)
				keyStr, _, err := db.CreateAPIKey(&expired)
				require.NoError(t, err)

				// Should fail validation
				valid, err := db.ValidateAPIKey(keyStr)
				require.NoError(t, err)
				assert.False(t, valid)
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

func TestGetAPIKeyByID(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	// Create an API key
	_, apiKey, err := db.CreateAPIKey(nil)
	require.NoError(t, err)
	require.NotNil(t, apiKey)

	// Retrieve by ID
	retrievedKey, err := db.GetAPIKeyByID(apiKey.ID)
	require.NoError(t, err)
	require.NotNil(t, retrievedKey)
	assert.Equal(t, apiKey.ID, retrievedKey.ID)
	assert.Equal(t, apiKey.Prefix, retrievedKey.Prefix)
}

func TestGetAPIKeyByIDNotFound(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	// Try to get a non-existent key by ID
	key, err := db.GetAPIKeyByID(99999)
	require.Error(t, err)
	assert.Nil(t, key)
}
