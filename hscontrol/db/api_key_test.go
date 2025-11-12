package db

import (
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gopkg.in/check.v1"
)

func (*Suite) TestCreateAPIKey(c *check.C) {
	apiKeyStr, apiKey, err := db.CreateAPIKey(nil)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey, check.NotNil)

	// Did we get a valid key?
	c.Assert(apiKey.Prefix, check.NotNil)
	c.Assert(apiKey.Hash, check.NotNil)
	c.Assert(apiKeyStr, check.Not(check.Equals), "")

	_, err = db.ListAPIKeys()
	c.Assert(err, check.IsNil)

	keys, err := db.ListAPIKeys()
	c.Assert(err, check.IsNil)
	c.Assert(len(keys), check.Equals, 1)
}

func (*Suite) TestAPIKeyDoesNotExist(c *check.C) {
	key, err := db.GetAPIKey("does-not-exist")
	c.Assert(err, check.NotNil)
	c.Assert(key, check.IsNil)
}

func (*Suite) TestValidateAPIKeyOk(c *check.C) {
	nowPlus2 := time.Now().Add(2 * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowPlus2)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey, check.NotNil)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	c.Assert(err, check.IsNil)
	c.Assert(valid, check.Equals, true)
}

func (*Suite) TestValidateAPIKeyNotOk(c *check.C) {
	nowMinus2 := time.Now().Add(time.Duration(-2) * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowMinus2)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey, check.NotNil)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	c.Assert(err, check.IsNil)
	c.Assert(valid, check.Equals, false)

	now := time.Now()
	apiKeyStrNow, apiKey, err := db.CreateAPIKey(&now)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey, check.NotNil)

	validNow, err := db.ValidateAPIKey(apiKeyStrNow)
	c.Assert(err, check.IsNil)
	c.Assert(validNow, check.Equals, false)

	validSilly, err := db.ValidateAPIKey("nota.validkey")
	c.Assert(err, check.NotNil)
	c.Assert(validSilly, check.Equals, false)

	validWithErr, err := db.ValidateAPIKey("produceerrorkey")
	c.Assert(err, check.NotNil)
	c.Assert(validWithErr, check.Equals, false)
}

func (*Suite) TestExpireAPIKey(c *check.C) {
	nowPlus2 := time.Now().Add(2 * time.Hour)
	apiKeyStr, apiKey, err := db.CreateAPIKey(&nowPlus2)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey, check.NotNil)

	valid, err := db.ValidateAPIKey(apiKeyStr)
	c.Assert(err, check.IsNil)
	c.Assert(valid, check.Equals, true)

	err = db.ExpireAPIKey(apiKey)
	c.Assert(err, check.IsNil)
	c.Assert(apiKey.Expiration, check.NotNil)

	notValid, err := db.ValidateAPIKey(apiKeyStr)
	c.Assert(err, check.IsNil)
	c.Assert(notValid, check.Equals, false)
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
