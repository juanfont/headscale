package db

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/ptr"
)

func TestCreatePreAuthKey(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "error_invalid_user_id",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				_, err := db.CreatePreAuthKey(12345, true, false, nil, nil)
				assert.Error(t, err)
			},
		},
		{
			name: "success_create_and_list",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				key, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
				require.NoError(t, err)
				assert.NotEmpty(t, key.Key)

				// List keys for the user
				keys, err := db.ListPreAuthKeys(types.UserID(user.ID))
				require.NoError(t, err)
				assert.Len(t, keys, 1)

				// Verify User association is populated
				assert.Equal(t, user.ID, keys[0].User.ID)
			},
		},
		{
			name: "error_list_invalid_user_id",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				_, err := db.ListPreAuthKeys(1000000)
				assert.Error(t, err)
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

func TestPreAuthKeyACLTags(t *testing.T) {
	tests := []struct {
		name string
		test func(*testing.T, *HSDatabase)
	}{
		{
			name: "reject_malformed_tags",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test-tags-1"})
				require.NoError(t, err)

				_, err = db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, []string{"badtag"})
				assert.Error(t, err)
			},
		},
		{
			name: "deduplicate_and_sort_tags",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test-tags-2"})
				require.NoError(t, err)

				expectedTags := []string{"tag:test1", "tag:test2"}
				tagsWithDuplicate := []string{"tag:test1", "tag:test2", "tag:test2"}

				_, err = db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, tagsWithDuplicate)
				require.NoError(t, err)

				listedPaks, err := db.ListPreAuthKeys(types.UserID(user.ID))
				require.NoError(t, err)
				require.Len(t, listedPaks, 1)

				gotTags := listedPaks[0].Proto().GetAclTags()
				slices.Sort(gotTags)
				assert.Equal(t, expectedTags, gotTags)
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

func TestCannotDeleteAssignedPreAuthKey(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)
	user, err := db.CreateUser(types.User{Name: "test8"})
	require.NoError(t, err)

	key, err := db.CreatePreAuthKey(types.UserID(user.ID), false, false, nil, []string{"tag:good"})
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		Hostname:       "testest",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      ptr.To(key.ID),
	}
	db.DB.Save(&node)

	err = db.DB.Delete(&types.PreAuthKey{ID: key.ID}).Error
	require.ErrorContains(t, err, "constraint failed: FOREIGN KEY constraint failed")
}

func TestPreAuthKeyAuthentication(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test-user")

	tests := []struct {
		name            string
		setupKey        func() string // Returns key string to test
		wantFindErr     bool          // Error when finding the key
		wantValidateErr bool          // Error when validating the key
		validateResult  func(*testing.T, *types.PreAuthKey)
	}{
		{
			name: "legacy_key_plaintext",
			setupKey: func() string {
				// Insert legacy key directly using GORM (simulate existing production key)
				// Note: We use raw SQL to bypass GORM's handling and set prefix to empty string
				// which simulates how legacy keys exist in production databases
				legacyKey := "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
				now := time.Now()

				// Use raw SQL to insert with empty prefix to avoid UNIQUE constraint
				err := db.DB.Exec(`
					INSERT INTO pre_auth_keys (key, user_id, reusable, ephemeral, used, created_at)
					VALUES (?, ?, ?, ?, ?, ?)
				`, legacyKey, user.ID, true, false, false, now).Error
				require.NoError(t, err)

				return legacyKey
			},
			wantFindErr:     false,
			wantValidateErr: false,
			validateResult: func(t *testing.T, pak *types.PreAuthKey) {
				t.Helper()

				assert.Equal(t, user.ID, pak.UserID)
				assert.NotEmpty(t, pak.Key) // Legacy keys have Key populated
				assert.Empty(t, pak.Prefix) // Legacy keys have empty Prefix
				assert.Nil(t, pak.Hash)     // Legacy keys have nil Hash
			},
		},
		{
			name: "new_key_bcrypt",
			setupKey: func() string {
				// Create new key via API
				keyStr, err := db.CreatePreAuthKey(
					types.UserID(user.ID),
					true, false, nil, []string{"tag:test"},
				)
				require.NoError(t, err)

				return keyStr.Key
			},
			wantFindErr:     false,
			wantValidateErr: false,
			validateResult: func(t *testing.T, pak *types.PreAuthKey) {
				t.Helper()

				assert.Equal(t, user.ID, pak.UserID)
				assert.Empty(t, pak.Key)       // New keys have empty Key
				assert.NotEmpty(t, pak.Prefix) // New keys have Prefix
				assert.NotNil(t, pak.Hash)     // New keys have Hash
				assert.Len(t, pak.Prefix, 12)  // Prefix is 12 chars
			},
		},
		{
			name: "new_key_format_validation",
			setupKey: func() string {
				keyStr, err := db.CreatePreAuthKey(
					types.UserID(user.ID),
					true, false, nil, nil,
				)
				require.NoError(t, err)

				// Verify format: hskey-auth-{12-char-prefix}-{64-char-hash}
				// Use fixed-length parsing since prefix/hash can contain dashes (base64 URL-safe)
				assert.True(t, strings.HasPrefix(keyStr.Key, "hskey-auth-"))

				// Extract prefix and hash using fixed-length parsing like the real code does
				_, prefixAndHash, found := strings.Cut(keyStr.Key, "hskey-auth-")
				assert.True(t, found)
				assert.GreaterOrEqual(t, len(prefixAndHash), 12+1+64) // prefix + '-' + hash minimum

				prefix := prefixAndHash[:12]
				assert.Len(t, prefix, 12)                     // Prefix is 12 chars
				assert.Equal(t, byte('-'), prefixAndHash[12]) // Separator
				hash := prefixAndHash[13:]
				assert.Len(t, hash, 64) // Hash is 64 chars

				return keyStr.Key
			},
			wantFindErr:     false,
			wantValidateErr: false,
		},
		{
			name: "invalid_bcrypt_hash",
			setupKey: func() string {
				// Create valid key
				key, err := db.CreatePreAuthKey(
					types.UserID(user.ID),
					true, false, nil, nil,
				)
				require.NoError(t, err)

				keyStr := key.Key

				// Return key with tampered hash using fixed-length parsing
				_, prefixAndHash, _ := strings.Cut(keyStr, "hskey-auth-")
				prefix := prefixAndHash[:12]

				return "hskey-auth-" + prefix + "-" + "wrong_hash_here_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "empty_key",
			setupKey: func() string {
				return ""
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "key_too_short",
			setupKey: func() string {
				return "hskey-auth-short"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "missing_separator",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKLabcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOPQRSTUVWXYZ"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "hash_too_short",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKL-short"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "prefix_with_invalid_chars",
			setupKey: func() string {
				return "hskey-auth-ABC$EF@HIJKL-" + strings.Repeat("a", 64)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "hash_with_invalid_chars",
			setupKey: func() string {
				return "hskey-auth-ABCDEFGHIJKL-" + "invalid$chars" + strings.Repeat("a", 54)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "prefix_not_found_in_db",
			setupKey: func() string {
				// Create a validly formatted key but with a prefix that doesn't exist
				return "hskey-auth-NotInDB12345-" + strings.Repeat("a", 64)
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "expired_legacy_key",
			setupKey: func() string {
				legacyKey := "expired_legacy_key_123456789012345678901234"
				now := time.Now()
				expiration := time.Now().Add(-1 * time.Hour) // Expired 1 hour ago

				// Use raw SQL to avoid UNIQUE constraint on empty prefix
				err := db.DB.Exec(`
					INSERT INTO pre_auth_keys (key, user_id, reusable, ephemeral, used, created_at, expiration)
					VALUES (?, ?, ?, ?, ?, ?, ?)
				`, legacyKey, user.ID, true, false, false, now, expiration).Error
				require.NoError(t, err)

				return legacyKey
			},
			wantFindErr:     false,
			wantValidateErr: true,
		},
		{
			name: "used_single_use_legacy_key",
			setupKey: func() string {
				legacyKey := "used_legacy_key_123456789012345678901234567"
				now := time.Now()

				// Use raw SQL to avoid UNIQUE constraint on empty prefix
				err := db.DB.Exec(`
					INSERT INTO pre_auth_keys (key, user_id, reusable, ephemeral, used, created_at)
					VALUES (?, ?, ?, ?, ?, ?)
				`, legacyKey, user.ID, false, false, true, now).Error
				require.NoError(t, err)

				return legacyKey
			},
			wantFindErr:     false,
			wantValidateErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keyStr := tt.setupKey()

			pak, err := db.GetPreAuthKey(keyStr)

			if tt.wantFindErr {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.NotNil(t, pak)

			// Check validation if needed
			if tt.wantValidateErr {
				err := pak.Validate()
				assert.Error(t, err)

				return
			}

			if tt.validateResult != nil {
				tt.validateResult(t, pak)
			}
		})
	}
}

func TestMultipleLegacyKeysAllowed(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test-legacy"})
	require.NoError(t, err)

	// Create multiple legacy keys by directly inserting with empty prefix
	// This simulates the migration scenario where existing databases have multiple
	// plaintext keys without prefix/hash fields
	now := time.Now()

	for i := range 5 {
		legacyKey := fmt.Sprintf("legacy_key_%d_%s", i, strings.Repeat("x", 40))

		err := db.DB.Exec(`
			INSERT INTO pre_auth_keys (key, prefix, hash, user_id, reusable, ephemeral, used, created_at)
			VALUES (?, '', NULL, ?, ?, ?, ?, ?)
		`, legacyKey, user.ID, true, false, false, now).Error
		require.NoError(t, err, "should allow multiple legacy keys with empty prefix")
	}

	// Verify all legacy keys can be retrieved
	var legacyKeys []types.PreAuthKey

	err = db.DB.Where("prefix = '' OR prefix IS NULL").Find(&legacyKeys).Error
	require.NoError(t, err)
	assert.Len(t, legacyKeys, 5, "should have created 5 legacy keys")

	// Now create new bcrypt-based keys - these should have unique prefixes
	key1, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, key1.Key)

	key2, err := db.CreatePreAuthKey(types.UserID(user.ID), true, false, nil, nil)
	require.NoError(t, err)
	assert.NotEmpty(t, key2.Key)

	// Verify the new keys have different prefixes
	pak1, err := db.GetPreAuthKey(key1.Key)
	require.NoError(t, err)
	assert.NotEmpty(t, pak1.Prefix)

	pak2, err := db.GetPreAuthKey(key2.Key)
	require.NoError(t, err)
	assert.NotEmpty(t, pak2.Prefix)

	assert.NotEqual(t, pak1.Prefix, pak2.Prefix, "new keys should have unique prefixes")

	// Verify we cannot manually insert duplicate non-empty prefixes
	duplicatePrefix := "test_prefix1"
	hash1 := []byte("hash1")
	hash2 := []byte("hash2")

	// First insert should succeed
	err = db.DB.Exec(`
		INSERT INTO pre_auth_keys (key, prefix, hash, user_id, reusable, ephemeral, used, created_at)
		VALUES ('', ?, ?, ?, ?, ?, ?, ?)
	`, duplicatePrefix, hash1, user.ID, true, false, false, now).Error
	require.NoError(t, err, "first key with prefix should succeed")

	// Second insert with same prefix should fail
	err = db.DB.Exec(`
		INSERT INTO pre_auth_keys (key, prefix, hash, user_id, reusable, ephemeral, used, created_at)
		VALUES ('', ?, ?, ?, ?, ?, ?, ?)
	`, duplicatePrefix, hash2, user.ID, true, false, false, now).Error
	require.Error(t, err, "duplicate non-empty prefix should be rejected")
	assert.Contains(t, err.Error(), "UNIQUE constraint failed", "should fail with UNIQUE constraint error")
}
