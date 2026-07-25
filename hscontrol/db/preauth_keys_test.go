package db

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
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

				_, err := db.CreatePreAuthKey(new(types.UserID(12345)), true, false, nil, nil)
				assert.Error(t, err)
			},
		},
		{
			name: "success_create_and_list",
			test: func(t *testing.T, db *HSDatabase) {
				t.Helper()

				user, err := db.CreateUser(types.User{Name: "test"})
				require.NoError(t, err)

				key, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
				require.NoError(t, err)
				assert.NotEmpty(t, key.Key)

				// List keys for the user
				keys, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				assert.Len(t, keys, 1)

				// Verify User association is populated
				assert.Equal(t, user.ID, keys[0].User.ID)
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

				_, err = db.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"badtag"})
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

				_, err = db.CreatePreAuthKey(user.TypedID(), false, false, nil, tagsWithDuplicate)
				require.NoError(t, err)

				listedPaks, err := db.ListPreAuthKeys()
				require.NoError(t, err)
				require.Len(t, listedPaks, 1)

				gotTags := slices.Clone(listedPaks[0].Tags)
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

	key, err := db.CreatePreAuthKey(user.TypedID(), false, false, nil, []string{"tag:good"})
	require.NoError(t, err)

	node := types.Node{
		ID:             0,
		Hostname:       "testest",
		UserID:         &user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      new(key.ID),
	}
	db.DB.Save(&node)

	err = db.DB.Where("kind = ? AND id = ?", types.CredentialPreAuthKey, key.ID).
		Delete(&types.Credential{}).Error
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
			name: "legacy_plaintext_rejected",
			setupKey: func() string {
				// Plaintext pre-auth keys (pre-0.30) are no longer supported: a
				// key string without the hskey-auth- prefix is treated as unknown.
				return "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
			},
			wantFindErr:     true,
			wantValidateErr: false,
		},
		{
			name: "new_key_bcrypt",
			setupKey: func() string {
				// Create new key via API
				keyStr, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, []string{"tag:test"},
				)
				require.NoError(t, err)

				return keyStr.Key
			},
			wantFindErr:     false,
			wantValidateErr: false,
			validateResult: func(t *testing.T, pak *types.PreAuthKey) {
				t.Helper()

				assert.Equal(t, user.ID, *pak.UserID)
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
					user.TypedID(),
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
					user.TypedID(),
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

// TestPreAuthKeysHaveUniqueIdentifiers verifies that freshly created pre-auth
// keys get distinct identifiers in the unified credentials table.
func TestPreAuthKeysHaveUniqueIdentifiers(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "test-unique"})
	require.NoError(t, err)

	key1, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	key2, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
	require.NoError(t, err)

	pak1, err := db.GetPreAuthKey(key1.Key)
	require.NoError(t, err)

	pak2, err := db.GetPreAuthKey(key2.Key)
	require.NoError(t, err)

	assert.NotEmpty(t, pak1.Prefix)
	assert.NotEmpty(t, pak2.Prefix)
	assert.NotEqual(t, pak1.Prefix, pak2.Prefix, "new keys should have unique identifiers")
}

// TestUsePreAuthKeyAtomicCAS verifies that UsePreAuthKey is an atomic
// compare-and-set: a second call against an already-used key reports
// PAKError("authkey already used") rather than silently succeeding.
func TestUsePreAuthKeyAtomicCAS(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user, err := db.CreateUser(types.User{Name: "atomic-cas"})
	require.NoError(t, err)

	pakNew, err := db.CreatePreAuthKey(user.TypedID(), false /* reusable */, false, nil, nil)
	require.NoError(t, err)

	pak, err := db.GetPreAuthKey(pakNew.Key)
	require.NoError(t, err)
	require.False(t, pak.Reusable, "test sanity: key must be single-use")

	// First Use should commit cleanly.
	err = db.Write(func(tx *gorm.DB) error {
		return UsePreAuthKey(tx, pak)
	})
	require.NoError(t, err, "first UsePreAuthKey should succeed")

	// Reload from disk to drop the in-memory Used=true the first call
	// set on the struct, simulating a second concurrent transaction
	// that loaded the same row before the first one committed.
	stale, err := db.GetPreAuthKey(pakNew.Key)
	require.NoError(t, err)

	stale.Used = false

	err = db.Write(func(tx *gorm.DB) error {
		return UsePreAuthKey(tx, stale)
	})
	require.Error(t, err, "second UsePreAuthKey on the same single-use key must fail")

	var pakErr types.PAKError
	require.ErrorAs(t, err, &pakErr,
		"second UsePreAuthKey error must be a PAKError, got: %v", err)
	assert.Equal(t, "authkey already used", pakErr.Error())
}

// TestGetPreAuthKeyUnknownMapsToRecordNotFound ensures an unknown (or deleted)
// pre-auth key resolves to a record-not-found error, which the registration
// handler maps to a 401 rather than a raw server error.
func TestGetPreAuthKeyUnknownMapsToRecordNotFound(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	_, err = db.GetPreAuthKey("nonexistent-key")
	require.Error(t, err)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound,
		"unknown pre-auth key must map to record-not-found (handled as 401)")
}

// TestPreAuthKeyLazyRehashesBcrypt seeds a new-format key whose secret is stored
// as a legacy bcrypt hash and asserts that authenticating it upgrades the stored
// hash to argon2id, while continuing to authenticate.
func TestPreAuthKeyLazyRehashesBcrypt(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("rehash-user")

	prefix := "abcdefghijkl"
	secret := strings.Repeat("b", 64)
	keyStr := "hskey-auth-" + prefix + "-" + secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	require.NoError(t, err)

	err = db.DB.Exec(
		`INSERT INTO credentials (kind, identifier, hash, user_id, reusable, ephemeral, used, created_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		types.CredentialPreAuthKey, prefix, hash, user.ID, true, false, false, time.Now(),
	).Error
	require.NoError(t, err)

	pak, err := db.GetPreAuthKey(keyStr)
	require.NoError(t, err)
	require.NotNil(t, pak)

	reloaded, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(string(reloaded.Hash), "$argon2id$"),
		"a bcrypt-stored key must be rehashed to argon2id on first auth")

	// Still authenticates against the upgraded hash.
	_, err = db.GetPreAuthKey(keyStr)
	require.NoError(t, err)
}
