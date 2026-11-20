package db

import (
	"context"
	"fmt"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/types/key"
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

func TestDestroyPreAuthKeyKeepsReferencedEphemeralKey(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("ephemeral-key-user")
	pak, err := db.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)

	node := &types.Node{
		Hostname: "ephemeral-key-node", UserID: &user.ID, AuthKeyID: &pak.ID,
		Ephemeral: true,
	}
	require.NoError(t, db.DB.Create(node).Error)
	require.NoError(t, db.DeletePreAuthKey(pak.ID))

	nodes, err := db.ListNodes()
	require.NoError(t, err)
	require.Len(t, nodes, 1)
	require.True(t, nodes[0].IsEphemeral(), "reload must preserve ephemerality")

	retained, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	require.NotNil(t, retained.Revoked)
	require.Error(t, retained.Validate())
	require.NoError(t, db.DeletePreAuthKey(pak.ID))
	again, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	require.Equal(t, retained.Revoked, again.Revoked)

	cutoff := time.Now().Add(time.Hour)
	count, err := db.DestroyRevokedCredentialsBefore(cutoff)
	require.NoError(t, err)
	require.Zero(t, count)
	require.NoError(t, db.DeleteNode(node))
	count, err = db.DestroyRevokedCredentialsBefore(cutoff)
	require.NoError(t, err)
	require.Equal(t, int64(1), count)

	_, err = db.GetPreAuthKeyByID(pak.ID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)

	unused, err := db.CreatePreAuthKey(user.TypedID(), true, true, nil, nil)
	require.NoError(t, err)
	require.NoError(t, db.DeletePreAuthKey(unused.ID))
	_, err = db.GetPreAuthKeyByID(unused.ID)
	require.ErrorIs(t, err, gorm.ErrRecordNotFound)
}

// createTokenKey makes a key as a token's create does.
func createTokenKey(db *HSDatabase) (*types.PreAuthKeyNew, error) {
	return Write(db.DB, func(tx *gorm.DB) (*types.PreAuthKeyNew, error) {
		_, made, err := CreatePreAuthKeyFrom(tx, NewPreAuthKey{Tags: []string{"tag:ci"}, Reusable: true, ByToken: true})

		return made, err
	})
}

// TestCreateTokenPreAuthKeyIsAtomic: a key a token makes is marked in the
// insert that creates it, so no key exists without its mark.
func TestCreateTokenPreAuthKeyIsAtomic(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	pak, err := createTokenKey(db)
	require.NoError(t, err)

	got, err := db.GetPreAuthKeyByID(pak.ID)
	require.NoError(t, err)
	assert.True(t, got.CreatedByToken)

	require.NoError(t, db.DB.Exec(`CREATE TRIGGER refuse_mark
		BEFORE INSERT ON credentials WHEN NEW.created_by_token
		BEGIN SELECT RAISE(ABORT, 'refused'); END`).Error)

	_, err = createTokenKey(db)
	require.Error(t, err)

	keys, err := db.ListPreAuthKeys()
	require.NoError(t, err)
	assert.Len(t, keys, 1, "the failed create left a key behind")
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
	require.ErrorIs(t, err, gorm.ErrForeignKeyViolated)
}

func TestPreAuthKeyAuthentication(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("test-user")

	tests := []struct {
		name            string
		setupKey        func() string // Returns key string to test
		wantFindErr     bool          // Error when finding the key
		findErrIs       error         // Specific error expected when finding, if any
		wantValidateErr bool          // Error when validating the key
		validateResult  func(*testing.T, *types.PreAuthKey)
	}{
		{
			// TODO(kradalby): remove in 0.32 with legacy key formats (announced).
			name: "unknown_unprefixed_key_rejected",
			setupKey: func() string {
				// An unprefixed string is looked up as a migrated legacy
				// plaintext key; one that was never stored is unknown.
				return "abc123def456ghi789jkl012mno345pqr678stu901vwx234yz"
			},
			wantFindErr:     true,
			findErrIs:       ErrPreAuthKeyNotFound,
			wantValidateErr: false,
		},
		{
			name: "text_before_prefix_rejected",
			setupKey: func() string {
				keyStr, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, []string{"tag:test"},
				)
				require.NoError(t, err)

				// The prefix must start the key, not merely appear in it.
				return "x" + keyStr.Key
			},
			wantFindErr: true,
			findErrIs:   ErrPreAuthKeyNotFound,
		},
		{
			name: "new_key_sha256",
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
				assert.Len(t, pak.Prefix, 12)
				assert.True(t, strings.HasPrefix(string(pak.Hash), hashPrefixSHA256))
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
			name: "wrong_secret",
			setupKey: func() string {
				// Create valid key
				key, err := db.CreatePreAuthKey(
					user.TypedID(),
					true, false, nil, nil,
				)
				require.NoError(t, err)

				keyStr := key.Key

				// Well-formed key with the right identifier but a wrong secret:
				// must read as an unknown key (401), not a server error.
				_, prefixAndHash, _ := strings.Cut(keyStr, "hskey-auth-")
				prefix := prefixAndHash[:12]

				return "hskey-auth-" + prefix + "-" + strings.Repeat("0", 64)
			},
			wantFindErr:     true,
			findErrIs:       errSecretMismatch,
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
				require.Error(t, err)

				if tt.findErrIs != nil {
					require.ErrorIs(t, err, tt.findErrIs)
					require.ErrorIs(t, err, gorm.ErrRecordNotFound, "must map to 401")
				}

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

// TestClaimPreAuthKeyAfterRevoke: a registration read and checked its key,
// then the key was revoked or expired. The claim in the registration's
// transaction refuses it, so an end that answered holds for every key.
func TestClaimPreAuthKeyAfterRevoke(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		user, err := db.CreateUser(types.User{Name: "claim"})
		require.NoError(t, err)

		claim := func(k *types.PreAuthKey, consume bool) error {
			return db.Write(func(tx *gorm.DB) error { return ClaimPreAuthKey(tx, k, consume) })
		}

		ends := []struct {
			end  func(uint64) error
			want string
		}{
			{db.RevokePreAuthKey, "authkey revoked"},
			{db.ExpirePreAuthKey, "authkey expired"},
		}

		for _, end := range ends {
			for _, reusable := range []bool{false, true} {
				made, err := db.CreatePreAuthKey(user.TypedID(), reusable, false, new(time.Now().Add(time.Hour)), nil)
				require.NoError(t, err)

				read, err := db.GetPreAuthKey(made.Key)
				require.NoError(t, err)
				require.NoError(t, read.Validate(), "checked before the end")

				require.NoError(t, end.end(read.ID))

				err = claim(read, !reusable)

				var pakErr types.PAKError
				require.ErrorAs(t, err, &pakErr)
				require.Equal(t, end.want, pakErr.Error())

				after, err := db.GetPreAuthKeyByID(read.ID)
				require.NoError(t, err)
				require.False(t, after.Used, "a refused claim uses nothing")
			}
		}

		t.Run("a reusable key stays unused", func(t *testing.T) {
			made, err := db.CreatePreAuthKey(user.TypedID(), true, false, nil, nil)
			require.NoError(t, err)

			read, err := db.GetPreAuthKey(made.Key)
			require.NoError(t, err)
			require.NoError(t, claim(read, false))
			require.NoError(t, claim(read, false))

			after, err := db.GetPreAuthKeyByID(read.ID)
			require.NoError(t, err)
			require.False(t, after.Used)
		})

		t.Run("a removed key", func(t *testing.T) {
			require.ErrorIs(t, claim(&types.PreAuthKey{ID: 99999}, false), ErrPreAuthKeyNotFound)
		})
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// TestListPreAuthKeysPage: a page holds the keys its filters both match,
// in ID order, revoked ones too, and names the keys a node refers to.
func TestListPreAuthKeysPage(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		alice, err := db.CreateUser(types.User{Name: "alice"})
		require.NoError(t, err)

		bob, err := db.CreateUser(types.User{Name: "bob"})
		require.NoError(t, err)

		ids := make([]uint64, 0, 7)

		for _, k := range []struct {
			user *types.UserID
			tags []string
		}{
			{alice.TypedID(), nil},
			{alice.TypedID(), []string{"tag:ci"}}, // a legacy tagged key: its maker in the owner column
			{bob.TypedID(), nil},
			{nil, []string{"tag:ci", "tag:web"}},
			{alice.TypedID(), nil},
			{nil, []string{"tag:CI"}},
			{nil, []string{"tag:cid"}},
		} {
			made, err := db.CreatePreAuthKey(k.user, false, false, nil, k.tags)
			require.NoError(t, err)

			ids = append(ids, made.ID)
		}

		require.NoError(t, db.RevokePreAuthKey(ids[2]))

		node := types.Node{Hostname: "n", UserID: &alice.ID, AuthKeyID: &ids[4], MachineKey: key.NewMachine().Public(), NodeKey: key.NewNode().Public()}
		require.NoError(t, db.DB.Save(&node).Error)

		for _, tt := range []struct {
			name string
			f    PreAuthKeyFilter
			want []uint64
		}{
			{"every key", PreAuthKeyFilter{}, ids},
			{"a user's keys, not the tagged key it made", PreAuthKeyFilter{User: *alice.TypedID()}, []uint64{ids[0], ids[4]}},
			{"a revoked key", PreAuthKeyFilter{User: *bob.TypedID()}, []uint64{ids[2]}},
			{"a tag, exactly", PreAuthKeyFilter{Tag: "tag:ci"}, []uint64{ids[1], ids[3]}},
			{"both must match", PreAuthKeyFilter{User: *alice.TypedID(), Tag: "tag:ci"}, nil},
			{"an unknown user", PreAuthKeyFilter{User: 99999}, nil},
		} {
			t.Run(tt.name, func(t *testing.T) {
				var (
					got   []uint64
					after uint64
				)

				for {
					page, refs, err := db.ListPreAuthKeysPage(t.Context(), after, 1, tt.f)
					require.NoError(t, err)

					for _, k := range page {
						got = append(got, k.ID)
						require.Equal(t, k.ID == ids[4], refs.Contains(k.ID))
					}

					if len(page) < 1 {
						break
					}

					after = page[len(page)-1].ID
				}

				require.Equal(t, tt.want, got)
			})
		}

		ctx, cancel := context.WithCancel(t.Context())
		cancel()

		_, _, err = db.ListPreAuthKeysPage(ctx, 0, 2, PreAuthKeyFilter{})
		require.ErrorIs(t, err, context.Canceled, "the list ends with its request")

		k, referenced, err := db.GetPreAuthKeyWithReference(ids[4])
		require.NoError(t, err)
		require.True(t, referenced)
		require.Equal(t, ids[4], k.ID)

		_, _, err = db.GetPreAuthKeyWithReference(99999)
		require.ErrorIs(t, err, ErrPreAuthKeyNotFound)
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}

// TestListPreAuthKeysPageQueries: what a page costs does not grow with how
// few keys its filter matches. A filter that matches none of many keys is
// one query; rows the SQL selects and Go drops are read in batches that
// grow, whatever the page size.
func TestListPreAuthKeysPageQueries(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		user, err := db.CreateUser(types.User{Name: "many"})
		require.NoError(t, err)

		const keys = 3000

		creds := make([]types.Credential, keys)
		for i := range creds {
			creds[i] = types.Credential{
				Kind: types.CredentialPreAuthKey, Identifier: fmt.Sprintf("many-%d", i), Hash: []byte("$x"),
				UserID: &user.ID, Tags: []string{"tag:other"},
			}
		}

		require.NoError(t, db.DB.CreateInBatches(creds, 500).Error)

		var queries atomic.Int64

		require.NoError(t, db.DB.Callback().Query().Before("gorm:query").Register("test:count", func(tx *gorm.DB) {
			if tx.Statement.Table == "credentials" {
				queries.Add(1)
			}
		}))

		for _, f := range []PreAuthKeyFilter{{Tag: "tag:none"}, {User: *user.TypedID()}, {User: 99999}} {
			queries.Store(0)

			page, _, err := db.ListPreAuthKeysPage(t.Context(), 0, 2, f)
			require.NoError(t, err)
			require.Empty(t, page)
			require.LessOrEqual(t, queries.Load(), int64(1), "%+v", f)
		}

		queries.Store(0)

		kept, err := Read(db.DB, func(rx *gorm.DB) ([]types.Credential, error) {
			return pageCredentials(rx, types.CredentialPreAuthKey, 0, 2,
				func(rx *gorm.DB) *gorm.DB { return rx },
				func(*types.Credential) bool { return false })
		})
		require.NoError(t, err)
		require.Empty(t, kept)
		require.LessOrEqual(t, queries.Load(), int64(15), "a walk of %d rows the SQL selects and Go drops", keys)
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
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
// hash to SHA-256, while continuing to authenticate.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func TestPreAuthKeyLazyRehashesBcrypt(t *testing.T) {
	db, err := newSQLiteTestDB()
	require.NoError(t, err)

	user := db.CreateUserForTest("rehash-user")

	prefix := "abcdefghijkl"
	secret := strings.Repeat("b", 64)
	keyStr := "hskey-auth-" + prefix + "-" + secret

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
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
	assert.True(t, strings.HasPrefix(string(reloaded.Hash), hashPrefixSHA256),
		"a bcrypt-stored key must be rehashed to SHA-256 on first auth")

	// Still authenticates against the upgraded hash.
	_, err = db.GetPreAuthKey(keyStr)
	require.NoError(t, err)
}

// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func TestPreAuthKeyInvalidatedWhileQueuedOnLegacyLimiter(t *testing.T) {
	tests := []struct {
		name       string
		invalidate func(*HSDatabase, uint64) error
		wantErr    types.PAKError
	}{
		{
			name:       "expired",
			invalidate: (*HSDatabase).ExpirePreAuthKey,
			wantErr:    "authkey expired",
		},
		{
			name:       "revoked",
			invalidate: (*HSDatabase).RevokePreAuthKey,
			wantErr:    "authkey revoked",
		},
		{name: "deleted", invalidate: (*HSDatabase).DeletePreAuthKey},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			db, err := newSQLiteTestDB()
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, db.Close()) })

			user := db.CreateUserForTest("queued-user")
			prefix := "abcdefghijkl"
			secret := strings.Repeat("b", 64)

			hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.MinCost)
			require.NoError(t, err)

			cred := types.Credential{
				Kind:       types.CredentialPreAuthKey,
				Identifier: prefix,
				Hash:       hash,
				UserID:     &user.ID,
				Reusable:   true,
			}
			require.NoError(t, db.DB.Create(&cred).Error)

			read := make(chan struct{})
			signalRead := sync.OnceFunc(func() { close(read) })

			require.NoError(t, db.DB.Callback().Query().After("gorm:query").
				Register("signal_credential_read", func(tx *gorm.DB) {
					if tx.Statement.Table == "credentials" {
						signalRead()
					}
				}))

			for range cap(legacyHashLimiter) {
				legacyHashLimiter <- struct{}{}
			}

			release := sync.OnceFunc(func() {
				for range cap(legacyHashLimiter) {
					<-legacyHashLimiter
				}
			})

			var (
				wg     sync.WaitGroup
				pak    *types.PreAuthKey
				getErr error
			)

			defer func() {
				release()
				wg.Wait()
			}()

			wg.Go(func() {
				pak, getErr = db.GetPreAuthKey(authKeyPrefix + prefix + "-" + secret)
			})

			select {
			case <-read:
			case <-time.After(5 * time.Second):
				t.Fatal("credential lookup did not read the row")
			}

			require.NoError(t, tt.invalidate(db, cred.ID))
			release()
			wg.Wait()

			if tt.name == "deleted" {
				require.ErrorIs(t, getErr, ErrPreAuthKeyNotFound)

				return
			}

			require.NoError(t, getErr)
			require.NotNil(t, pak)
			require.NotNil(t, pak.User)
			assert.Equal(t, user.ID, pak.User.ID)
			require.ErrorIs(t, pak.Validate(), tt.wantErr)
		})
	}
}

// TestClaimPreAuthKeyWaitsForAnEnd: an end (revoke, expire) written but not
// yet committed holds the key's row when the claim runs. The claim waits for
// it, then refuses. On PostgreSQL that needs the claim to read the key after
// its UPDATE took the row lock; read before, it sees the key as it was and
// lets the node in. SQLite runs one write transaction at a time, so there the
// claim's whole transaction waits and the order inside it does not show.
func TestClaimPreAuthKeyWaitsForAnEnd(t *testing.T) {
	test := func(t *testing.T, db *HSDatabase) {
		t.Helper()

		user, err := db.CreateUser(types.User{Name: "wait"})
		require.NoError(t, err)

		ends := []struct {
			name string
			end  func(*gorm.DB, uint64) error
			want string
		}{
			{"revoke", RevokePreAuthKey, "authkey revoked"},
			{"expire", ExpirePreAuthKey, "authkey expired"},
		}

		for _, end := range ends {
			for _, reusable := range []bool{false, true} {
				t.Run(fmt.Sprintf("%s, reusable %t", end.name, reusable), func(t *testing.T) {
					made, err := db.CreatePreAuthKey(user.TypedID(), reusable, false, new(time.Now().Add(time.Hour)), nil)
					require.NoError(t, err)

					read, err := db.GetPreAuthKey(made.Key)
					require.NoError(t, err)

					tx := db.DB.Begin()
					require.NoError(t, tx.Error)
					require.NoError(t, end.end(tx, read.ID))

					claimed := make(chan error, 1)

					go func() {
						claimed <- db.Write(func(tx *gorm.DB) error { return ClaimPreAuthKey(tx, read, !reusable) })
					}()

					select {
					case err := <-claimed:
						tx.Rollback()
						t.Fatalf("the claim did not wait for the end (%v)", err)
					case <-time.After(200 * time.Millisecond):
					}

					require.NoError(t, tx.Commit().Error)

					var pakErr types.PAKError
					require.ErrorAs(t, <-claimed, &pakErr)
					require.Equal(t, end.want, pakErr.Error())
				})
			}
		}
	}

	t.Run("sqlite", func(t *testing.T) {
		db, err := newSQLiteTestDB()
		require.NoError(t, err)
		test(t, db)
	})
	t.Run("postgres", func(t *testing.T) { test(t, newPostgresTestDB(t)) })
}
