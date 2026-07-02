package db

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"golang.org/x/crypto/bcrypt"
)

// TestVerifySecretArgon2idNoRehash verifies that an Argon2id-stored secret
// matches and reports no rehash needed.
func TestVerifySecretArgon2idNoRehash(t *testing.T) {
	hash, err := hashSecret("s3cr3t")
	require.NoError(t, err)

	needsRehash, err := verifySecret(hash, "s3cr3t")
	require.NoError(t, err)
	require.False(t, needsRehash, "argon2id hash should never need a rehash")
}

// TestVerifySecretBcryptNeedsRehash verifies that a legacy bcrypt-stored secret
// still authenticates and is flagged for lazy rehash to Argon2id.
func TestVerifySecretBcryptNeedsRehash(t *testing.T) {
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cr3t"), bcrypt.DefaultCost)
	require.NoError(t, err)

	needsRehash, err := verifySecret(hash, "s3cr3t")
	require.NoError(t, err)
	require.True(t, needsRehash, "a matched bcrypt hash must request a rehash to argon2id")

	_, err = verifySecret(hash, "wrong")
	require.ErrorIs(t, err, errSecretMismatch)
}

// TestVerifySecretMalformed verifies that a hash in no recognised format is
// rejected rather than silently accepted.
func TestVerifySecretMalformed(t *testing.T) {
	_, err := verifySecret([]byte("not-a-hash"), "s3cr3t")
	require.Error(t, err)
}

// TestGenerateSecret verifies the unified key generation: hskey-<prefix><id>-<secret>,
// a 12-char identifier, a 64-char secret, and an argon2id hash of the secret.
func TestGenerateSecret(t *testing.T) {
	full, identifier, hash, err := generateSecret("hskey-test-")
	require.NoError(t, err)

	require.Len(t, identifier, 12)
	require.True(t, strings.HasPrefix(full, "hskey-test-"+identifier+"-"))

	secret := strings.TrimPrefix(full, "hskey-test-"+identifier+"-")
	require.Len(t, secret, 64)

	needsRehash, err := verifySecret(hash, secret)
	require.NoError(t, err)
	require.False(t, needsRehash)
}
