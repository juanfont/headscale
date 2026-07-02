package db

import (
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/util/rands"
)

// Every credential is a "hskey-<kind>-<identifier(12)>-<secret(64)>" string: the
// identifier is the public, indexed lookup key and only the secret is hashed.
const (
	keyIdentifierLength = 12
	keySecretLength     = 64
)

// Argon2id parameters, OWASP's minimum recommendation (19 MiB, 2 iterations, 1
// lane). They are encoded into every stored hash, so raising them later still
// verifies credentials stored under the old cost.
const (
	argon2Time    = 2
	argon2Memory  = 19 * 1024
	argon2Threads = 1
	argon2KeyLen  = 32
	argon2SaltLen = 16
)

var (
	errSecretHashMalformed = errors.New("malformed secret hash")
	errSecretMismatch      = errors.New("secret does not match hash")
)

// argon2Limiter bounds concurrent Argon2id computations. Each costs ~19 MiB and
// the unauthenticated OAuth token endpoint runs one per attempt, so an unbounded
// flood could exhaust memory. A global semaphore sized to GOMAXPROCS;
// TODO(kradalby): revisit only if credential hashing becomes a throughput bottleneck.
var argon2Limiter = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// generateSecret builds a new credential string of the form
// prefix+identifier+"-"+secret, returning the full string (shown ONCE to the
// user), the public identifier used for lookup, and the Argon2id hash of the
// secret to store. It is the single generator for every credential kind.
func generateSecret(prefix string) (string, string, []byte, error) {
	identifier := rands.HexString(keyIdentifierLength)
	secret := rands.HexString(keySecretLength)
	full := prefix + identifier + "-" + secret

	hash, err := hashSecret(secret)
	if err != nil {
		return "", "", nil, err
	}

	return full, identifier, hash, nil
}

// rehashToArgon2id upgrades a credential's stored hash to Argon2id after a
// successful verify reported the secret was still under legacy bcrypt. It is
// best effort: a failed upgrade leaves the bcrypt hash in place, so the next
// authentication simply tries again. model must be a pointer to a credential
// row with its primary key set and a "hash" column.
func rehashToArgon2id(db *gorm.DB, model any, secret string) {
	hash, err := hashSecret(secret)
	if err != nil {
		return
	}

	_ = db.Model(model).Update("hash", hash).Error
}

// hashSecret hashes a credential secret with Argon2id, encoded in PHC string
// form so the parameters travel with the hash. Argon2id is the current OWASP
// recommendation, replacing bcrypt for new credential storage.
func hashSecret(secret string) ([]byte, error) {
	salt := make([]byte, argon2SaltLen)

	_, err := rand.Read(salt)
	if err != nil {
		return nil, fmt.Errorf("generating salt: %w", err)
	}

	hash := argon2.IDKey([]byte(secret), salt, argon2Time, argon2Memory, argon2Threads, argon2KeyLen)

	encoded := fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, argon2Memory, argon2Time, argon2Threads,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(hash),
	)

	return []byte(encoded), nil
}

// verifySecret reports whether secret matches a stored hash, transparently
// accepting both the current Argon2id PHC form and legacy bcrypt hashes. A
// matched bcrypt hash returns needsRehash=true so the caller can upgrade the
// stored hash to Argon2id on the next successful authentication.
//
// TODO(kradalby): remove the bcrypt branch in 0.32; any credential not rehashed
// by then stops authenticating (pre-announced breaking change).
func verifySecret(encoded []byte, secret string) (bool, error) {
	if bytes.HasPrefix(encoded, []byte("$argon2id$")) {
		return false, verifyArgon2id(encoded, secret)
	}

	// Legacy bcrypt hash: a clean compare means the secret is valid but stored
	// under the old algorithm, so request a rehash. A mismatch is a wrong
	// secret; any other bcrypt error means the stored hash is not a usable hash.
	switch err := bcrypt.CompareHashAndPassword(encoded, []byte(secret)); {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, errSecretMismatch
	default:
		return false, errSecretHashMalformed
	}
}

// verifyArgon2id reads the cost parameters from the stored hash and compares in
// constant time so a mismatch leaks no timing signal.
func verifyArgon2id(encoded []byte, secret string) error {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errSecretHashMalformed
	}

	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version { //nolint:noinlineerr
		return errSecretHashMalformed
	}

	var (
		memory, time uint32
		threads      uint8
	)

	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads); err != nil { //nolint:noinlineerr
		return errSecretHashMalformed
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return errSecretHashMalformed
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return errSecretHashMalformed
	}

	argon2Limiter <- struct{}{}
	//nolint:gosec // want is a 32-byte hash read back from storage, no overflow
	got := argon2.IDKey([]byte(secret), salt, time, memory, threads, uint32(len(want)))

	<-argon2Limiter

	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errSecretMismatch
	}

	return nil
}
