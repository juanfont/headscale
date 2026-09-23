package db

import (
	"bytes"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"tailscale.com/util/rands"
)

// Every credential is a "<prefix><identifier(12)>-<secret(64)>" string, where
// the prefix is one of hskey-api-, hskey-auth-, hskey-client- or
// hskey-oauthtok-. The identifier is the public, indexed lookup key and only
// the secret is hashed.
const (
	keyIdentifierLength = 12
	keySecretLength     = 64
)

// hashPrefixSHA256 marks the current hash format. Secrets hold 256 bits of
// crypto/rand entropy and are never user-chosen, so recovering one from its
// SHA-256 digest means searching that whole space; security comes from the
// entropy, not hash cost. Password stretching (bcrypt, Argon2id) defends
// guessable secrets and would only add cost to every authentication. The same
// entropy reasoning underlies NIST SP 800-63B-4 §3.1.2.2 (look-up secrets need
// a salted password hash only below 112 bits) and RFC 6819 §5.1.4.1.3 (salt
// hardens low-entropy credentials such as passwords).
const hashPrefixSHA256 = "$sha256$"

// Bounds for legacy Argon2id hashes read back from storage, so a corrupt row
// cannot panic argon2 or allocate unbounded memory.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
const (
	argon2KeyLen    = 32
	argon2MaxMemory = 64 * 1024
)

var (
	errSecretHashMalformed = errors.New("malformed secret hash")
	errSecretMismatch      = errors.New("secret does not match hash")
)

// legacyHashLimiter bounds concurrent bcrypt/Argon2id verifications. Both are
// deliberately expensive and reachable from unauthenticated endpoints; they
// only run until every stored hash has been upgraded to SHA-256.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
var legacyHashLimiter = make(chan struct{}, max(2, runtime.GOMAXPROCS(0)))

// generateSecret builds a new credential string prefix+identifier+"-"+secret,
// returning the full string (shown ONCE to the user), the public identifier
// used for lookup, and the hash of the secret to store.
func generateSecret(prefix string) (string, string, []byte) {
	identifier := rands.HexString(keyIdentifierLength)
	secret := rands.HexString(keySecretLength)

	return prefix + identifier + "-" + secret, identifier, hashSecret(secret)
}

// hashSecret returns the storage form of a credential secret.
func hashSecret(secret string) []byte {
	sum := sha256.Sum256([]byte(secret))

	return []byte(hashPrefixSHA256 + hex.EncodeToString(sum[:]))
}

// authenticateCredential looks up the credential of kind by its public
// identifier and verifies secret against it, upgrading a legacy hash on
// success. An unknown identifier and a wrong secret both return notFound, so a
// caller cannot tell which half of the key was wrong. preloads names the
// associations the caller needs, so the common path stays one query.
func authenticateCredential(
	tx *gorm.DB,
	kind types.CredentialKind,
	identifier, secret string,
	notFound error,
	preloads ...string,
) (*types.Credential, error) {
	var cred types.Credential

	query := tx
	for _, p := range preloads {
		query = query.Preload(p)
	}

	err := query.First(&cred, "kind = ? AND identifier = ?", kind, identifier).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, notFound
	}

	if err != nil {
		return nil, fmt.Errorf("looking up %s credential: %w", kind, err)
	}

	needsRehash, err := verifySecret(cred.Hash, secret)
	if errors.Is(err, errSecretMismatch) {
		return nil, fmt.Errorf("%w: %w", notFound, err)
	}

	if err != nil {
		return nil, fmt.Errorf("verifying %s credential %d: %w", kind, cred.ID, err)
	}

	// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
	if needsRehash {
		// Best effort: on failure the legacy hash stays and the next
		// authentication retries.
		cred.Hash = hashSecret(secret)

		err := tx.Model(&types.Credential{}).Where("id = ?", cred.ID).
			Update("hash", cred.Hash).Error
		if err != nil {
			log.Warn().Err(err).Uint64("credential", cred.ID).
				Msg("upgrading legacy credential hash")
		}
	}

	return &cred, nil
}

// verifySecret reports whether secret matches a stored hash. Legacy bcrypt and
// Argon2id hashes still verify and return needsRehash=true so the caller can
// upgrade them to SHA-256.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support. Any
// credential not rehashed by then stops authenticating (pre-announced).
func verifySecret(encoded []byte, secret string) (bool, error) {
	if hexSum, ok := bytes.CutPrefix(encoded, []byte(hashPrefixSHA256)); ok {
		want, err := hex.DecodeString(string(hexSum))
		if err != nil || len(want) != sha256.Size {
			return false, errSecretHashMalformed
		}

		got := sha256.Sum256([]byte(secret))
		if subtle.ConstantTimeCompare(got[:], want) != 1 {
			return false, errSecretMismatch
		}

		return false, nil
	}

	legacyHashLimiter <- struct{}{}
	defer func() { <-legacyHashLimiter }()

	if bytes.HasPrefix(encoded, []byte("$argon2id$")) {
		err := verifyArgon2id(encoded, secret)

		return err == nil, err
	}

	switch err := bcrypt.CompareHashAndPassword(encoded, []byte(secret)); {
	case err == nil:
		return true, nil
	case errors.Is(err, bcrypt.ErrMismatchedHashAndPassword):
		return false, errSecretMismatch
	default:
		return false, errSecretHashMalformed
	}
}

// verifyArgon2id checks secret against a PHC-encoded Argon2id hash, rejecting
// parameters argon2 would panic on or that would allocate unbounded memory.
//
// TODO(kradalby): remove in 0.32 with bcrypt/Argon2id support.
func verifyArgon2id(encoded []byte, secret string) error {
	parts := strings.Split(string(encoded), "$")
	if len(parts) != 6 || parts[1] != "argon2id" {
		return errSecretHashMalformed
	}

	var version int

	_, err := fmt.Sscanf(parts[2], "v=%d", &version)
	if err != nil || version != argon2.Version {
		return errSecretHashMalformed
	}

	var (
		memory, time uint32
		threads      uint8
	)

	_, err = fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &time, &threads)
	if err != nil || time < 1 || threads < 1 || memory > argon2MaxMemory {
		return errSecretHashMalformed
	}

	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil || len(salt) == 0 {
		return errSecretHashMalformed
	}

	want, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil || len(want) != argon2KeyLen {
		return errSecretHashMalformed
	}

	got := argon2.IDKey([]byte(secret), salt, time, memory, threads, argon2KeyLen)
	if subtle.ConstantTimeCompare(got, want) != 1 {
		return errSecretMismatch
	}

	return nil
}
