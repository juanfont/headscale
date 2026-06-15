package util

import (
	"crypto/rand"
	"encoding/base64"
	"strings"
)

// GenerateRandomBytes returns securely generated random bytes.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomBytes(n int) ([]byte, error) {
	bytes := make([]byte, n)

	// Note that err == nil only if we read len(b) bytes.
	if _, err := rand.Read(bytes); err != nil { //nolint:noinlineerr
		return nil, err
	}

	return bytes, nil
}

// GenerateRandomStringURLSafe returns a URL-safe, base64 encoded
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringURLSafe(n int) (string, error) {
	b, err := GenerateRandomBytes(n)

	return encodeRandomURLSafe(b, n, err)
}

// encodeRandomURLSafe URL-safe base64-encodes b and truncates to n. It checks
// err first: on an RNG failure b is nil, so slicing the empty encoding would
// panic instead of returning the ("", err) the caller is promised.
func encodeRandomURLSafe(b []byte, n int, err error) (string, error) {
	if err != nil {
		return "", err
	}

	return base64.RawURLEncoding.EncodeToString(b)[:n], nil
}

// GenerateRandomStringDNSSafe returns a DNS-safe
// securely generated random string.
// It will return an error if the system's secure random
// number generator fails to function correctly, in which
// case the caller should not continue.
func GenerateRandomStringDNSSafe(size int) (string, error) {
	var (
		str string
		err error
	)

	for len(str) < size {
		str, err = GenerateRandomStringURLSafe(size)
		if err != nil {
			return "", err
		}

		str = strings.ToLower(
			strings.ReplaceAll(strings.ReplaceAll(str, "_", ""), "-", ""),
		)
	}

	return str[:size], nil
}

func MustGenerateRandomStringDNSSafe(size int) string {
	hash, err := GenerateRandomStringDNSSafe(size)
	if err != nil {
		panic(err)
	}

	return hash
}
