package types

import (
	"errors"
	"fmt"
)

var errSecretEmpty = errors.New("file is empty")

// ResolveSecret resolves the secret setting key as [Secret.Resolve] does;
// errors name the key and say what to fix.
func ResolveSecret(key, value string) (string, error) {
	secret, err := Secret(value).Resolve()
	if err != nil {
		return "", fmt.Errorf("%s: %w; ensure the file exists, is not empty and is readable by the user running headscale", key, err)
	}

	return secret, nil
}
