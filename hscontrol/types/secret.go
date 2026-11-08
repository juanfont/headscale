package types

import (
	"errors"
	"fmt"
	"strings"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
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

// keepSecret leaves a file: secret unread, for checking a config without
// reading the files it names; checks that need the secret skip it.
func keepSecret(_, value string) (string, error) {
	if strings.HasPrefix(value, "file:") {
		return value, hsdns.ErrSecretUnread
	}

	return value, nil
}
