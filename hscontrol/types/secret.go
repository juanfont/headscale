package types

import (
	"errors"
	"fmt"
	"os"
	"strings"

	hsdns "github.com/juanfont/headscale/hscontrol/dns"
)

var errSecretEmpty = errors.New("file is empty")

// ResolveSecret returns value, or the trimmed contents of the file named
// by "file:<path>" (Tailscale's form), which keeps the secret out of the
// config and the environment. Variables in the path are expanded so a
// systemd credential can be named by ${CREDENTIALS_DIRECTORY}.
func ResolveSecret(key, value string) (string, error) {
	path, ok := strings.CutPrefix(value, "file:")
	if !ok {
		return value, nil
	}

	path = os.ExpandEnv(path)

	b, err := os.ReadFile(path)
	if err != nil {
		return "", fmt.Errorf("%s: %w", key, err)
	}

	// An empty file is a credential that was not written, not a choice.
	secret := strings.TrimSpace(string(b))
	if secret == "" {
		return "", fmt.Errorf("%s: %s: %w", key, path, errSecretEmpty)
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

// configSecret resolves the secret setting key, recording a failure in v.
func configSecret(v *configValidator, resolve func(key, value string) (string, error), key, value string) string {
	secret, err := resolve(key, value)
	if errors.Is(err, hsdns.ErrSecretUnread) {
		return value
	}

	if err != nil {
		v.Add(&ConfigError{
			Reason:  key + " cannot be read",
			Current: []KV{{key, value}},
			Detail:  err.Error(),
			Hint:    "ensure the file exists, is not empty and is readable by the user running headscale",
			Cause:   err,
		})
	}

	return secret
}
