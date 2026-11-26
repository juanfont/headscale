package dockertestutil

import (
	"fmt"
	"regexp"
)

// secretPattern is a credential headscale or Tailscale prints:
// <hs|ts>key-<kind>-<rest>, the rest in the base64 URL-safe alphabet the
// key parser accepts (hscontrol/db.parsePrefixedKey), "-" and "_" included.
var secretPattern = regexp.MustCompile(`((?:hs|ts)key-([a-z]+)-)([0-9A-Za-z_-]+)`)

// keyPrefixLen is the fixed length of the part of a headscale key before
// its secret (hscontrol/db.keyIdentifierLength); it names the key and is
// not secret.
const keyPrefixLen = 12

// Redact hides every secret in s. The suite's logs and errors end up in CI
// artefacts, and a command that makes or takes a credential prints it, or
// echoes it in an error. A rest that has a key prefix and its "-" keeps the
// prefix; any other rest is hidden whole. An auth ID (hskey-authreq-) is a
// request, not a credential, and stays. A key of the legacy form, which has
// no hskey- prefix, is not seen: the suite mints none.
func Redact(s string) string {
	return secretPattern.ReplaceAllStringFunc(s, func(m string) string {
		sub := secretPattern.FindStringSubmatch(m)
		head, kind, rest := sub[1], sub[2], sub[3]

		switch {
		case kind == "authreq":
			return m
		// Only the prefix and its "-": masked before, "***" follows.
		case len(rest) == keyPrefixLen+1 && rest[keyPrefixLen] == '-':
			return m
		case len(rest) > keyPrefixLen+1 && rest[keyPrefixLen] == '-':
			return head + rest[:keyPrefixLen+1] + "***"
		default:
			return head + "***"
		}
	})
}

// Redactf is fmt.Errorf for the text of a failure that may hold a secret:
// the whole text is redacted, and the error unwraps to cause, so errors.Is
// and errors.As see through it. Format the cause with %v or %s.
func Redactf(cause error, format string, args ...any) error {
	return redactedError{msg: Redact(fmt.Sprintf(format, args...)), err: cause}
}

// RedactError is err with every secret in its text hidden; nil stays nil.
func RedactError(err error) error {
	if err == nil {
		return nil
	}

	return Redactf(err, "%v", err)
}

type redactedError struct {
	msg string
	err error
}

func (e redactedError) Error() string { return e.msg }
func (e redactedError) Unwrap() error { return e.err }
