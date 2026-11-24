package util

import (
	"errors"
	"fmt"
	"unicode"
	"unicode/utf8"
)

const (
	// LabelHostnameLength is the maximum length for a DNS label,
	// value related to RFC 1123 and 952.
	LabelHostnameLength = 63
)

// DNS validation errors. Hostname-side validation lives on
// `tailscale.com/util/dnsname` and [state.NodeStore] collision handling; only
// the username-side errors stay in this package.
var (
	ErrUsernameTooShort        = errors.New("username must be at least 2 characters long")
	ErrUsernameMustStartLetter = errors.New("username must start with a letter")
	ErrUsernameTooManyAt       = errors.New("username cannot contain more than one '@'")
	ErrUsernameInvalidChar     = errors.New("username contains invalid character")
)

// ValidateUsername checks if a username is valid.
// It must be at least 2 characters long, start with a letter, and contain
// only letters, numbers, hyphens, dots, and underscores.
// It cannot contain more than one '@'.
// It cannot contain invalid characters.
func ValidateUsername(username string) error {
	first, width := utf8.DecodeRuneInString(username)
	if width == len(username) {
		return ErrUsernameTooShort
	}

	if !unicode.IsLetter(first) {
		return ErrUsernameMustStartLetter
	}

	atCount := 0

	for _, char := range username {
		switch {
		case unicode.IsLetter(char),
			unicode.IsDigit(char),
			char == '-',
			char == '.',
			char == '_':
			// Valid characters
		case char == '@':
			atCount++
			if atCount > 1 {
				return ErrUsernameTooManyAt
			}
		default:
			return fmt.Errorf("%w: '%c'", ErrUsernameInvalidChar, char)
		}
	}

	return nil
}
