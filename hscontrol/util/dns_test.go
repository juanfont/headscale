package util

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestValidateUsername judges initials and length by rune, not byte.
func TestValidateUsername(t *testing.T) {
	for _, tt := range []struct {
		name, username string
		want           error
	}{
		{"ascii", "ab", nil},
		{"latin initial", "øyvind", nil},
		{"hebrew initial", "אב", nil},
		{"empty", "", ErrUsernameTooShort},
		{"one ascii letter", "a", ErrUsernameTooShort},
		{"one letter outside ascii", "Å", ErrUsernameTooShort},
		{"ascii digit initial", "0x", ErrUsernameMustStartLetter},
		{"arabic-indic digit initial", "٠x", ErrUsernameMustStartLetter},
		{"two at signs", "a@b@c", ErrUsernameTooManyAt},
	} {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, ValidateUsername(tt.username), tt.want)
		})
	}
}
