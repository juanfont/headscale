package util

import (
	"errors"
	"testing"
	"unicode"

	"github.com/juanfont/headscale/internal/testgen"
	"pgregory.net/rapid"
)

func TestUsernameDecimalDigit(t *testing.T) {
	err := ValidateUsername("٢x")
	if !errors.Is(err, ErrUsernameMustStartLetter) {
		t.Fatalf("digit initial: got %v, want %v", err, ErrUsernameMustStartLetter)
	}

	err = ValidateUsername("x٢")
	if err != nil {
		t.Fatalf("digit suffix: %v", err)
	}
}

func TestRapidUsernameDigits(t *testing.T) {
	letter := testgen.Letter()
	digit := rapid.RuneFrom(nil, unicode.Nd)

	rapid.Check(t, func(rt *rapid.T) {
		initial := string(letter.Draw(rt, "letter"))
		digits := string(rapid.SliceOfN(digit, 1, 8).Draw(rt, "decimal digits"))

		err := ValidateUsername(digits + initial)
		if !errors.Is(err, ErrUsernameMustStartLetter) {
			rt.Fatalf("digit-first name %q: got %v, want %v", digits+initial, err, ErrUsernameMustStartLetter)
		}

		err = ValidateUsername(initial + digits)
		if err != nil {
			rt.Fatalf("letter-first name %q: %v", initial+digits, err)
		}
	})
}
