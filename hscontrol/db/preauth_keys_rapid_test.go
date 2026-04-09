package db

import (
	"errors"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

const authkeyExpiredMsg = "authkey expired"

// ============================================================================
// Generators
// ============================================================================

// genFutureTime generates a time in the future (1 second to 10 years from now).
func genFutureTime() *rapid.Generator[time.Time] {
	return rapid.Custom[time.Time](func(t *rapid.T) time.Time {
		offsetSec := rapid.Int64Range(1, 10*365*24*3600).Draw(t, "futureOffset")
		return time.Now().Add(time.Duration(offsetSec) * time.Second)
	})
}

// genPastTime generates a time in the past (1 second to 10 years ago).
func genPastTime() *rapid.Generator[time.Time] {
	return rapid.Custom[time.Time](func(t *rapid.T) time.Time {
		offsetSec := rapid.Int64Range(1, 10*365*24*3600).Draw(t, "pastOffset")
		return time.Now().Add(-time.Duration(offsetSec) * time.Second)
	})
}

// genBase64URLSafeChar generates a single character from the base64 URL-safe alphabet.
func genBase64URLSafeChar() *rapid.Generator[byte] {
	return rapid.Custom[byte](func(t *rapid.T) byte {
		return rapid.SampledFrom(base64URLSafeAlphabet).Draw(t, "char")
	})
}

var base64URLSafeAlphabet = func() []byte {
	var chars []byte
	for c := byte('A'); c <= 'Z'; c++ {
		chars = append(chars, c)
	}

	for c := byte('a'); c <= 'z'; c++ {
		chars = append(chars, c)
	}

	for c := byte('0'); c <= '9'; c++ {
		chars = append(chars, c)
	}

	chars = append(chars, '-', '_')

	return chars
}()

// genBase64URLSafeString generates a string containing only [A-Za-z0-9_-] characters.
func genBase64URLSafeString(minLen, maxLen int) *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		n := rapid.IntRange(minLen, maxLen).Draw(t, "len")

		buf := make([]byte, n)
		for i := range buf {
			buf[i] = genBase64URLSafeChar().Draw(t, "char")
		}

		return string(buf)
	})
}

// ============================================================================
// PreAuthKey.Validate properties
// ============================================================================

// Property: nil PreAuthKey -> error.
func TestRapid_PreAuthKeyValidate_NilKey_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		var pak *types.PreAuthKey

		err := pak.Validate()
		if err == nil {
			t.Fatal("nil PreAuthKey should return error")
		}
	})
}

// Property: expired key -> error.
func TestRapid_PreAuthKeyValidate_Expired_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pastTime := genPastTime().Draw(t, "expiration")
		reusable := rapid.Bool().Draw(t, "reusable")
		used := rapid.Bool().Draw(t, "used")

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   reusable,
			Used:       used,
			Expiration: &pastTime,
		}

		err := pak.Validate()
		if err == nil {
			t.Fatalf("expired key (exp=%v) should return error", pastTime)
		}

		var pakErr types.PAKError

		ok := errors.As(err, &pakErr)
		if !ok {
			t.Fatalf("expected PAKError, got %T: %v", err, err)
		}

		if string(pakErr) != authkeyExpiredMsg {
			t.Fatalf("expected %q, got %q", authkeyExpiredMsg, pakErr)
		}
	})
}

// Property: non-reusable + used -> error.
func TestRapid_PreAuthKeyValidate_NonReusableUsed_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Not expired: either nil expiration or future expiration.
		var expiration *time.Time

		if rapid.Bool().Draw(t, "hasExpiration") {
			ft := genFutureTime().Draw(t, "expiration")
			expiration = &ft
		}

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   false,
			Used:       true,
			Expiration: expiration,
		}

		err := pak.Validate()
		if err == nil {
			t.Fatal("non-reusable used key should return error")
		}

		var pakErr types.PAKError

		ok := errors.As(err, &pakErr)
		if !ok {
			t.Fatalf("expected PAKError, got %T: %v", err, err)
		}

		if string(pakErr) != "authkey already used" {
			t.Fatalf("expected 'authkey already used', got %q", pakErr)
		}
	})
}

// Property: reusable + used -> ok (reusable keys bypass the used check).
func TestRapid_PreAuthKeyValidate_ReusableUsed_OK(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Not expired: either nil expiration or future expiration.
		var expiration *time.Time

		if rapid.Bool().Draw(t, "hasExpiration") {
			ft := genFutureTime().Draw(t, "expiration")
			expiration = &ft
		}

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   true,
			Used:       true,
			Expiration: expiration,
		}

		err := pak.Validate()
		if err != nil {
			t.Fatalf("reusable+used key should be valid, got: %v", err)
		}
	})
}

// Property: valid, unexpired, unused key -> ok.
func TestRapid_PreAuthKeyValidate_ValidUnexpiredUnused_OK(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		reusable := rapid.Bool().Draw(t, "reusable")

		// Not expired: either nil expiration or future expiration.
		var expiration *time.Time

		if rapid.Bool().Draw(t, "hasExpiration") {
			ft := genFutureTime().Draw(t, "expiration")
			expiration = &ft
		}

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   reusable,
			Used:       false,
			Expiration: expiration,
		}

		err := pak.Validate()
		if err != nil {
			t.Fatalf("valid unexpired unused key should be ok, got: %v", err)
		}
	})
}

// Property: expiration priority — expired keys always fail regardless of
// reusable/used flags.
func TestRapid_PreAuthKeyValidate_ExpirationTakesPrecedence(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		pastTime := genPastTime().Draw(t, "expiration")
		reusable := rapid.Bool().Draw(t, "reusable")
		used := rapid.Bool().Draw(t, "used")

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   reusable,
			Used:       used,
			Expiration: &pastTime,
		}

		err := pak.Validate()
		if err == nil {
			t.Fatalf("expired key should always fail, reusable=%v used=%v",
				reusable, used)
		}
		// The error should specifically be about expiration, not about being used.
		var pakErr types.PAKError

		ok := errors.As(err, &pakErr)
		if !ok {
			t.Fatalf("expected PAKError, got %T: %v", err, err)
		}

		if string(pakErr) != authkeyExpiredMsg {
			t.Fatalf("expected %q for expired key, got %q", authkeyExpiredMsg, pakErr)
		}
	})
}

// Property: nil expiration never triggers the expiration error (key may still
// fail for other reasons like being used).
func TestRapid_PreAuthKeyValidate_NilExpirationNeverExpires(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		reusable := rapid.Bool().Draw(t, "reusable")
		used := rapid.Bool().Draw(t, "used")

		pak := &types.PreAuthKey{
			ID:         rapid.Uint64().Draw(t, "id"),
			Reusable:   reusable,
			Used:       used,
			Expiration: nil,
		}

		err := pak.Validate()
		if err != nil {
			// If there's an error, it must NOT be about expiration.
			var pakErr types.PAKError

			ok := errors.As(err, &pakErr)
			if !ok {
				t.Fatalf("expected PAKError, got %T: %v", err, err)
			}

			if string(pakErr) == authkeyExpiredMsg {
				t.Fatal("nil expiration should never trigger expiration error")
			}
		}
	})
}

// ============================================================================
// isValidBase64URLSafe properties
// ============================================================================

// Property: strings containing only [A-Za-z0-9_-] -> true.
func TestRapid_IsValidBase64URLSafe_ValidChars_True(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := genBase64URLSafeString(0, 100).Draw(t, "validString")

		if !isValidBase64URLSafe(s) {
			t.Fatalf("isValidBase64URLSafe(%q) = false, want true", s)
		}
	})
}

// Property: strings containing only chars from regex [A-Za-z0-9_-] -> true.
// Uses rapid's StringMatching for independent validation.
func TestRapid_IsValidBase64URLSafe_RegexGenerated_True(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.StringMatching(`[A-Za-z0-9_-]*`).Draw(t, "regexString")

		if !isValidBase64URLSafe(s) {
			t.Fatalf("isValidBase64URLSafe(%q) = false for regex-matched string", s)
		}
	})
}

// Property: empty string -> true (vacuous truth: no invalid characters).
func TestRapid_IsValidBase64URLSafe_EmptyString_True(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		if !isValidBase64URLSafe("") {
			t.Fatal("isValidBase64URLSafe(\"\") = false, want true")
		}
	})
}

// Property: strings with any character outside [A-Za-z0-9_-] -> false.
func TestRapid_IsValidBase64URLSafe_InvalidChars_False(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a valid base string.
		validPart := genBase64URLSafeString(0, 50).Draw(t, "validPart")

		// Generate a character that is NOT in [A-Za-z0-9_-].
		invalidChar := rapid.Custom[byte](func(t *rapid.T) byte {
			// Pick from known invalid characters.
			candidates := []byte{
				' ', '!', '@', '#', '$', '%', '^', '&', '*', '(', ')',
				'+', '=', '[', ']', '{', '}', '|', '\\', '/', '?',
				'<', '>', ',', '.', ';', ':', '\'', '"', '`', '~',
				'\t', '\n', '\r', '\x00',
			}

			return rapid.SampledFrom(candidates).Draw(t, "invalidChar")
		}).Draw(t, "invalidByte")

		// Insert the invalid character at a random position.
		pos := rapid.IntRange(0, len(validPart)).Draw(t, "pos")
		withInvalid := validPart[:pos] + string(invalidChar) + validPart[pos:]

		if isValidBase64URLSafe(withInvalid) {
			t.Fatalf("isValidBase64URLSafe(%q) = true, want false (has byte 0x%02x at pos %d)",
				withInvalid, invalidChar, pos)
		}
	})
}

// Property: any arbitrary Unicode string containing a non-base64-url-safe rune -> false.
func TestRapid_IsValidBase64URLSafe_ArbitraryUnicode(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "arbitrary")

		result := isValidBase64URLSafe(s)

		// Manually verify: check each rune.
		expected := true

		for _, c := range s {
			if (c < 'A' || c > 'Z') && (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
				expected = false
				break
			}
		}

		if result != expected {
			t.Fatalf("isValidBase64URLSafe(%q) = %v, want %v", s, result, expected)
		}
	})
}

// Property: concatenation of two valid strings is also valid.
func TestRapid_IsValidBase64URLSafe_ConcatValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a := genBase64URLSafeString(0, 50).Draw(t, "a")
		b := genBase64URLSafeString(0, 50).Draw(t, "b")

		if !isValidBase64URLSafe(a + b) {
			t.Fatalf("concatenation of valid strings %q + %q should be valid", a, b)
		}
	})
}

// Property: every individual character of a valid string is also valid.
func TestRapid_IsValidBase64URLSafe_EveryCharValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := genBase64URLSafeString(1, 100).Draw(t, "validString")

		for i, c := range s {
			if !isValidBase64URLSafe(string(c)) {
				t.Fatalf("character %q at position %d of valid string %q is not valid", string(c), i, s)
			}
		}
	})
}

// Property: single characters from the alphabet are valid, all others are not.
func TestRapid_IsValidBase64URLSafe_SingleChar(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		c := rapid.Byte().Draw(t, "char")

		isAlphaNum := (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
		isSpecial := c == '-' || c == '_'
		expected := isAlphaNum || isSpecial

		got := isValidBase64URLSafe(string(c))
		if got != expected {
			t.Fatalf("isValidBase64URLSafe(%q) = %v, want %v", string(c), got, expected)
		}
	})
}
