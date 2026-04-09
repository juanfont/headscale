package types

import (
	"errors"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// ============================================================================
// NewAuthID properties
// ============================================================================

// Property: NewAuthID always produces a valid AuthID.
func TestRapid_NewAuthID_AlwaysValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		aid, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() returned error: %v", err)
		}

		err = aid.Validate()
		if err != nil {
			t.Fatalf("NewAuthID() produced invalid AuthID %q: %v", aid, err)
		}
	})
}

// Property: NewAuthID always has correct prefix.
func TestRapid_NewAuthID_HasCorrectPrefix(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		aid, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() returned error: %v", err)
		}

		if !strings.HasPrefix(string(aid), "hskey-authreq-") {
			t.Fatalf("NewAuthID() = %q, missing prefix 'hskey-authreq-'", aid)
		}
	})
}

// Property: NewAuthID always has correct length (AuthIDLength = 38).
func TestRapid_NewAuthID_HasCorrectLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		aid, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() returned error: %v", err)
		}

		if len(aid) != AuthIDLength {
			t.Fatalf("NewAuthID() length = %d, want %d", len(aid), AuthIDLength)
		}
	})
}

// Property: NewAuthID produces distinct values (with overwhelming probability).
func TestRapid_NewAuthID_Unique(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		a, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() returned error: %v", err)
		}

		b, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() returned error: %v", err)
		}

		if a == b {
			t.Fatalf("two NewAuthID() calls returned the same value: %q", a)
		}
	})
}

// ============================================================================
// AuthID.Validate: wrong prefix -> error
// ============================================================================

// Property: AuthID with wrong prefix always fails validation with ErrInvalidAuthIDPrefix.
func TestRapid_AuthID_WrongPrefix_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random string that does NOT start with "hskey-authreq-"
		// by picking a random prefix and padding to the correct length.
		wrongPrefix := rapid.StringMatching(`[a-zA-Z0-9]{1,13}`).Draw(t, "wrongPrefix")

		// Ensure the prefix is actually wrong.
		if wrongPrefix == "hskey-authreq" {
			wrongPrefix = "wrong-prefix-"
		}

		// Pad the rest to make it the correct total length.
		suffixLen := AuthIDLength - len(wrongPrefix)
		if suffixLen <= 0 {
			// If wrongPrefix is too long, just truncate and ensure it's wrong.
			wrongPrefix = wrongPrefix[:10]
			suffixLen = AuthIDLength - 10
		}

		suffix := rapid.StringMatching(`[A-Za-z0-9_-]{`+strings.Repeat("1", 0)+`}`).Draw(t, "suffix")
		// Build a fixed-length string
		padded := wrongPrefix + strings.Repeat("x", suffixLen)

		if len(suffix) > 0 {
			_ = suffix // used for generation entropy, actual padding via Repeat
		}

		aid := AuthID(padded[:AuthIDLength])

		err := aid.Validate()
		if err == nil {
			t.Fatalf("AuthID with wrong prefix %q should fail validation", aid)
		}

		if !errors.Is(err, ErrInvalidAuthIDPrefix) {
			t.Fatalf("expected ErrInvalidAuthIDPrefix, got: %v", err)
		}
	})
}

// Property: Any string not starting with "hskey-authreq-" fails with prefix error.
func TestRapid_AuthID_ArbitraryNonPrefixed_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "arbitrary")

		// Skip if it accidentally has the correct prefix.
		if strings.HasPrefix(s, "hskey-authreq-") {
			return
		}

		aid := AuthID(s)

		err := aid.Validate()
		if err == nil {
			t.Fatalf("AuthID %q without correct prefix should fail", aid)
		}

		if !errors.Is(err, ErrInvalidAuthIDPrefix) {
			t.Fatalf("expected ErrInvalidAuthIDPrefix for %q, got: %v", aid, err)
		}
	})
}

// ============================================================================
// AuthID.Validate: wrong length -> error
// ============================================================================

// Property: AuthID with correct prefix but wrong length always fails with ErrInvalidAuthIDLength.
func TestRapid_AuthID_WrongLength_Error(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a random suffix of incorrect length.
		suffixLen := rapid.IntRange(0, 100).Draw(t, "suffixLen")
		// Skip the one length that would make it valid.
		correctSuffixLen := AuthIDLength - len("hskey-authreq-")
		if suffixLen == correctSuffixLen {
			suffixLen++ // Make it wrong.
		}

		suffix := rapid.StringMatching(`[A-Za-z0-9_-]*`).Draw(t, "suffix")
		// Pad or truncate to desired length.
		for len(suffix) < suffixLen {
			suffix += "x"
		}

		if len(suffix) > suffixLen {
			suffix = suffix[:suffixLen]
		}

		aid := AuthID("hskey-authreq-" + suffix)

		err := aid.Validate()
		if err == nil {
			t.Fatalf("AuthID with length %d should fail (expected %d), value: %q",
				len(aid), AuthIDLength, aid)
		}

		if !errors.Is(err, ErrInvalidAuthIDLength) {
			t.Fatalf("expected ErrInvalidAuthIDLength for len=%d, got: %v", len(aid), err)
		}
	})
}

// Property: AuthIDFromString round-trips for valid AuthIDs.
func TestRapid_AuthIDFromString_RoundTrip(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		original, err := NewAuthID()
		if err != nil {
			t.Fatalf("NewAuthID() error: %v", err)
		}

		parsed, err := AuthIDFromString(original.String())
		if err != nil {
			t.Fatalf("AuthIDFromString(%q) error: %v", original, err)
		}

		if parsed != original {
			t.Fatalf("round-trip mismatch: %q != %q", parsed, original)
		}
	})
}

// Property: AuthIDFromString rejects invalid strings.
func TestRapid_AuthIDFromString_RejectsInvalid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		s := rapid.String().Draw(t, "arbitrary")

		_, err := AuthIDFromString(s)

		// If string happens to be a valid AuthID, that's fine.
		// Otherwise, it must return an error.
		probe := AuthID(s)
		if probe.Validate() != nil && err == nil {
			t.Fatalf("AuthIDFromString(%q) should have returned error", s)
		}
	})
}
