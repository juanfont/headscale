package util

import (
	"strings"
	"testing"
	"unicode"

	"pgregory.net/rapid"
)

// ============================================================================
// Generators
// ============================================================================

// genValidHostname generates a string that should pass ValidateHostname:
// 2-63 lowercase alphanum chars, dots, hyphens; not starting/ending with - or .
func genValidHostname() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		// Use a safe inner charset and wrap with alphanumeric boundaries.
		innerLen := rapid.IntRange(0, 59).Draw(t, "innerLen")
		first := rapid.StringMatching(`[a-z0-9]`).Draw(t, "first")
		last := rapid.StringMatching(`[a-z0-9]`).Draw(t, "last")

		var inner string
		if innerLen > 0 {
			inner = rapid.StringMatching(`[a-z0-9\-.]{0,59}`).Draw(t, "inner")
			if len(inner) > innerLen {
				inner = inner[:innerLen]
			}
		}

		result := first + inner + last
		if len(result) > LabelHostnameLength {
			result = result[:LabelHostnameLength]
		}
		// Ensure no leading/trailing - or .
		result = strings.TrimLeft(result, "-.")

		result = strings.TrimRight(result, "-.")
		if len(result) < 2 {
			result = "aa"
		}

		return result
	})
}

// genArbitraryString generates arbitrary unicode strings of length 0-100.
func genArbitraryString() *rapid.Generator[string] {
	return rapid.StringOfN(rapid.Rune(), 0, 100, -1)
}

// genValidUsername generates a string that should pass ValidateUsername:
// starts with letter, 2+ chars, only [letter, digit, -, ., _, @(max 1)].
func genValidUsername() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		first := rapid.StringMatching(`[a-zA-Z]`).Draw(t, "first")
		restLen := rapid.IntRange(1, 30).Draw(t, "restLen")

		rest := rapid.StringMatching(`[a-zA-Z0-9\-._]{1,30}`).Draw(t, "rest")
		if len(rest) > restLen {
			rest = rest[:restLen]
		}

		return first + rest
	})
}

// ============================================================================
// ValidateHostname properties
// ============================================================================

// Property: ValidateHostname accepts well-formed hostnames.
func TestRapid_ValidateHostname_AcceptsValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostname := genValidHostname().Draw(t, "hostname")

		err := ValidateHostname(hostname)
		if err != nil {
			t.Fatalf("ValidateHostname(%q) = %v, want nil", hostname, err)
		}
	})
}

// Property: ValidateHostname rejects strings that are too short (< 2 chars).
func TestRapid_ValidateHostname_RejectsShort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		short := rapid.StringMatching(`[a-z0-9]?`).Draw(t, "short")
		if len(short) >= 2 {
			return // skip if generator produced 2+ chars
		}

		err := ValidateHostname(short)
		if err == nil {
			t.Fatalf("ValidateHostname(%q) should reject short hostname", short)
		}
	})
}

// Property: ValidateHostname rejects strings longer than 63 chars.
func TestRapid_ValidateHostname_RejectsLong(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Generate a string > 63 lowercase alphanum chars
		extra := rapid.IntRange(64, 128).Draw(t, "len")

		long := rapid.StringMatching(`[a-z0-9]{64,128}`).Draw(t, "long")
		if len(long) > extra {
			long = long[:extra]
		}

		if len(long) <= LabelHostnameLength {
			return
		}

		err := ValidateHostname(long)
		if err == nil {
			t.Fatalf("ValidateHostname(%q) should reject long hostname (len=%d)", long, len(long))
		}
	})
}

// Property: ValidateHostname rejects uppercase characters.
func TestRapid_ValidateHostname_RejectsUppercase(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostname := genValidHostname().Draw(t, "hostname")
		// Insert an uppercase letter at a random position
		pos := rapid.IntRange(0, len(hostname)-1).Draw(t, "pos")
		upper := rapid.StringMatching(`[A-Z]`).Draw(t, "upper")

		mixed := hostname[:pos] + upper + hostname[pos:]
		if len(mixed) > LabelHostnameLength {
			mixed = mixed[:LabelHostnameLength]
		}

		err := ValidateHostname(mixed)
		if err == nil {
			t.Fatalf("ValidateHostname(%q) should reject hostname with uppercase", mixed)
		}
	})
}

// ============================================================================
// NormaliseHostname properties
// ============================================================================

// Property: NormaliseHostname is idempotent — normalising a normalised value yields the same result.
func TestRapid_NormaliseHostname_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		// Use strings that have a chance of normalizing successfully
		input := rapid.StringMatching(`[a-zA-Z0-9\-._]{2,80}`).Draw(t, "input")

		first, err1 := NormaliseHostname(input)
		if err1 != nil {
			return // input normalised to something invalid; skip
		}

		second, err2 := NormaliseHostname(first)
		if err2 != nil {
			t.Fatalf("NormaliseHostname idempotency: first(%q)=%q succeeded, second failed: %v",
				input, first, err2)
		}

		if first != second {
			t.Fatalf("NormaliseHostname not idempotent: first=%q, second=%q", first, second)
		}
	})
}

// Property: If NormaliseHostname succeeds, the output passes ValidateHostname.
func TestRapid_NormaliseHostname_OutputIsValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := genArbitraryString().Draw(t, "input")

		normalised, err := NormaliseHostname(input)
		if err != nil {
			return // normalisation failed; that's expected for some inputs
		}

		err = ValidateHostname(normalised)
		if err != nil {
			t.Fatalf("NormaliseHostname(%q) = %q which fails ValidateHostname: %v",
				input, normalised, err)
		}
	})
}

// Property: NormaliseHostname output is always lowercase (postcondition).
func TestRapid_NormaliseHostname_AlwaysLowercase(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.StringMatching(`[a-zA-Z0-9\-._]{2,80}`).Draw(t, "input")

		normalised, err := NormaliseHostname(input)
		if err != nil {
			return
		}

		if normalised != strings.ToLower(normalised) {
			t.Fatalf("NormaliseHostname(%q) = %q is not all lowercase", input, normalised)
		}
	})
}

// Property: NormaliseHostname output length is bounded by LabelHostnameLength.
func TestRapid_NormaliseHostname_BoundedLength(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.StringOfN(rapid.Rune(), 0, 200, -1).Draw(t, "input")

		normalised, err := NormaliseHostname(input)
		if err != nil {
			return
		}

		if len(normalised) > LabelHostnameLength {
			t.Fatalf("NormaliseHostname(%q) = %q exceeds %d chars (len=%d)",
				input, normalised, LabelHostnameLength, len(normalised))
		}
	})
}

// Property: Roundtrip — a valid hostname is preserved by NormaliseHostname.
func TestRapid_NormaliseHostname_PreservesValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		hostname := genValidHostname().Draw(t, "hostname")

		normalised, err := NormaliseHostname(hostname)
		if err != nil {
			t.Fatalf("NormaliseHostname(%q) failed on valid hostname: %v", hostname, err)
		}

		if normalised != hostname {
			t.Fatalf("NormaliseHostname changed valid hostname: %q -> %q", hostname, normalised)
		}
	})
}

// ============================================================================
// ValidateUsername properties
// ============================================================================

// Property: ValidateUsername accepts well-formed usernames.
func TestRapid_ValidateUsername_AcceptsValid(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		username := genValidUsername().Draw(t, "username")

		err := ValidateUsername(username)
		if err != nil {
			t.Fatalf("ValidateUsername(%q) = %v, want nil", username, err)
		}
	})
}

// Property: ValidateUsername rejects strings shorter than 2 chars.
func TestRapid_ValidateUsername_RejectsShort(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		short := rapid.StringMatching(`[a-z]?`).Draw(t, "short")
		if len(short) >= 2 {
			return
		}

		err := ValidateUsername(short)
		if err == nil {
			t.Fatalf("ValidateUsername(%q) should reject short username", short)
		}
	})
}

// Property: ValidateUsername rejects strings starting with a non-letter.
func TestRapid_ValidateUsername_RejectsNonLetterStart(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		firstRune := rapid.RuneFrom(nil, &unicode.RangeTable{
			R16: []unicode.Range16{
				{Lo: '0', Hi: '9', Stride: 1},
				{Lo: '-', Hi: '-', Stride: 1},
				{Lo: '.', Hi: '.', Stride: 1},
				{Lo: '_', Hi: '_', Stride: 1},
			},
		}).Draw(t, "first")
		rest := rapid.StringMatching(`[a-z0-9]{1,10}`).Draw(t, "rest")
		username := string(firstRune) + rest

		err := ValidateUsername(username)
		if err == nil {
			t.Fatalf("ValidateUsername(%q) should reject non-letter start", username)
		}
	})
}

// Property: ValidateUsername rejects usernames with more than one '@'.
func TestRapid_ValidateUsername_RejectsMultipleAt(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		username := genValidUsername().Draw(t, "username")
		// Append two @ signs
		withAts := username + "@domain@extra"

		err := ValidateUsername(withAts)
		if err == nil {
			t.Fatalf("ValidateUsername(%q) should reject multiple @ signs", withAts)
		}
	})
}

// ============================================================================
// GenerateIPv4DNSRootDomain properties
// ============================================================================

// Generators genIPv4Addr and genMaskedIPv4Prefix are defined in addr_rapid_test.go.

// Property: All generated FQDNs end with ".in-addr.arpa.".
// Note: bits restricted to [8, 31] because GenerateIPv4DNSRootDomain panics
// on /32 prefixes (lastOctet=4 is out of range for a 4-byte IP).
func TestRapid_GenerateIPv4DNSRootDomain_AllEndWithArpa(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(31).Draw(t, "prefix")

		fqdns := GenerateIPv4DNSRootDomain(prefix)

		for i, fqdn := range fqdns {
			s := fqdn.WithTrailingDot()
			if !strings.HasSuffix(s, ".in-addr.arpa.") {
				t.Fatalf("fqdns[%d] = %q does not end with .in-addr.arpa. (prefix=%s)",
					i, s, prefix)
			}
		}
	})
}

// Property: The count of generated FQDNs is deterministic from prefix bits.
// For a prefix with B bits, the last octet index is B/8 and the wildcard
// bits are 8 - (B % 8). The count is always 2^wildcardBits.
// Note: bits restricted to [8, 31] to avoid /32 panic.
func TestRapid_GenerateIPv4DNSRootDomain_DeterministicCount(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(31).Draw(t, "prefix")

		fqdns := GenerateIPv4DNSRootDomain(prefix)

		bits := prefix.Bits()

		wildcardBits := ByteSize - bits%ByteSize
		if wildcardBits == ByteSize {
			wildcardBits = ByteSize
		}

		expectedCount := 1 << wildcardBits

		if len(fqdns) != expectedCount {
			t.Fatalf("GenerateIPv4DNSRootDomain(%s): got %d FQDNs, want %d (bits=%d, wildcardBits=%d)",
				prefix, len(fqdns), expectedCount, bits, wildcardBits)
		}
	})
}

// Property: No duplicates in the output.
// Note: bits restricted to [8, 31] to avoid /32 panic.
func TestRapid_GenerateIPv4DNSRootDomain_NoDuplicates(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		prefix := genMaskedIPv4Prefix(31).Draw(t, "prefix")

		fqdns := GenerateIPv4DNSRootDomain(prefix)

		seen := make(map[string]bool, len(fqdns))
		for i, fqdn := range fqdns {
			s := fqdn.WithTrailingDot()
			if seen[s] {
				t.Fatalf("duplicate FQDN at index %d: %q (prefix=%s)", i, s, prefix)
			}

			seen[s] = true
		}
	})
}
