package types

import (
	"database/sql"
	"net/url"
	"strings"
	"testing"

	"gorm.io/gorm"
	"pgregory.net/rapid"
)

// ============================================================================
// Generators
// ============================================================================

// genSimpleIdentifier generates a non-empty string without slashes or whitespace.
func genSimpleIdentifier() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z0-9._-]{1,30}`)
}

// genURLIssuer generates a URL-form issuer (e.g., "https://example.com/path").
func genURLIssuer() *rapid.Generator[string] {
	return rapid.Custom[string](func(t *rapid.T) string {
		scheme := rapid.SampledFrom([]string{"https", "http"}).Draw(t, "scheme")
		host := rapid.StringMatching(`[a-z]{3,12}\.[a-z]{2,5}`).Draw(t, "host")
		nParts := rapid.IntRange(0, 3).Draw(t, "nParts")

		parts := make([]string, nParts)
		for i := range parts {
			parts[i] = rapid.StringMatching(`[a-z0-9]{1,10}`).Draw(t, "part")
		}

		path := ""
		if len(parts) > 0 {
			path = "/" + strings.Join(parts, "/")
		}

		return scheme + "://" + host + path
	})
}

// genNonURLIssuer generates a non-URL issuer (e.g., "oidc" or "local").
func genNonURLIssuer() *rapid.Generator[string] {
	return rapid.StringMatching(`[a-z]{2,15}`)
}

// genOIDCClaims generates an OIDCClaims with various Iss/Sub combinations.
func genOIDCClaims() *rapid.Generator[*OIDCClaims] {
	return rapid.Custom[*OIDCClaims](func(t *rapid.T) *OIDCClaims {
		mode := rapid.IntRange(0, 3).Draw(t, "mode")
		switch mode {
		case 0: // URL issuer
			return &OIDCClaims{
				Iss: genURLIssuer().Draw(t, "iss"),
				Sub: genSimpleIdentifier().Draw(t, "sub"),
			}
		case 1: // Non-URL issuer
			return &OIDCClaims{
				Iss: genNonURLIssuer().Draw(t, "iss"),
				Sub: genSimpleIdentifier().Draw(t, "sub"),
			}
		case 2: // Empty issuer
			return &OIDCClaims{
				Iss: "",
				Sub: genSimpleIdentifier().Draw(t, "sub"),
			}
		default: // Empty sub
			return &OIDCClaims{
				Iss: genURLIssuer().Draw(t, "iss"),
				Sub: "",
			}
		}
	})
}

// ============================================================================
// CleanIdentifier properties
// ============================================================================

// Property: CleanIdentifier is idempotent.
func TestRapid_CleanIdentifier_Idempotent(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.StringOfN(rapid.Rune(), 0, 80, -1).Draw(t, "input")

		first := CleanIdentifier(input)
		second := CleanIdentifier(first)

		if first != second {
			t.Fatalf("CleanIdentifier not idempotent: first=%q, second=%q (input=%q)",
				first, second, input)
		}
	})
}

// Property: CleanIdentifier output never contains double slashes in the path.
func TestRapid_CleanIdentifier_NoDoubleSlashes(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.StringOfN(rapid.Rune(), 0, 80, -1).Draw(t, "input")

		result := CleanIdentifier(input)

		// Strip the scheme (e.g., "https://") before checking
		toCheck := result

		u, err := url.Parse(result)
		if err == nil && u.Scheme != "" {
			toCheck = u.Path
		}

		if strings.Contains(toCheck, "//") {
			t.Fatalf("CleanIdentifier(%q) = %q contains double slashes in path",
				input, result)
		}
	})
}

// Property: CleanIdentifier("") returns "".
func TestRapid_CleanIdentifier_EmptyPreserved(t *testing.T) {
	result := CleanIdentifier("")
	if result != "" {
		t.Fatalf("CleanIdentifier(\"\") = %q, want \"\"", result)
	}
}

// Property: CleanIdentifier output has no leading/trailing whitespace.
func TestRapid_CleanIdentifier_NoWhitespace(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		input := rapid.StringOfN(rapid.Rune(), 0, 80, -1).Draw(t, "input")

		result := CleanIdentifier(input)

		if result != strings.TrimSpace(result) {
			t.Fatalf("CleanIdentifier(%q) = %q has leading/trailing whitespace",
				input, result)
		}
	})
}

// Property: CleanIdentifier preserves URL scheme.
func TestRapid_CleanIdentifier_PreservesScheme(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		issuer := genURLIssuer().Draw(t, "url")

		result := CleanIdentifier(issuer)

		u, err := url.Parse(result)
		if err != nil {
			t.Fatalf("CleanIdentifier(%q) = %q is not a valid URL: %v",
				issuer, result, err)
		}

		origU, _ := url.Parse(issuer)
		if u.Scheme != strings.ToLower(origU.Scheme) {
			t.Fatalf("CleanIdentifier(%q) changed scheme: got %q, want %q",
				issuer, u.Scheme, strings.ToLower(origU.Scheme))
		}
	})
}

// ============================================================================
// OIDCClaims.Identifier properties
// ============================================================================

// Property: Identifier output is always cleaned (double-cleaning is idempotent).
func TestRapid_OIDCClaims_Identifier_AlwaysCleaned(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		claims := genOIDCClaims().Draw(t, "claims")

		result := claims.Identifier()
		cleaned := CleanIdentifier(result)

		if result != cleaned {
			t.Fatalf("Identifier() = %q is not cleaned (CleanIdentifier = %q)",
				result, cleaned)
		}
	})
}

// Property: When both Iss and Sub are empty, Identifier returns "".
func TestRapid_OIDCClaims_Identifier_BothEmptyIsEmpty(t *testing.T) {
	claims := &OIDCClaims{Iss: "", Sub: ""}

	result := claims.Identifier()
	if result != "" {
		t.Fatalf("Identifier() = %q for empty Iss+Sub, want \"\"", result)
	}
}

// Property: When Iss is a URL and Sub is a safe alphanumeric identifier,
// the Sub appears in the result.
//
// BUG FINDING: url.JoinPath treats ".." as path traversal, so Sub=".."
// with Iss="https://example.com" produces "https://example.com" (Sub lost).
// This means OIDC providers with Sub values containing ".." or "." would
// produce colliding identifiers. We restrict the generator to safe Subs
// to test the normal case, and document the edge case separately.
func TestRapid_OIDCClaims_Identifier_SubAppearsInResult(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		iss := genURLIssuer().Draw(t, "iss")
		// Use only alphanumeric subs to avoid path-traversal edge cases
		sub := rapid.StringMatching(`[a-z0-9]{1,30}`).Draw(t, "sub")
		claims := &OIDCClaims{Iss: iss, Sub: sub}

		result := claims.Identifier()

		if !strings.Contains(result, sub) {
			t.Fatalf("Identifier() = %q does not contain Sub %q (Iss=%q)",
				result, sub, iss)
		}
	})
}

// BUG FINDING: Identifier() loses the Sub when Sub is ".." due to url.JoinPath
// treating it as path traversal. This could cause distinct OIDC users to get
// the same identifier, leading to user collisions.
func TestRapid_OIDCClaims_Identifier_PathTraversalSubLost(t *testing.T) {
	claims1 := &OIDCClaims{Iss: "https://example.com", Sub: ".."}
	claims2 := &OIDCClaims{Iss: "https://example.com", Sub: "legit-user"}

	id1 := claims1.Identifier()
	id2 := claims2.Identifier()

	// The bug: Sub=".." gets path-traversed away, potentially colliding
	// with other identifiers. At minimum, two different Subs must produce
	// different identifiers.
	if !strings.Contains(id1, "..") {
		// Sub was lost — this IS the bug. Two distinct OIDC users
		// could collide if one has Sub=".." and another has a Sub
		// that resolves to the same path after JoinPath.
		t.Fatalf("BUG: Sub '..' lost in Identifier() = %q — "+
			"path traversal causes OIDC identifier collision risk "+
			"(compare with Sub='legit-user' = %q)", id1, id2)
	}
}

// Property: When only Sub is set (Iss empty), Identifier returns CleanIdentifier(Sub).
func TestRapid_OIDCClaims_Identifier_OnlySubSetReturnsCleanedSub(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		sub := genSimpleIdentifier().Draw(t, "sub")
		claims := &OIDCClaims{Iss: "", Sub: sub}

		result := claims.Identifier()
		expected := CleanIdentifier(sub)

		if result != expected {
			t.Fatalf("Identifier() = %q for empty Iss, want CleanIdentifier(%q) = %q",
				result, sub, expected)
		}
	})
}

// ============================================================================
// User.Username properties
// ============================================================================

// Property: Username never returns empty string — there's always a fallback.
func TestRapid_Username_NeverEmpty(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		id := uint(rapid.IntRange(1, 10000).Draw(t, "id")) //nolint:gosec // positive bounded value
		user := &User{
			Model: gorm.Model{ID: id},
		}

		// Optionally set various fields
		if rapid.Bool().Draw(t, "hasEmail") {
			user.Email = rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		}

		if rapid.Bool().Draw(t, "hasName") {
			user.Name = rapid.StringMatching(`[a-z]{2,15}`).Draw(t, "name")
		}

		if rapid.Bool().Draw(t, "hasProvider") {
			user.ProviderIdentifier = sql.NullString{
				String: genURLIssuer().Draw(t, "provider") + "/sub",
				Valid:  true,
			}
		}

		username := user.Username()
		if username == "" {
			t.Fatalf("Username() returned empty for user ID=%d", id)
		}
	})
}

// Property: Username prioritizes Email over Name.
func TestRapid_Username_EmailPriority(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		email := rapid.StringMatching(`[a-z]{3,10}@[a-z]{3,8}\.[a-z]{2,4}`).Draw(t, "email")
		name := rapid.StringMatching(`[a-z]{2,15}`).Draw(t, "name")

		user := &User{
			Model: gorm.Model{ID: 1},
			Email: email,
			Name:  name,
		}

		if user.Username() != email {
			t.Fatalf("Username() = %q, want email %q (should take priority over name %q)",
				user.Username(), email, name)
		}
	})
}

// Property: Username returns Name when Email is empty.
func TestRapid_Username_NameFallback(t *testing.T) {
	rapid.Check(t, func(t *rapid.T) {
		name := rapid.StringMatching(`[a-z]{2,15}`).Draw(t, "name")

		user := &User{
			Model: gorm.Model{ID: 1},
			Name:  name,
		}

		if user.Username() != name {
			t.Fatalf("Username() = %q, want name %q", user.Username(), name)
		}
	})
}
