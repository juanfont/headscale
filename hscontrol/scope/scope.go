// Package scope models the OAuth capability scopes the Headscale v2 API enforces
// and the rule for whether a granted set of scopes satisfies a required one.
//
// The vocabulary is taken from Tailscale's OpenAPI spec (the same scope names
// the Terraform provider and Kubernetes operator request), so a client written
// against Tailscale's scopes works unchanged against Headscale. The grant
// predicate is kept here, separate from the HTTP/huma layer in
// hscontrol/api/v2, so it can be tested exhaustively on its own.
package scope

import "strings"

// Scope is an OAuth capability an operation requires and a token grants. The names
// mirror Tailscale's API scopes; a "...:read" scope is the read-only subset of its
// write scope.
type Scope string

const (
	// All and AllRead are Tailscale's forward-compatible super-scopes: "all"
	// grants every other scope, "all:read" grants every :read subset.
	All     Scope = "all"
	AllRead Scope = "all:read"

	AuthKeys     Scope = "auth_keys"
	AuthKeysRead Scope = "auth_keys:read"

	// OAuthKeys gates managing OAuth clients (keyType:"client" on the keys
	// resource).
	OAuthKeys     Scope = "oauth_keys"
	OAuthKeysRead Scope = "oauth_keys:read"

	DevicesCore     Scope = "devices:core"
	DevicesCoreRead Scope = "devices:core:read"

	DevicesRoutes     Scope = "devices:routes"
	DevicesRoutesRead Scope = "devices:routes:read"

	PolicyFile     Scope = "policy_file"
	PolicyFileRead Scope = "policy_file:read"

	FeatureSettings     Scope = "feature_settings"
	FeatureSettingsRead Scope = "feature_settings:read"

	Users     Scope = "users"
	UsersRead Scope = "users:read"
)

const readSuffix = ":read"

// Known returns every scope in the vocabulary, in a stable order. Useful for
// exhaustive iteration in tests and documentation.
func Known() []Scope {
	return []Scope{
		All, AllRead,
		AuthKeys, AuthKeysRead,
		OAuthKeys, OAuthKeysRead,
		DevicesCore, DevicesCoreRead,
		DevicesRoutes, DevicesRoutesRead,
		PolicyFile, PolicyFileRead,
		FeatureSettings, FeatureSettingsRead,
		Users, UsersRead,
	}
}

// IsRead reports whether s is a read-only scope (its name ends with ":read").
func (s Scope) IsRead() bool {
	return strings.HasSuffix(string(s), readSuffix)
}

// IsWrite reports whether s is a non-empty write scope.
func (s Scope) IsWrite() bool {
	return s != "" && !s.IsRead()
}

// Parse converts scope strings (as stored on a token or client) into Scope values.
// Unknown strings are kept as-is; they simply never satisfy any required scope.
func Parse(ss []string) []Scope {
	out := make([]Scope, len(ss))
	for i, s := range ss {
		out[i] = Scope(s)
	}

	return out
}

// Grants reports whether the granted scopes satisfy the required want scope.
func Grants(granted []Scope, want Scope) bool {
	for _, g := range granted {
		if satisfies(g, want) {
			return true
		}
	}

	return false
}

// satisfies reports whether a single held scope satisfies want: exact match; a
// write scope grants its own :read subset; "all" grants everything; "all:read"
// grants any :read scope.
func satisfies(have, want Scope) bool {
	if have == want || have == All {
		return true
	}

	if have == AllRead {
		return want.IsRead()
	}

	// A write scope grants its own read subset, e.g. auth_keys ⊇ auth_keys:read.
	return string(want) == string(have)+readSuffix
}

// RequiresTags reports whether any scope obliges a credential to carry tags:
// devices:core and auth_keys mint tagged, tailnet-owned credentials.
func RequiresTags(scopes []Scope) bool {
	for _, s := range scopes {
		if s == DevicesCore || s == AuthKeys {
			return true
		}
	}

	return false
}
