package scope

import (
	"fmt"
	"strings"
	"testing"
)

// classify decomposes a scope into (resource, super, read) WITHOUT reusing any of
// the production logic, so the oracle below is an independent second
// implementation of the grant rule: a divergence between it and Grants is a real
// bug in one of them, not a tautology.
type classified struct {
	resource string // "" for super-scopes; otherwise the write-scope base (e.g. "auth_keys")
	super    bool   // all / all:read
	read     bool   // the :read variant
}

func classify(s Scope) classified {
	str := string(s)
	read := strings.HasSuffix(str, ":read")
	base := strings.TrimSuffix(str, ":read")

	if base == "all" {
		return classified{super: true, read: read}
	}

	return classified{resource: base, read: read}
}

// oracle re-derives "does have satisfy want" from the classification, independent
// of satisfies/Grants.
func oracle(have, want Scope) bool {
	h, w := classify(have), classify(want)

	if h.super {
		// "all" grants everything; "all:read" grants only reads.
		return !h.read || w.read
	}

	if h.resource != w.resource {
		return false
	}

	// Same resource: a write scope grants both read and write; a read scope grants
	// only read.
	return !h.read || w.read
}

func oracleGrants(granted []Scope, want Scope) bool {
	for _, g := range granted {
		if oracle(g, want) {
			return true
		}
	}

	return false
}

// TestGrantsHandPicked pins specific (granted, want) outcomes with literal
// expected values, independent of any oracle: the anchor for the rules.
func TestGrantsHandPicked(t *testing.T) {
	tests := []struct {
		granted []Scope
		want    Scope
		ok      bool
	}{
		{granted: []Scope{AuthKeys}, want: AuthKeys, ok: true},
		{granted: []Scope{AuthKeys}, want: AuthKeysRead, ok: true},
		{granted: []Scope{AuthKeysRead}, want: AuthKeys, ok: false},
		{granted: []Scope{AuthKeysRead}, want: AuthKeysRead, ok: true},
		{granted: []Scope{DevicesCore}, want: AuthKeys, ok: false},
		{granted: []Scope{DevicesCoreRead}, want: AuthKeysRead, ok: false},
		{granted: []Scope{All}, want: AuthKeys, ok: true},
		{granted: []Scope{All}, want: FeatureSettingsRead, ok: true},
		{granted: []Scope{AllRead}, want: PolicyFileRead, ok: true},
		{granted: []Scope{AllRead}, want: PolicyFile, ok: false},
		{granted: []Scope{AllRead}, want: All, ok: false},
		{granted: []Scope{DevicesCore, OAuthKeys}, want: OAuthKeys, ok: true},
		{granted: nil, want: AuthKeysRead, ok: false},
		{granted: []Scope{"garbage"}, want: AuthKeys, ok: false},
		{granted: []Scope{"garbage"}, want: "garbage", ok: true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v_%s", tt.granted, tt.want), func(t *testing.T) {
			if got := Grants(tt.granted, tt.want); got != tt.ok {
				t.Errorf("Grants(%v, %q) = %v, want %v", tt.granted, tt.want, got, tt.ok)
			}
		})
	}
}

// TestGrantsExhaustive checks every single-grant pair in the vocabulary against
// the independent oracle, plus representative multi-grant cases.
func TestGrantsExhaustive(t *testing.T) {
	known := Known()

	for _, g := range known {
		for _, w := range known {
			got := Grants([]Scope{g}, w)
			exp := oracle(g, w)

			if got != exp {
				t.Errorf("Grants([%q], %q) = %v, oracle = %v", g, w, got, exp)
			}
		}
	}

	multi := [][]Scope{
		{All, AuthKeysRead},
		{AllRead, AuthKeys},
		{AuthKeys, OAuthKeysRead},
		{DevicesCore, DevicesRoutes, PolicyFile},
		{AuthKeys, AuthKeys}, // duplicates
	}

	for _, granted := range multi {
		for _, w := range known {
			got := Grants(granted, w)
			exp := oracleGrants(granted, w)

			if got != exp {
				t.Errorf("Grants(%v, %q) = %v, oracle = %v", granted, w, got, exp)
			}
		}
	}
}

// TestWriteGrantsItsRead and friends assert the structural rules over the whole
// vocabulary, deterministically.
func TestWriteGrantsItsRead(t *testing.T) {
	for _, s := range Known() {
		if !s.IsWrite() {
			continue
		}

		read := Scope(string(s) + ":read")
		if !Grants([]Scope{s}, read) {
			t.Errorf("write scope %q does not grant its read subset %q", s, read)
		}
	}
}

func TestReadNeverGrantsWrite(t *testing.T) {
	for _, s := range Known() {
		if !s.IsRead() {
			continue
		}

		write := Scope(strings.TrimSuffix(string(s), ":read"))
		if Grants([]Scope{s}, write) {
			t.Errorf("read scope %q must not grant write scope %q", s, write)
		}
	}
}

func TestAllGrantsEverything(t *testing.T) {
	for _, w := range Known() {
		if !Grants([]Scope{All}, w) {
			t.Errorf("all should grant %q", w)
		}
	}
}

func TestAllReadGrantsReadsOnly(t *testing.T) {
	for _, w := range Known() {
		got := Grants([]Scope{AllRead}, w)
		if got != w.IsRead() {
			t.Errorf("all:read grants %q = %v, want %v (IsRead)", w, got, w.IsRead())
		}
	}
}

// TestResourceIsolation: a non-super scope never grants a scope of a different
// resource.
func TestResourceIsolation(t *testing.T) {
	for _, a := range Known() {
		if a == All || a == AllRead {
			continue
		}

		for _, b := range Known() {
			if classify(a).resource == classify(b).resource {
				continue
			}

			if Grants([]Scope{a}, b) {
				t.Errorf("scope %q (resource %q) must not grant %q (resource %q)",
					a, classify(a).resource, b, classify(b).resource)
			}
		}
	}
}

func TestRequiresTags(t *testing.T) {
	tests := []struct {
		scopes   []Scope
		requires bool
	}{
		{scopes: []Scope{DevicesCore}, requires: true},
		{scopes: []Scope{AuthKeys}, requires: true},
		{scopes: []Scope{OAuthKeys}, requires: false},
		{scopes: []Scope{PolicyFile, AuthKeys}, requires: true},
		{scopes: []Scope{DevicesCoreRead}, requires: false},
		{scopes: nil, requires: false},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.scopes), func(t *testing.T) {
			if got := RequiresTags(tt.scopes); got != tt.requires {
				t.Errorf("RequiresTags(%v) = %v, want %v", tt.scopes, got, tt.requires)
			}
		})
	}
}

func TestKnownIsComplete(t *testing.T) {
	known := Known()

	seen := make(map[Scope]bool, len(known))
	for _, s := range known {
		if seen[s] {
			t.Errorf("Known() contains duplicate %q", s)
		}

		seen[s] = true
	}

	// 7 resources × 2 (write+read) + 2 super-scopes = 16.
	if len(known) != 16 {
		t.Errorf("Known() has %d scopes, want 16", len(known))
	}
}
