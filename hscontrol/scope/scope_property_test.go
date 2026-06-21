package scope

import (
	"slices"
	"testing"

	"pgregory.net/rapid"
)

// scopeGen draws a scope: mostly from the real vocabulary, sometimes adversarial
// junk (including read-like junk such as "foo:read") so the rules are exercised
// against unknown input too.
func scopeGen() *rapid.Generator[Scope] {
	known := Known()

	return rapid.Custom(func(t *rapid.T) Scope {
		if rapid.Float64().Draw(t, "junkP") < 0.2 {
			return Scope(rapid.StringMatching(`[a-z_]{1,12}(:read)?`).Draw(t, "junk"))
		}

		return rapid.SampledFrom(known).Draw(t, "vocab")
	})
}

// TestGrantsMatchesOracle fuzzes Grants against the independent oracle over random
// granted-sets and want-scopes (vocabulary + junk).
func TestGrantsMatchesOracle(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		granted := rapid.SliceOfN(scopeGen(), 0, 6).Draw(rt, "granted")
		want := scopeGen().Draw(rt, "want")

		if got, exp := Grants(granted, want), oracleGrants(granted, want); got != exp {
			rt.Fatalf("Grants(%v, %q) = %v, oracle = %v", granted, want, got, exp)
		}
	})
}

// TestGrantsInvariants asserts the algebraic properties of the grant relation hold
// for arbitrary inputs.
func TestGrantsInvariants(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		granted := rapid.SliceOfN(scopeGen(), 0, 6).Draw(rt, "granted")
		want := scopeGen().Draw(rt, "want")

		// Reflexivity: a scope always grants itself.
		if !Grants([]Scope{want}, want) {
			rt.Fatalf("reflexivity: %q does not grant itself", want)
		}

		// The empty set grants nothing.
		if Grants(nil, want) {
			rt.Fatalf("empty grant satisfied %q", want)
		}

		// OR-semantics: a set grants iff some member does.
		anyMember := slices.ContainsFunc(granted, func(g Scope) bool {
			return Grants([]Scope{g}, want)
		})
		if Grants(granted, want) != anyMember {
			rt.Fatalf("OR-semantics broken for %v / %q", granted, want)
		}

		// Monotonicity: adding a scope never withdraws a grant.
		before := Grants(granted, want)
		extra := scopeGen().Draw(rt, "extra")
		after := Grants(append(slices.Clone(granted), extra), want)

		if before && !after {
			rt.Fatalf("monotonicity broken: adding %q withdrew the grant of %q", extra, want)
		}
	})
}

// TestSuperScopeProperties fuzzes the super-scope rules.
func TestSuperScopeProperties(t *testing.T) {
	rapid.Check(t, func(rt *rapid.T) {
		want := scopeGen().Draw(rt, "want")

		// all grants everything.
		if !Grants([]Scope{All}, want) {
			rt.Fatalf("all did not grant %q", want)
		}

		// all:read grants exactly the read scopes.
		if Grants([]Scope{AllRead}, want) != want.IsRead() {
			rt.Fatalf("all:read grant of %q = %v, want IsRead = %v",
				want, Grants([]Scope{AllRead}, want), want.IsRead())
		}
	})
}
