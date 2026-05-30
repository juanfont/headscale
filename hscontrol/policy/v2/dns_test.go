package v2

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

// boolp returns a pointer to b. Tests use it for *bool fields where
// present-vs-absent semantics matter.
func boolp(b bool) *bool { return &b }

// nsList returns a pointer to a []string built from the given values.
func nsList(s ...string) *[]string { x := []string(s); return &x }

// splitMap returns a pointer to a map[string][]string.
func splitMap(m map[string][]string) *map[string][]string { return &m }

// TestNodeDNSConfig exercises the matcher across all three tiers
// (tag > user > group), the within-tier list-order precedence, and
// the "no match returns base unchanged" behavior.
func TestNodeDNSConfig(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "admin", Email: "admin@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "friend", Email: "friend@headscale.net"},
		{Model: gorm.Model{ID: 3}, Name: "boss", Email: "boss@headscale.net"},
		{Model: gorm.Model{ID: 4}, Name: "other", Email: "other@headscale.net"},
	}
	adminUser, friendUser, bossUser, otherUser := users[0], users[1], users[2], users[3]

	splitRoutes := map[string][]*dnstype.Resolver{
		"scoresby.cloud": {{Addr: "192.168.4.2"}},
	}
	base := &tailcfg.DNSConfig{
		Routes:  splitRoutes,
		Domains: []string{"ts.scoresby.cloud"},
		Proxied: true,
	}

	// Profiles in list order:
	//   [0] admin override — Resolvers, override=true. Both group:admin
	//       and friend@ (user-tier) point at it. friend is also in
	//       group:friend listed later, but user tier beats group tier so
	//       this profile wins for friend.
	//   [1] friend group override — used by group:friend members that
	//       aren't overridden via user tier above.
	//   [2] server tag — for tagged nodes.
	pol := `{
		"groups": {
			"group:admin": ["admin@"],
			"group:friend": ["friend@", "boss@"]
		},
		"tagOwners": {
			"tag:server": ["admin@"]
		},
		"dns": [
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"groups": ["group:admin"],
				"users": ["friend@"]
			},
			{
				"nameservers": ["1.1.1.1"],
				"groups": ["group:friend"]
			},
			{
				"nameservers": ["10.0.0.1"],
				"overrideLocalDNS": true,
				"tags": ["tag:server"]
			}
		]
	}`

	adminNode := node("admin-phone", "100.64.0.1", "fd7a:115c:a1e0::1", adminUser)
	adminNode.ID = 1
	friendNode := node("friend-laptop", "100.64.0.2", "fd7a:115c:a1e0::2", friendUser)
	friendNode.ID = 2
	bossNode := node("boss-laptop", "100.64.0.3", "fd7a:115c:a1e0::3", bossUser)
	bossNode.ID = 3
	otherNode := node("other-phone", "100.64.0.4", "fd7a:115c:a1e0::4", otherUser)
	otherNode.ID = 4
	taggedNode := node("server-1", "100.64.0.5", "fd7a:115c:a1e0::5", types.User{})
	taggedNode.ID = 5
	taggedNode.Tags = types.Strings{"tag:server"}
	untaggedNode := node("other-router", "100.64.0.6", "fd7a:115c:a1e0::6", types.User{})
	untaggedNode.ID = 6
	untaggedNode.Tags = types.Strings{"tag:unrelated"}

	nodes := types.Nodes{adminNode, friendNode, bossNode, otherNode, taggedNode, untaggedNode}
	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	tests := []struct {
		name string
		node types.NodeView
		want *tailcfg.DNSConfig
	}{
		{
			// Admin is in group:admin → profile [0], override=true → Resolvers.
			name: "group-tier-admin",
			node: adminNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "192.168.4.2"}},
			},
		},
		{
			// friend@ matches profile [0]'s Users (user tier > group tier);
			// would otherwise match profile [1] via group:friend.
			name: "user-tier-beats-group-tier",
			node: friendNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "192.168.4.2"}},
			},
		},
		{
			// boss@ is in group:friend only → profile [1], override=false → FallbackResolvers.
			name: "group-tier-fallback-only",
			node: bossNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:            splitRoutes,
				Domains:           []string{"ts.scoresby.cloud"},
				Proxied:           true,
				FallbackResolvers: []*dnstype.Resolver{{Addr: "1.1.1.1"}},
			},
		},
		{
			// other@ matches no profile → base unchanged.
			name: "no-match-returns-base",
			node: otherNode.View(),
			want: base.Clone(),
		},
		{
			// Tagged node matches profile [2] via tag:server.
			name: "tag-tier",
			node: taggedNode.View(),
			want: &tailcfg.DNSConfig{
				Routes:    splitRoutes,
				Domains:   []string{"ts.scoresby.cloud"},
				Proxied:   true,
				Resolvers: []*dnstype.Resolver{{Addr: "10.0.0.1"}},
			},
		},
		{
			// Tagged node whose tags aren't in any profile → base unchanged.
			name: "tagged-no-match-returns-base",
			node: untaggedNode.View(),
			want: base.Clone(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pm.NodeDNSConfig(tt.node, base, "")
			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("NodeDNSConfig() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// TestNodeDNSConfigListOrderWithinTier verifies that within the group
// tier, the first profile to list a matching group wins — even if the
// node's user is in multiple groups assigned to different profiles.
func TestNodeDNSConfigListOrderWithinTier(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	user := users[0]

	// The user is in both groups; list order ⇒ profile [0] wins.
	pol := `{
		"groups": {
			"group:first":  ["u@"],
			"group:second": ["u@"]
		},
		"dns": [
			{ "nameservers": ["1.1.1.1"], "overrideLocalDNS": true, "groups": ["group:first"] },
			{ "nameservers": ["8.8.8.8"], "overrideLocalDNS": true, "groups": ["group:second"] }
		]
	}`

	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "1.1.1.1"}}
	if diff := cmp.Diff(want, got.Resolvers); diff != "" {
		t.Errorf("list-order should pick profile[0] (group:first); mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigMultiTagProfileListOrder verifies the tag tier
// matches by profile list order, not by the order tags appear on the
// node. A node with [tag:b, tag:a] should match profile {tags:[a]} (the
// first profile listed) even though tag:b appears first on the node.
func TestNodeDNSConfigMultiTagProfileListOrder(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "owner", Email: "owner@headscale.net"}}
	pol := `{
		"tagOwners": {
			"tag:a": ["owner@"],
			"tag:b": ["owner@"]
		},
		"dns": [
			{ "nameservers": ["1.1.1.1"], "overrideLocalDNS": true, "tags": ["tag:a"] },
			{ "nameservers": ["8.8.8.8"], "overrideLocalDNS": true, "tags": ["tag:b"] }
		]
	}`

	n := node("server", "100.64.0.1", "fd7a:115c:a1e0::1", types.User{})
	n.ID = 1
	n.Tags = types.Strings{"tag:b", "tag:a"} // node order: b, a

	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	got := pm.NodeDNSConfig(n.View(), &tailcfg.DNSConfig{}, "")
	require.NotNil(t, got)
	want := []*dnstype.Resolver{{Addr: "1.1.1.1"}}
	if diff := cmp.Diff(want, got.Resolvers); diff != "" {
		t.Errorf("profile list order (tag:a) should win over node tag order (tag:b first); mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigUntaggedNoValidUser: an untagged node whose user is
// invalid (no user record attached) matches no profile and returns base.
func TestNodeDNSConfigUntaggedNoValidUser(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pol := `{
		"groups": { "group:x": ["u@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"], "groups": ["group:x"] }
		]
	}`

	// Node with no user attached.
	n := node("nouser", "100.64.0.1", "fd7a:115c:a1e0::1", types.User{})
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{"x.example": {{Addr: "base"}}}}
	got := pm.NodeDNSConfig(n.View(), base, "")
	if diff := cmp.Diff(base, got); diff != "" {
		t.Errorf("node with no valid user should return base unchanged; mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigEmptyDNSPolicy: a policy with no dns block returns
// base unchanged.
func TestNodeDNSConfigEmptyDNSPolicy(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	user := users[0]
	pol := `{}`
	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{Routes: map[string][]*dnstype.Resolver{"x.example": {{Addr: "base"}}}}
	got := pm.NodeDNSConfig(n.View(), base, "")
	if diff := cmp.Diff(base, got); diff != "" {
		t.Errorf("empty DNS policy should return base unchanged; mismatch (-want +got):\n%s", diff)
	}
}

// TestNodeDNSConfigNilBase: a nil base passes through as nil.
func TestNodeDNSConfigNilBase(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pol := `{}`
	n := node("u-node", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)
	if got := pm.NodeDNSConfig(n.View(), nil, ""); got != nil {
		t.Errorf("nil base should produce nil; got %v", got)
	}
}

// TestNodeDNSConfigSplitAndSearchDomains: a profile can override Split
// (Routes) and SearchDomains on top of base.
func TestNodeDNSConfigSplitAndSearchDomains(t *testing.T) {
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "eng", Email: "eng@headscale.net"}}
	user := users[0]

	pol := `{
		"groups": { "group:eng": ["eng@"] },
		"dns": [
			{
				"nameservers": ["192.168.4.2"],
				"overrideLocalDNS": true,
				"split": { "internal.example": ["10.0.0.1"] },
				"searchDomains": ["internal.example"],
				"groups": ["group:eng"]
			}
		]
	}`

	n := node("eng-node", "100.64.0.1", "fd7a:115c:a1e0::1", user)
	n.ID = 1
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{n}.ViewSlice())
	require.NoError(t, err)

	base := &tailcfg.DNSConfig{
		Routes:  map[string][]*dnstype.Resolver{"old.example": {{Addr: "base-res"}}},
		Domains: []string{"base.example"},
		Proxied: true,
	}
	got := pm.NodeDNSConfig(n.View(), base, "base.example")
	require.NotNil(t, got)

	// Split replaces Routes; SearchDomains is appended after base_domain.
	wantRoutes := map[string][]*dnstype.Resolver{"internal.example": {{Addr: "10.0.0.1"}}}
	if diff := cmp.Diff(wantRoutes, got.Routes); diff != "" {
		t.Errorf("Routes mismatch (-want +got):\n%s", diff)
	}
	wantDomains := []string{"base.example", "internal.example"}
	if diff := cmp.Diff(wantDomains, got.Domains); diff != "" {
		t.Errorf("Domains mismatch (-want +got):\n%s", diff)
	}
}

// ---- Validation tests ----

// TestPolicyValidateDNSProfileNoAssignmentList: a profile with no
// Groups, Users, or Tags is rejected — it could never match any node.
func TestPolicyValidateDNSProfileNoAssignmentList(t *testing.T) {
	pol := `{
		"dns": [
			{ "nameservers": ["9.9.9.9"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	if err == nil {
		t.Fatal("expected validation error for profile with no assignment list, got nil")
	}
	if !errors.Is(err, ErrDNSProfileHasNoAssignmentList) {
		t.Errorf("expected ErrDNSProfileHasNoAssignmentList, got: %v", err)
	}
}

// TestPolicyValidateDNSDuplicatePrincipal: a group / user / tag may
// appear in at most one profile's assignment list.
func TestPolicyValidateDNSDuplicatePrincipal(t *testing.T) {
	cases := map[string]string{
		"group-in-two-profiles": `{
			"groups": { "group:x": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"], "groups": ["group:x"] },
				{ "nameservers": ["1.1.1.1"], "groups": ["group:x"] }
			]
		}`,
		"user-in-two-profiles": `{
			"dns": [
				{ "nameservers": ["9.9.9.9"], "users": ["u@"] },
				{ "nameservers": ["1.1.1.1"], "users": ["u@"] }
			]
		}`,
		"tag-in-two-profiles": `{
			"tagOwners": { "tag:t": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"], "tags": ["tag:t"] },
				{ "nameservers": ["1.1.1.1"], "tags": ["tag:t"] }
			]
		}`,
	}
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
			if err == nil {
				t.Fatal("expected validation error for duplicate principal across profiles, got nil")
			}
			if !errors.Is(err, ErrDNSPrincipalAssignedTwice) {
				t.Errorf("expected ErrDNSPrincipalAssignedTwice, got: %v", err)
			}
		})
	}
}

// TestPolicyValidateDNSUndefinedReference: every referenced group must
// exist in the policy's top-level groups; every tag must exist in
// tagOwners; every username must be syntactically valid.
func TestPolicyValidateDNSUndefinedReference(t *testing.T) {
	cases := map[string]string{
		"undefined-group": `{
			"groups": { "group:defined": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"], "groups": ["group:undefined"] }
			]
		}`,
		"undefined-tag": `{
			"tagOwners": { "tag:defined": ["u@"] },
			"dns": [
				{ "nameservers": ["9.9.9.9"], "tags": ["tag:undefined"] }
			]
		}`,
		"bad-username": `{
			"dns": [
				{ "nameservers": ["9.9.9.9"], "users": ["no-at-sign"] }
			]
		}`,
	}
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	for name, pol := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
			if err == nil {
				t.Fatal("expected validation error for undefined reference, got nil")
			}
		})
	}
}

// TestSetUsersForcesChangeWhenDNSProfilesExist verifies that a user
// update on a policy that has DNS profiles always reports change=true,
// even when the filter / tag-owner / auto-approver hashes are stable.
// A user create / rename can shift which DNS profile a node matches
// (e.g., a new user landing in a group an existing profile assigns) —
// without this carve-out, affected nodes would keep stale DNS until
// the next unrelated policy event.
func TestSetUsersForcesChangeWhenDNSProfilesExist(t *testing.T) {
	// Policy has only DNS profiles, no ACLs / grants / SSH — so the
	// filter and tag-owner hashes are empty/stable across SetUsers.
	pol := `{
		"groups": { "group:eng": ["eng@"] },
		"dns": [
			{ "nameservers": ["9.9.9.9"], "groups": ["group:eng"] }
		]
	}`
	users := types.Users{{Model: gorm.Model{ID: 1}, Name: "u", Email: "u@headscale.net"}}
	pm, err := NewPolicyManager([]byte(pol), users, types.Nodes{}.ViewSlice())
	require.NoError(t, err)

	// Add a new user. With no DNS carve-out, SetUsers would return
	// false (filter/tag/autoapprove hashes haven't moved). With the
	// carve-out, it returns true so map responses get rebroadcast.
	newUsers := append(users, types.User{Model: gorm.Model{ID: 2}, Name: "eng", Email: "eng@headscale.net"})
	changed, err := pm.SetUsers(newUsers)
	require.NoError(t, err)
	if !changed {
		t.Error("SetUsers should report change=true when the policy has DNS profiles, even if other hashes are stable")
	}
}

// ---- applyDNSProfile direct unit tests ----

func TestApplyDNSProfileFieldHandoff(t *testing.T) {
	base := &tailcfg.DNSConfig{
		Resolvers:         []*dnstype.Resolver{{Addr: "base-res"}},
		FallbackResolvers: []*dnstype.Resolver{{Addr: "base-fb"}},
		Routes:            map[string][]*dnstype.Resolver{"old.example": {{Addr: "old-res"}}},
		Domains:           []string{"base.example"},
	}

	t.Run("override-true-clears-fallback", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			Nameservers:      nsList("1.1.1.1"),
			OverrideLocalDNS: boolp(true),
		})
		if got.Resolvers[0].Addr != "1.1.1.1" {
			t.Errorf("Resolvers should be set to profile.Nameservers")
		}
		if got.FallbackResolvers != nil {
			t.Errorf("FallbackResolvers should be cleared when override=true; got %v", got.FallbackResolvers)
		}
	})

	t.Run("override-false-clears-resolvers", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			Nameservers:      nsList("8.8.8.8"),
			OverrideLocalDNS: boolp(false),
		})
		if got.FallbackResolvers[0].Addr != "8.8.8.8" {
			t.Errorf("FallbackResolvers should be set to profile.Nameservers")
		}
		if got.Resolvers != nil {
			t.Errorf("Resolvers should be cleared when override=false; got %v", got.Resolvers)
		}
	})

	t.Run("absent-nameservers-inherits-both", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{})
		if diff := cmp.Diff(base.Resolvers, got.Resolvers); diff != "" {
			t.Errorf("absent nameservers should leave Resolvers inherited; mismatch (-want +got):\n%s", diff)
		}
		if diff := cmp.Diff(base.FallbackResolvers, got.FallbackResolvers); diff != "" {
			t.Errorf("absent nameservers should leave FallbackResolvers inherited; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-nameservers-clears-both", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			Nameservers:      nsList(),
			OverrideLocalDNS: boolp(true),
		})
		if got.Resolvers != nil {
			t.Errorf("present-empty Nameservers with override=true should clear Resolvers; got %v", got.Resolvers)
		}
		if got.FallbackResolvers != nil {
			t.Errorf("FallbackResolvers should be cleared; got %v", got.FallbackResolvers)
		}
	})

	t.Run("override-only-reroutes-inherited-from-fallback-to-resolvers", func(t *testing.T) {
		fbBase := &tailcfg.DNSConfig{
			FallbackResolvers: []*dnstype.Resolver{{Addr: "fb"}},
		}
		got := applyDNSProfile(fbBase, "", DNSProfile{
			OverrideLocalDNS: boolp(true),
		})
		if got.Resolvers == nil || got.Resolvers[0].Addr != "fb" {
			t.Errorf("inherited FallbackResolvers should re-route to Resolvers; got Resolvers=%v", got.Resolvers)
		}
		if got.FallbackResolvers != nil {
			t.Errorf("FallbackResolvers should be cleared after re-route; got %v", got.FallbackResolvers)
		}
	})

	t.Run("override-only-reroutes-inherited-from-resolvers-to-fallback", func(t *testing.T) {
		resBase := &tailcfg.DNSConfig{
			Resolvers: []*dnstype.Resolver{{Addr: "res"}},
		}
		got := applyDNSProfile(resBase, "", DNSProfile{
			OverrideLocalDNS: boolp(false),
		})
		if got.FallbackResolvers == nil || got.FallbackResolvers[0].Addr != "res" {
			t.Errorf("inherited Resolvers should re-route to FallbackResolvers; got FallbackResolvers=%v", got.FallbackResolvers)
		}
		if got.Resolvers != nil {
			t.Errorf("Resolvers should be cleared after re-route; got %v", got.Resolvers)
		}
	})

	t.Run("split-replaces-routes", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			Split: splitMap(map[string][]string{"new.example": {"new-res"}}),
		})
		want := map[string][]*dnstype.Resolver{"new.example": {{Addr: "new-res"}}}
		if diff := cmp.Diff(want, got.Routes); diff != "" {
			t.Errorf("Split should replace Routes; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("absent-split-inherits-routes", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{})
		if diff := cmp.Diff(base.Routes, got.Routes); diff != "" {
			t.Errorf("absent Split should leave Routes inherited; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-split-clears-routes", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			Split: splitMap(map[string][]string{}),
		})
		if len(got.Routes) != 0 {
			t.Errorf("present-empty Split should clear Routes; got %v", got.Routes)
		}
	})

	t.Run("search-domains-replaces-preserving-base-domain", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{
			SearchDomains: &[]string{"new.example"},
		})
		want := []string{"base.example", "new.example"}
		if diff := cmp.Diff(want, got.Domains); diff != "" {
			t.Errorf("SearchDomains should replace Domains[1:] preserving Domains[0]; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("search-domains-no-base-domain-fully-replaces-domains", func(t *testing.T) {
		// When base_domain is unset (yaml has dns.base_domain: "") but
		// dns.search_domains is set, base.Domains contains only search
		// domains. SearchDomains on a profile should fully replace those —
		// NOT promote the first inherited search domain to a "base_domain"
		// slot.
		searchOnlyBase := &tailcfg.DNSConfig{
			Domains: []string{"inherited-search1", "inherited-search2"},
		}
		got := applyDNSProfile(searchOnlyBase, "", DNSProfile{
			SearchDomains: &[]string{"profile-search"},
		})
		want := []string{"profile-search"}
		if diff := cmp.Diff(want, got.Domains); diff != "" {
			t.Errorf("with no base_domain, SearchDomains should fully replace Domains; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("absent-search-domains-leaves-domains-untouched", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{})
		if diff := cmp.Diff(base.Domains, got.Domains); diff != "" {
			t.Errorf("absent SearchDomains should leave Domains untouched; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-search-domains-clears-search-portion", func(t *testing.T) {
		// SearchDomains: &[]string{} is the "present-but-empty" case —
		// it explicitly clears the search-domain portion of Domains,
		// preserving only baseDomain.
		got := applyDNSProfile(base, "base.example", DNSProfile{
			SearchDomains: &[]string{},
		})
		want := []string{"base.example"}
		if diff := cmp.Diff(want, got.Domains); diff != "" {
			t.Errorf("present-empty SearchDomains with baseDomain should yield [baseDomain]; mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("present-empty-search-domains-no-base-domain-clears-all", func(t *testing.T) {
		// SearchDomains: &[]string{} with empty baseDomain → no Domains.
		got := applyDNSProfile(base, "", DNSProfile{
			SearchDomains: &[]string{},
		})
		if len(got.Domains) != 0 {
			t.Errorf("present-empty SearchDomains with no baseDomain should yield empty Domains; got %v", got.Domains)
		}
	})

	t.Run("fully-empty-profile-equals-base", func(t *testing.T) {
		got := applyDNSProfile(base, "base.example", DNSProfile{})
		if diff := cmp.Diff(base, got); diff != "" {
			t.Errorf("a fully-empty profile should produce base.Clone(); mismatch (-want +got):\n%s", diff)
		}
	})
}
