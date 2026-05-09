// Unit tests for OIDC-asserted group resolution in policy v2.
//
// Validates that Group.Resolve matches not only by user identifier
// (upstream behaviour) but also by a user's persisted OIDC groups claim.
package v2

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"gorm.io/gorm"
	"tailscale.com/types/views"
)

func TestGroupResolve_MatchesOIDCGroupClaim(t *testing.T) {
	alice := types.User{
		Model:  gorm.Model{ID: 1},
		Name:   "alice@example.com",
		Email:  "alice@example.com",
		Groups: []string{"group1", "group2"},
	}
	bob := types.User{
		Model:  gorm.Model{ID: 2},
		Name:   "bob@example.com",
		Email:  "bob@example.com",
		Groups: []string{"group3"},
	}
	// A user whose identifier literally matches a group reference (the
	// upstream resolution path). Ensures the union with the IdP-claim
	// path keeps working.
	literal := types.User{
		Model: gorm.Model{ID: 3},
		Name:  "group1",
	}

	users := types.Users{alice, bob, literal}

	aliceNode := nodeWithIPs(t, 1, "100.64.0.1")
	bobNode := nodeWithIPs(t, 2, "100.64.0.2")
	literalNode := nodeWithIPs(t, 3, "100.64.0.3")

	nodes := views.SliceOf([]types.NodeView{
		aliceNode.View(), bobNode.View(), literalNode.View(),
	})

	tests := []struct {
		name       string
		members    []Username
		wantPfxStr []string
	}{
		{
			name:    "resolves group by IdP claim and literal username",
			members: []Username{"group1@"},
			wantPfxStr: []string{
				"100.64.0.1/32", // alice carries group1 in her groups claim
				"100.64.0.3/32", // literal user named group1
			},
		},
		{
			name:    "resolves distinct IdP group",
			members: []Username{"group3@"},
			wantPfxStr: []string{
				"100.64.0.2/32", // bob only
			},
		},
		{
			name:       "returns empty set when group unmatched",
			members:    []Username{"unknown@"},
			wantPfxStr: []string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			pol := &Policy{
				Groups: Groups{
					Group("group:test"): tc.members,
				},
			}
			g := Group("group:test")
			resolved, err := g.Resolve(pol, users, nodes)
			if err != nil && len(tc.wantPfxStr) > 0 {
				t.Fatalf("unexpected error: %v", err)
			}

			var got []string
			if resolved != nil {
				got = prefixStrings(resolved.Prefixes())
			}
			if diff := cmp.Diff(tc.wantPfxStr, got); diff != "" {
				t.Errorf("prefix mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

// nodeWithIPs constructs a minimal Node owned by user ID uid carrying a
// single IPv4 address so we can exercise Group.Resolve.
func nodeWithIPs(t *testing.T, uid uint, ip string) *types.Node {
	t.Helper()
	addr := netip.MustParseAddr(ip)
	uidCopy := uid
	return &types.Node{
		ID:       types.NodeID(uid),
		UserID:   &uidCopy,
		User:     &types.User{Model: gorm.Model{ID: uid}},
		IPv4:     &addr,
		Hostname: "n",
	}
}

// TestPolicyManagerSetUsersRefreshesOIDCGroupResolution exercises the
// live-update path that runs after an OIDC login (State.UpdateUser →
// updatePolicyManagerUsers → PolicyManager.SetUsers). A user whose
// Groups claim is newly populated must be picked up by group:* sources
// without requiring a server restart.
func TestPolicyManagerSetUsersRefreshesOIDCGroupResolution(t *testing.T) {
	alice := types.User{
		Model: gorm.Model{ID: 1},
		Name:  "alice@example.com",
		Email: "alice@example.com",
	}
	uid := alice.ID
	v4 := netip.MustParseAddr("100.64.0.1")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
	aliceNode := &types.Node{
		ID:       1,
		Hostname: "alice-node",
		User:     &alice,
		UserID:   &uid,
		IPv4:     &v4,
		IPv6:     &v6,
	}

	policy := []byte(`{
		"groups": {
			"group:test": ["group1@"]
		},
		"acls": [
			{
				"action": "accept",
				"src":    ["group:test"],
				"dst":    ["*:*"]
			}
		]
	}`)

	pm, err := NewPolicyManager(
		policy,
		types.Users{alice},
		types.Nodes{aliceNode}.ViewSlice(),
	)
	if err != nil {
		t.Fatalf("NewPolicyManager: %v", err)
	}

	// Without a Groups claim, group:test resolves to nothing and the rule
	// is dropped before reaching the global filter.
	filter, _ := pm.Filter()
	if len(filter) != 0 {
		t.Fatalf("expected empty filter before SetUsers, got %d rule(s): %+v", len(filter), filter)
	}

	aliceWithGroups := alice
	aliceWithGroups.Groups = []string{"group1"}

	changed, err := pm.SetUsers(types.Users{aliceWithGroups})
	if err != nil {
		t.Fatalf("SetUsers: %v", err)
	}
	if !changed {
		t.Fatalf("SetUsers returned changed=false; expected the new groups claim to invalidate the cached filter")
	}

	filter, _ = pm.Filter()
	if len(filter) != 1 {
		t.Fatalf("expected one filter rule after SetUsers populated the groups claim, got %d: %+v", len(filter), filter)
	}

	want := []string{"100.64.0.1", "fd7a:115c:a1e0::1"}
	if diff := cmp.Diff(want, filter[0].SrcIPs); diff != "" {
		t.Errorf("SrcIPs mismatch (-want +got):\n%s", diff)
	}
}
