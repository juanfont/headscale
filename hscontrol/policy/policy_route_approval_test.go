package policy

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
)

func TestApproveRoutesWithPolicy_NeverRemovesRoutes(t *testing.T) {
	// Test policy that allows specific routes to be auto-approved
	aclPolicy := `
{
	"groups": {
		"group:admins": ["test@"],
	},
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"autoApprovers": {
		"routes": {
			"10.0.0.0/24": ["test@"],
			"192.168.0.0/24": ["group:admins"],
			"172.16.0.0/16": ["tag:approved"],
		},
	},
	"tagOwners": {
		"tag:approved": ["test@"],
	},
}`

	tests := []struct {
		name              string
		currentApproved   []netip.Prefix
		announcedRoutes   []netip.Prefix
		nodeHostname      string
		nodeUser          string
		nodeTags          []string
		wantApproved      []netip.Prefix
		wantChanged       bool
		wantRemovedRoutes []netip.Prefix // Routes that should NOT be in the result
	}{
		{
			name: "previously_approved_route_no_longer_advertised_remains",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"), // Only this one still advertised
			},
			nodeUser: "test",
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Should remain!
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantChanged:       false,
			wantRemovedRoutes: []netip.Prefix{}, // Nothing should be removed
		},
		{
			name: "add_new_auto_approved_route_keeps_existing",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),    // Still advertised
				netip.MustParsePrefix("192.168.0.0/24"), // New route
			},
			nodeUser: "test",
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"), // Auto-approved via group
			},
			wantChanged: true,
		},
		{
			name: "no_announced_routes_keeps_all_approved",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			announcedRoutes: []netip.Prefix{}, // No routes announced anymore
			nodeUser:        "test",
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantChanged: false,
		},
		{
			name: "manually_approved_route_not_in_policy_remains",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("203.0.113.0/24"), // Not in auto-approvers
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Can be auto-approved
			},
			nodeUser: "test",
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),    // New auto-approved
				netip.MustParsePrefix("203.0.113.0/24"), // Manual approval preserved
			},
			wantChanged: true,
		},
		{
			name: "tagged_node_gets_tag_approved_routes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/16"), // Tag-approved route
			},
			nodeUser: "test",
			nodeTags: []string{"tag:approved"},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/16"), // New tag-approved
				netip.MustParsePrefix("10.0.0.0/24"),   // Previous approval preserved
			},
			wantChanged: true,
		},
		{
			name: "complex_scenario_multiple_changes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),    // Will not be advertised
				netip.MustParsePrefix("203.0.113.0/24"), // Manual, not advertised
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),  // New, auto-approvable
				netip.MustParsePrefix("172.16.0.0/16"),   // New, not approvable (no tag)
				netip.MustParsePrefix("198.51.100.0/24"), // New, not in policy
			},
			nodeUser: "test",
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),    // Kept despite not advertised
				netip.MustParsePrefix("192.168.0.0/24"), // New auto-approved
				netip.MustParsePrefix("203.0.113.0/24"), // Kept despite not advertised
			},
			wantChanged: true,
		},
	}

	pmfs := PolicyManagerFuncsForTest([]byte(aclPolicy))

	for _, tt := range tests {
		for i, pmf := range pmfs {
			t.Run(fmt.Sprintf("%s-policy-index%d", tt.name, i), func(t *testing.T) {
				// Create test user
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  tt.nodeUser,
				}
				users := []types.User{user}

				// Create test node
				node := types.Node{
					ID:             1,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       tt.nodeHostname,
					UserID:         user.ID,
					User:           user,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.announcedRoutes,
					},
					IPv4:           ptr.To(netip.MustParseAddr("100.64.0.1")),
					ApprovedRoutes: tt.currentApproved,
					ForcedTags:     tt.nodeTags,
				}
				nodes := types.Nodes{&node}

				// Create policy manager
				pm, err := pmf(users, nodes.ViewSlice())
				require.NoError(t, err)
				require.NotNil(t, pm)

				// Test ApproveRoutesWithPolicy
				gotApproved, gotChanged := ApproveRoutesWithPolicy(
					pm,
					node.View(),
					tt.currentApproved,
					tt.announcedRoutes,
				)

				// Check change flag
				assert.Equal(t, tt.wantChanged, gotChanged, "change flag mismatch")

				// Check approved routes match expected
				if diff := cmp.Diff(tt.wantApproved, gotApproved, util.Comparers...); diff != "" {
					t.Logf("Want: %v", tt.wantApproved)
					t.Logf("Got:  %v", gotApproved)
					t.Errorf("unexpected approved routes (-want +got):\n%s", diff)
				}

				// Verify all previously approved routes are still present
				for _, prevRoute := range tt.currentApproved {
					assert.Contains(t, gotApproved, prevRoute,
						"previously approved route %s was removed - this should NEVER happen", prevRoute)
				}

				// Verify no routes were incorrectly removed
				for _, removedRoute := range tt.wantRemovedRoutes {
					assert.NotContains(t, gotApproved, removedRoute,
						"route %s should have been removed but wasn't", removedRoute)
				}
			})
		}
	}
}

func TestApproveRoutesWithPolicy_EdgeCases(t *testing.T) {
	aclPolicy := `
{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"autoApprovers": {
		"routes": {
			"10.0.0.0/8": ["test@"],
		},
	},
}`

	tests := []struct {
		name            string
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
	}{
		{
			name:            "nil_current_approved",
			currentApproved: nil,
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name:            "empty_current_approved",
			currentApproved: []netip.Prefix{},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name: "duplicate_routes_handled",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.0.0.0/24"), // Duplicate
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: true, // Duplicates are removed, so it's a change
		},
	}

	pmfs := PolicyManagerFuncsForTest([]byte(aclPolicy))

	for _, tt := range tests {
		for i, pmf := range pmfs {
			t.Run(fmt.Sprintf("%s-policy-index%d", tt.name, i), func(t *testing.T) {
				// Create test user
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  "test",
				}
				users := []types.User{user}

				node := types.Node{
					ID:             1,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "testnode",
					UserID:         user.ID,
					User:           user,
					RegisterMethod: util.RegisterMethodAuthKey,
					Hostinfo: &tailcfg.Hostinfo{
						RoutableIPs: tt.announcedRoutes,
					},
					IPv4:           ptr.To(netip.MustParseAddr("100.64.0.1")),
					ApprovedRoutes: tt.currentApproved,
				}
				nodes := types.Nodes{&node}

				pm, err := pmf(users, nodes.ViewSlice())
				require.NoError(t, err)

				gotApproved, gotChanged := ApproveRoutesWithPolicy(
					pm,
					node.View(),
					tt.currentApproved,
					tt.announcedRoutes,
				)

				assert.Equal(t, tt.wantChanged, gotChanged)

				if diff := cmp.Diff(tt.wantApproved, gotApproved, util.Comparers...); diff != "" {
					t.Errorf("unexpected approved routes (-want +got):\n%s", diff)
				}
			})
		}
	}
}

func TestApproveRoutesWithPolicy_NilPolicyManagerCase(t *testing.T) {
	user := types.User{
		Model: gorm.Model{ID: 1},
		Name:  "test",
	}

	currentApproved := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/24"),
	}
	announcedRoutes := []netip.Prefix{
		netip.MustParsePrefix("192.168.0.0/24"),
	}

	node := types.Node{
		ID:             1,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "testnode",
		UserID:         user.ID,
		User:           user,
		RegisterMethod: util.RegisterMethodAuthKey,
		Hostinfo: &tailcfg.Hostinfo{
			RoutableIPs: announcedRoutes,
		},
		IPv4:           ptr.To(netip.MustParseAddr("100.64.0.1")),
		ApprovedRoutes: currentApproved,
	}

	// With nil policy manager, should return current approved unchanged
	gotApproved, gotChanged := ApproveRoutesWithPolicy(nil, node.View(), currentApproved, announcedRoutes)

	assert.False(t, gotChanged)
	assert.Equal(t, currentApproved, gotApproved)
}
