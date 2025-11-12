package policy

import (
	"fmt"
	"net/netip"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"gorm.io/gorm"
	"tailscale.com/net/tsaddr"
	"tailscale.com/types/key"
	"tailscale.com/types/ptr"
	"tailscale.com/types/views"
)

func TestApproveRoutesWithPolicy_NeverRemovesApprovedRoutes(t *testing.T) {
	user1 := types.User{
		Model: gorm.Model{ID: 1},
		Name:  "testuser@",
	}
	user2 := types.User{
		Model: gorm.Model{ID: 2},
		Name:  "otheruser@",
	}
	users := []types.User{user1, user2}

	node1 := &types.Node{
		ID:             1,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "test-node",
		UserID:         ptr.To(user1.ID),
		User:           ptr.To(user1),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           ptr.To(netip.MustParseAddr("100.64.0.1")),
		Tags:           []string{"tag:test"},
	}

	node2 := &types.Node{
		ID:             2,
		MachineKey:     key.NewMachine().Public(),
		NodeKey:        key.NewNode().Public(),
		Hostname:       "other-node",
		UserID:         ptr.To(user2.ID),
		User:           ptr.To(user2),
		RegisterMethod: util.RegisterMethodAuthKey,
		IPv4:           ptr.To(netip.MustParseAddr("100.64.0.2")),
	}

	// Create a policy that auto-approves specific routes
	policyJSON := `{
		"groups": {
			"group:test": ["testuser@"]
		},
		"tagOwners": {
			"tag:test": ["testuser@"]
		},
		"acls": [
			{
				"action": "accept",
				"src": ["*"],
				"dst": ["*:*"]
			}
		],
		"autoApprovers": {
			"routes": {
				"10.0.0.0/8": ["testuser@", "tag:test"],
				"10.1.0.0/24": ["testuser@"],
				"10.2.0.0/24": ["testuser@"],
				"192.168.0.0/24": ["tag:test"]
			}
		}
	}`

	pm, err := policyv2.NewPolicyManager([]byte(policyJSON), users, views.SliceOf([]types.NodeView{node1.View(), node2.View()}))
	assert.NoError(t, err)

	tests := []struct {
		name            string
		node            *types.Node
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
		description     string
	}{
		{
			name: "previously_approved_route_no_longer_advertised_should_remain",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Only this one is still advertised
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"), // Should still be here!
			},
			wantChanged: false,
			description: "Previously approved routes should never be removed even when no longer advertised",
		},
		{
			name: "add_new_auto_approved_route_keeps_old_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.5.0.0/24"), // This was manually approved
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"), // New route that should be auto-approved
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"), // New auto-approved route (subset of 10.0.0.0/8)
				netip.MustParsePrefix("10.5.0.0/24"), // Old approved route kept
			},
			wantChanged: true,
			description: "New auto-approved routes should be added while keeping old approved routes",
		},
		{
			name: "no_announced_routes_keeps_all_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("192.168.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
			},
			announcedRoutes: []netip.Prefix{}, // No routes announced
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("172.16.0.0/16"),
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantChanged: false,
			description: "All approved routes should remain when no routes are announced",
		},
		{
			name: "no_changes_when_announced_equals_approved",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
			description: "No changes should occur when announced routes match approved routes",
		},
		{
			name: "auto_approve_multiple_new_routes",
			node: node1,
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("172.16.0.0/24"), // This was manually approved
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.0/24"),    // Should be auto-approved (subset of 10.0.0.0/8)
				netip.MustParsePrefix("192.168.0.0/24"), // Should be auto-approved for tag:test
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.2.0.0/24"),    // New auto-approved
				netip.MustParsePrefix("172.16.0.0/24"),  // Original kept
				netip.MustParsePrefix("192.168.0.0/24"), // New auto-approved
			},
			wantChanged: true,
			description: "Multiple new routes should be auto-approved while keeping existing approved routes",
		},
		{
			name: "node_without_permission_no_auto_approval",
			node: node2, // Different node without the tag
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"), // This requires tag:test
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"), // Only the original approved route
			},
			wantChanged: false,
			description: "Routes should not be auto-approved for nodes without proper permissions",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotApproved, gotChanged := ApproveRoutesWithPolicy(pm, tt.node.View(), tt.currentApproved, tt.announcedRoutes)

			assert.Equal(t, tt.wantChanged, gotChanged, "changed flag mismatch: %s", tt.description)

			// Sort for comparison since ApproveRoutesWithPolicy sorts the results
			tsaddr.SortPrefixes(tt.wantApproved)
			assert.Equal(t, tt.wantApproved, gotApproved, "approved routes mismatch: %s", tt.description)

			// Verify that all previously approved routes are still present
			for _, prevRoute := range tt.currentApproved {
				assert.Contains(t, gotApproved, prevRoute,
					"previously approved route %s was removed - this should never happen", prevRoute)
			}
		})
	}
}

func TestApproveRoutesWithPolicy_NilAndEmptyCases(t *testing.T) {
	// Create a basic policy for edge case testing
	aclPolicy := `
{
	"acls": [
		{"action": "accept", "src": ["*"], "dst": ["*:*"]},
	],
	"autoApprovers": {
		"routes": {
			"10.1.0.0/24": ["test@"],
		},
	},
}`

	pmfs := PolicyManagerFuncsForTest([]byte(aclPolicy))

	tests := []struct {
		name            string
		currentApproved []netip.Prefix
		announcedRoutes []netip.Prefix
		wantApproved    []netip.Prefix
		wantChanged     bool
	}{
		{
			name: "nil_policy_manager",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("192.168.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
		},
		{
			name:            "nil_current_approved",
			currentApproved: nil,
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name: "nil_announced_routes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			announcedRoutes: nil,
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
			},
			wantChanged: false,
		},
		{
			name: "duplicate_approved_routes",
			currentApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.0.0.0/24"), // Duplicate
			},
			announcedRoutes: []netip.Prefix{
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantApproved: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/24"),
				netip.MustParsePrefix("10.1.0.0/24"),
			},
			wantChanged: true,
		},
		{
			name:            "empty_slices",
			currentApproved: []netip.Prefix{},
			announcedRoutes: []netip.Prefix{},
			wantApproved:    []netip.Prefix{},
			wantChanged:     false,
		},
	}

	for _, tt := range tests {
		for i, pmf := range pmfs {
			t.Run(fmt.Sprintf("%s-policy-index%d", tt.name, i), func(t *testing.T) {
				// Create test user
				user := types.User{
					Model: gorm.Model{ID: 1},
					Name:  "test",
				}
				users := []types.User{user}

				// Create test node
				node := types.Node{
					ID:             1,
					MachineKey:     key.NewMachine().Public(),
					NodeKey:        key.NewNode().Public(),
					Hostname:       "testnode",
					UserID:         ptr.To(user.ID),
					User:           ptr.To(user),
					RegisterMethod: util.RegisterMethodAuthKey,
					IPv4:           ptr.To(netip.MustParseAddr("100.64.0.1")),
					ApprovedRoutes: tt.currentApproved,
				}
				nodes := types.Nodes{&node}

				// Create policy manager or use nil if specified
				var pm PolicyManager
				var err error
				if tt.name != "nil_policy_manager" {
					pm, err = pmf(users, nodes.ViewSlice())
					assert.NoError(t, err)
				} else {
					pm = nil
				}

				gotApproved, gotChanged := ApproveRoutesWithPolicy(pm, node.View(), tt.currentApproved, tt.announcedRoutes)

				assert.Equal(t, tt.wantChanged, gotChanged, "changed flag mismatch")

				// Handle nil vs empty slice comparison
				if tt.wantApproved == nil {
					assert.Nil(t, gotApproved, "expected nil approved routes")
				} else {
					tsaddr.SortPrefixes(tt.wantApproved)
					assert.Equal(t, tt.wantApproved, gotApproved, "approved routes mismatch")
				}
			})
		}
	}
}
