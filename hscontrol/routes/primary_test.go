package routes

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/util/set"
)

// mp is a helper function that wraps netip.MustParsePrefix.
func mp(prefix string) netip.Prefix {
	return netip.MustParsePrefix(prefix)
}

func TestPrimaryRoutes(t *testing.T) {
	tests := []struct {
		name              string
		operations        func(pr *PrimaryRoutes) bool
		expectedRoutes    map[types.NodeID]set.Set[netip.Prefix]
		expectedPrimaries map[netip.Prefix]types.NodeID
		expectedIsPrimary map[types.NodeID]bool
		expectedUnhealthy set.Set[types.NodeID]
		expectedChange    bool

		// primaries is a map of prefixes to the node that is the primary for that prefix.
		primaries map[netip.Prefix]types.NodeID
		isPrimary map[types.NodeID]bool
	}{
		{
			name: "single-node-registers-single-route",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.SetRoutes(1, mp("192.168.1.0/24"))
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: true,
		},
		{
			name: "multiple-nodes-register-different-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				return pr.SetRoutes(2, mp("192.168.2.0/24"))
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.2.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
				mp("192.168.2.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
				2: true,
			},
			expectedChange: true,
		},
		{
			name: "multiple-nodes-register-overlapping-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))        // true
				return pr.SetRoutes(2, mp("192.168.1.0/24")) // false
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: false,
		},
		{
			name: "node-deregisters-a-route",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				return pr.SetRoutes(1) // Deregister by setting no routes
			},
			expectedRoutes:    nil,
			expectedPrimaries: nil,
			expectedIsPrimary: nil,
			expectedChange:    true,
		},
		{
			name: "node-deregisters-one-of-multiple-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"), mp("192.168.2.0/24"))
				return pr.SetRoutes(1, mp("192.168.2.0/24")) // Deregister one route by setting the remaining route
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.2.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.2.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: true,
		},
		{
			name: "node-registers-and-deregisters-routes-in-sequence",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.2.0/24"))
				pr.SetRoutes(1) // Deregister by setting no routes

				return pr.SetRoutes(1, mp("192.168.3.0/24"))
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.3.0/24"): {},
				},
				2: {
					mp("192.168.2.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.2.0/24"): 2,
				mp("192.168.3.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
				2: true,
			},
			expectedChange: true,
		},
		{
			name: "multiple-nodes-register-same-route",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true

				return pr.SetRoutes(3, mp("192.168.1.0/24")) // false
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: false,
		},
		{
			name: "register-multiple-routes-shift-primary-check-primary",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary

				return pr.SetRoutes(1) // true, 2 primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				2: {
					mp("192.168.1.0/24"): {},
				},
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedChange: true,
		},
		{
			name: "primary-route-map-is-cleared-up-no-primary",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary

				return pr.SetRoutes(2) // true, no primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 3,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				3: true,
			},
			expectedChange: true,
		},
		{
			name: "primary-route-map-is-cleared-up-all-no-primary",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary
				pr.SetRoutes(2)                       // true, no primary

				return pr.SetRoutes(3) // false, no primary
			},
			expectedChange: true,
		},
		{
			name: "primary-route-map-is-cleared-up",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary

				return pr.SetRoutes(2) // true, no primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 3,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				3: true,
			},
			expectedChange: true,
		},
		{
			name: "primary-route-no-flake",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary

				return pr.SetRoutes(1, mp("192.168.1.0/24")) // false, 2 primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedChange: false,
		},
		{
			name: "primary-route-no-flake-check-old-primary",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary

				return pr.SetRoutes(1, mp("192.168.1.0/24")) // false, 2 primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedChange: false,
		},
		{
			name: "primary-route-no-flake-full-integration",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24")) // false
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 1 primary
				pr.SetRoutes(3, mp("192.168.1.0/24")) // false, 1 primary
				pr.SetRoutes(1)                       // true, 2 primary
				pr.SetRoutes(2)                       // true, 3 primary
				pr.SetRoutes(1, mp("192.168.1.0/24")) // true, 3 primary
				pr.SetRoutes(2, mp("192.168.1.0/24")) // true, 3 primary
				pr.SetRoutes(1)                       // true, 3 primary

				return pr.SetRoutes(1, mp("192.168.1.0/24")) // false, 3 primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
				3: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 3,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				3: true,
			},
			expectedChange: false,
		},
		{
			name: "multiple-nodes-register-same-route-and-exit",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("0.0.0.0/0"), mp("192.168.1.0/24"))
				return pr.SetRoutes(2, mp("192.168.1.0/24"))
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.1.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: false,
		},
		{
			name: "deregister-non-existent-route",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.SetRoutes(1) // Deregister by setting no routes
			},
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "register-empty-prefix-list",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.SetRoutes(1)
			},
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "exit-nodes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("10.0.0.0/16"), mp("0.0.0.0/0"), mp("::/0"))
				pr.SetRoutes(3, mp("0.0.0.0/0"), mp("::/0"))

				return pr.SetRoutes(2, mp("0.0.0.0/0"), mp("::/0"))
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("10.0.0.0/16"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("10.0.0.0/16"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedChange: false,
		},
		{
			name: "unhealthy-primary-fails-over",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))

				return pr.SetNodeHealthy(1, false)
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedUnhealthy: set.Set[types.NodeID]{1: {}},
			expectedChange:    true,
		},
		{
			name: "unhealthy-non-primary-no-change",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))

				return pr.SetNodeHealthy(2, false)
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedUnhealthy: set.Set[types.NodeID]{2: {}},
			expectedChange:    false,
		},
		{
			name: "all-unhealthy-keeps-current-primary",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetNodeHealthy(1, false) // failover to 2

				return pr.SetNodeHealthy(2, false) // both unhealthy, falls back to first sorted (1)
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
			},
			expectedUnhealthy: set.Set[types.NodeID]{1: {}, 2: {}},
			expectedChange:    true,
		},
		{
			name: "recovery-marks-healthy-no-flap",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetRoutes(3, mp("192.168.1.0/24"))
				pr.SetNodeHealthy(1, false) // failover to 2

				return pr.SetNodeHealthy(1, true) // recovered, but 2 stays primary
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
				3: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedChange: false,
		},
		{
			name: "clear-unhealthy-on-reconnect",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetNodeHealthy(1, false) // failover to 2
				pr.ClearUnhealthy(1)        // reconnect clears unhealthy

				// 2 stays primary (stability), but 1 is healthy again
				return pr.SetNodeHealthy(1, false) // can be marked unhealthy again
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedUnhealthy: set.Set[types.NodeID]{1: {}},
			expectedChange:    false,
		},
		{
			name: "unhealthy-then-deregister",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetNodeHealthy(1, false)

				return pr.SetRoutes(1) // deregister clears routes and unhealthy
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				2: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				2: true,
			},
			expectedChange: false,
		},
		{
			name: "unhealthy-primary-three-nodes-cascade",
			operations: func(pr *PrimaryRoutes) bool {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetRoutes(3, mp("192.168.1.0/24"))
				pr.SetNodeHealthy(1, false) // failover to 2

				return pr.SetNodeHealthy(2, false) // failover to 3
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {mp("192.168.1.0/24"): {}},
				2: {mp("192.168.1.0/24"): {}},
				3: {mp("192.168.1.0/24"): {}},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 3,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				3: true,
			},
			expectedUnhealthy: set.Set[types.NodeID]{1: {}, 2: {}},
			expectedChange:    true,
		},
		{
			name: "concurrent-access",
			operations: func(pr *PrimaryRoutes) bool {
				var wg sync.WaitGroup
				wg.Add(2)

				var change1, change2 bool

				go func() {
					defer wg.Done()

					change1 = pr.SetRoutes(1, mp("192.168.1.0/24"))
				}()
				go func() {
					defer wg.Done()

					change2 = pr.SetRoutes(2, mp("192.168.2.0/24"))
				}()

				wg.Wait()

				return change1 || change2
			},
			expectedRoutes: map[types.NodeID]set.Set[netip.Prefix]{
				1: {
					mp("192.168.1.0/24"): {},
				},
				2: {
					mp("192.168.2.0/24"): {},
				},
			},
			expectedPrimaries: map[netip.Prefix]types.NodeID{
				mp("192.168.1.0/24"): 1,
				mp("192.168.2.0/24"): 2,
			},
			expectedIsPrimary: map[types.NodeID]bool{
				1: true,
				2: true,
			},
			expectedChange: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := New()

			change := tt.operations(pr)
			if change != tt.expectedChange {
				t.Errorf("change = %v, want %v", change, tt.expectedChange)
			}

			comps := append(util.Comparers, cmpopts.EquateEmpty())
			if diff := cmp.Diff(tt.expectedRoutes, pr.routes, comps...); diff != "" {
				t.Errorf("routes mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.expectedPrimaries, pr.primaries, comps...); diff != "" {
				t.Errorf("primaries mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.expectedIsPrimary, pr.isPrimary, comps...); diff != "" {
				t.Errorf("isPrimary mismatch (-want +got):\n%s", diff)
			}

			if diff := cmp.Diff(tt.expectedUnhealthy, pr.unhealthy, comps...); diff != "" {
				t.Errorf("unhealthy mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestHANodes(t *testing.T) {
	tests := []struct {
		name     string
		setup    func(pr *PrimaryRoutes)
		expected map[netip.Prefix][]types.NodeID
	}{
		{
			name: "single-node-not-ha",
			setup: func(pr *PrimaryRoutes) {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
			},
			expected: nil,
		},
		{
			name: "two-nodes-same-prefix-is-ha",
			setup: func(pr *PrimaryRoutes) {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
			},
			expected: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "two-nodes-different-prefixes-not-ha",
			setup: func(pr *PrimaryRoutes) {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.2.0/24"))
			},
			expected: nil,
		},
		{
			name: "three-nodes-two-share-prefix",
			setup: func(pr *PrimaryRoutes) {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetRoutes(3, mp("10.0.0.0/8"))
			},
			expected: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2},
			},
		},
		{
			name: "three-nodes-all-share",
			setup: func(pr *PrimaryRoutes) {
				pr.SetRoutes(1, mp("192.168.1.0/24"))
				pr.SetRoutes(2, mp("192.168.1.0/24"))
				pr.SetRoutes(3, mp("192.168.1.0/24"))
			},
			expected: map[netip.Prefix][]types.NodeID{
				mp("192.168.1.0/24"): {1, 2, 3},
			},
		},
		{
			name: "empty",
			setup: func(_ *PrimaryRoutes) {
			},
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := New()
			tt.setup(pr)

			got := pr.HANodes()

			comps := append(util.Comparers, cmpopts.EquateEmpty())
			if diff := cmp.Diff(tt.expected, got, comps...); diff != "" {
				t.Errorf("HANodes mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
