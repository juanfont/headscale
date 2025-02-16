package routes

import (
	"net/netip"
	"sync"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

// mp is a helper function that wraps netip.MustParsePrefix.
func mp(prefix string) netip.Prefix {
	return netip.MustParsePrefix(prefix)
}

func TestPrimaryRoutes(t *testing.T) {
	tests := []struct {
		name           string
		operations     func(pr *PrimaryRoutes) bool
		nodeID         types.NodeID
		expectedRoutes []netip.Prefix
		expectedChange bool
	}{
		{
			name: "single-node-registers-single-route",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.RegisterRoutes(1, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "multiple-nodes-register-different-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"))
				return pr.RegisterRoutes(2, mp("192.168.2.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "multiple-nodes-register-overlapping-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"))        // false
				return pr.RegisterRoutes(2, mp("192.168.1.0/24")) // true
			},
			nodeID:         1,
			expectedRoutes: []netip.Prefix{mp("192.168.1.0/24")},
			expectedChange: true,
		},
		{
			name: "node-deregisters-a-route",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"))
				return pr.DeregisterRoutes(1, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "node-deregisters-one-of-multiple-routes",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"), mp("192.168.2.0/24"))
				return pr.DeregisterRoutes(1, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "node-registers-and-deregisters-routes-in-sequence",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"))
				pr.RegisterRoutes(2, mp("192.168.2.0/24"))
				pr.DeregisterRoutes(1, mp("192.168.1.0/24"))
				return pr.RegisterRoutes(1, mp("192.168.3.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "no-change-in-primary-routes",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.RegisterRoutes(1, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "multiple-nodes-register-same-route",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("192.168.1.0/24"))        // false
				pr.RegisterRoutes(2, mp("192.168.1.0/24"))        // true
				return pr.RegisterRoutes(3, mp("192.168.1.0/24")) // false
			},
			nodeID:         1,
			expectedRoutes: []netip.Prefix{mp("192.168.1.0/24")},
			expectedChange: false,
		},
		{
			name: "multiple-nodes-register-same-route-and-exit",
			operations: func(pr *PrimaryRoutes) bool {
				pr.RegisterRoutes(1, mp("0.0.0.0/0"), mp("192.168.1.0/24"))
				return pr.RegisterRoutes(2, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: []netip.Prefix{mp("192.168.1.0/24")},
			expectedChange: true,
		},
		{
			name: "deregister-non-existent-route",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.DeregisterRoutes(1, mp("192.168.1.0/24"))
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "register-empty-prefix-list",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.RegisterRoutes(1)
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "deregister-empty-prefix-list",
			operations: func(pr *PrimaryRoutes) bool {
				return pr.DeregisterRoutes(1)
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "concurrent-access",
			operations: func(pr *PrimaryRoutes) bool {
				var wg sync.WaitGroup
				wg.Add(2)
				var change1, change2 bool
				go func() {
					defer wg.Done()
					change1 = pr.RegisterRoutes(1, mp("192.168.1.0/24"))
				}()
				go func() {
					defer wg.Done()
					change2 = pr.RegisterRoutes(2, mp("192.168.2.0/24"))
				}()
				wg.Wait()
				return change1 || change2
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
		{
			name: "no-routes-registered",
			operations: func(pr *PrimaryRoutes) bool {
				// No operations
				return false
			},
			nodeID:         1,
			expectedRoutes: nil,
			expectedChange: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pr := New()
			change := tt.operations(pr)
			if change != tt.expectedChange {
				t.Errorf("change = %v, want %v", change, tt.expectedChange)
			}
			routes := pr.PrimaryRoutes(tt.nodeID)
			if diff := cmp.Diff(tt.expectedRoutes, routes, util.Comparers...); diff != "" {
				t.Errorf("PrimaryRoutes() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}
