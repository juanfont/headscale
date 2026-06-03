package v2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

// TestNodeNeedsPeerRecompute pins which node roles force peers to recompute
// their netmap when the node's online state changes. An ordinary node only
// needs the lightweight online/offline peer patch; subnet routers, relay
// targets, and via targets change what peers compute and therefore need a
// full recompute. The predicate is keyed on the flipping node, so an ordinary
// node in a tailnet that uses relay or via elsewhere must still be classified
// as not needing a recompute.
func TestNodeNeedsPeerRecompute(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "user1", Email: "user1@headscale.net"},
	}

	const allowAll = `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`

	relayPol := `{
		"tagOwners": {"tag:relay": ["user1@"]},
		"grants": [
			{"src": ["*"], "dst": ["tag:relay"], "app": {"tailscale.com/cap/relay": [{}]}}
		]
	}`

	viaPol := `{
		"tagOwners": {"tag:via": ["user1@"]},
		"grants": [
			{"src": ["*"], "dst": ["10.0.0.0/24"], "ip": ["*"], "via": ["tag:via"]}
		]
	}`

	taildrivePol := `{
		"tagOwners": {"tag:drive": ["user1@"]},
		"grants": [
			{"src": ["*"], "dst": ["tag:drive"], "app": {"tailscale.com/cap/drive": [{}]}}
		]
	}`

	ordinary := node("ordinary", "100.64.0.1", "fd7a:115c:a1e0::1", users[0])
	ordinary.ID = 1

	subnetRouter := node("subnet", "100.64.0.2", "fd7a:115c:a1e0::2", users[0])
	subnetRouter.ID = 2
	subnetRouter.Hostinfo = &tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")},
	}
	subnetRouter.ApprovedRoutes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/24")}

	relayTarget := node("relay", "100.64.0.3", "fd7a:115c:a1e0::3", users[0])
	relayTarget.ID = 3
	relayTarget.Tags = []string{"tag:relay"}

	viaTarget := node("via", "100.64.0.4", "fd7a:115c:a1e0::4", users[0])
	viaTarget.ID = 4
	viaTarget.Tags = []string{"tag:via"}

	driveTarget := node("drive", "100.64.0.5", "fd7a:115c:a1e0::5", users[0])
	driveTarget.ID = 5
	driveTarget.Tags = []string{"tag:drive"}

	tests := []struct {
		name    string
		pol     string
		nodes   types.Nodes
		subject *types.Node
		want    bool
	}{
		{
			name:    "ordinary node under allow-all does not need recompute",
			pol:     allowAll,
			nodes:   types.Nodes{ordinary},
			subject: ordinary,
			want:    false,
		},
		{
			name:    "subnet router needs recompute",
			pol:     allowAll,
			nodes:   types.Nodes{subnetRouter},
			subject: subnetRouter,
			want:    true,
		},
		{
			name:    "relay target needs recompute",
			pol:     relayPol,
			nodes:   types.Nodes{relayTarget, ordinary},
			subject: relayTarget,
			want:    true,
		},
		{
			name:    "ordinary node in a relay-using tailnet does not need recompute",
			pol:     relayPol,
			nodes:   types.Nodes{relayTarget, ordinary},
			subject: ordinary,
			want:    false,
		},
		{
			name:    "via target needs recompute",
			pol:     viaPol,
			nodes:   types.Nodes{viaTarget, ordinary},
			subject: viaTarget,
			want:    true,
		},
		{
			name:    "ordinary node in a via-using tailnet does not need recompute",
			pol:     viaPol,
			nodes:   types.Nodes{viaTarget, ordinary},
			subject: ordinary,
			want:    false,
		},
		{
			name:    "taildrive target does not need recompute",
			pol:     taildrivePol,
			nodes:   types.Nodes{driveTarget, ordinary},
			subject: driveTarget,
			want:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes.ViewSlice())
			require.NoError(t, err)

			got := pm.NodeNeedsPeerRecompute(tt.subject.View())
			require.Equal(t, tt.want, got)
		})
	}
}
