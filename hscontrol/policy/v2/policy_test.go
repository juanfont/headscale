package v2

import (
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
)

func node(name, ipv4, ipv6 string, user types.User, hostinfo *tailcfg.Hostinfo) *types.Node {
	return &types.Node{
		ID:       0,
		Hostname: name,
		IPv4:     ap(ipv4),
		IPv6:     ap(ipv6),
		User:     user,
		UserID:   user.ID,
		Hostinfo: hostinfo,
	}
}

func TestPolicyManager(t *testing.T) {
	users := types.Users{
		{Model: gorm.Model{ID: 1}, Name: "testuser", Email: "testuser@headscale.net"},
		{Model: gorm.Model{ID: 2}, Name: "otheruser", Email: "otheruser@headscale.net"},
	}

	tests := []struct {
		name       string
		pol        string
		nodes      types.Nodes
		wantFilter []tailcfg.FilterRule
	}{
		{
			name:       "empty-policy",
			pol:        "{}",
			nodes:      types.Nodes{},
			wantFilter: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm, err := NewPolicyManager([]byte(tt.pol), users, tt.nodes)
			require.NoError(t, err)

			filter := pm.Filter()
			if diff := cmp.Diff(filter, tt.wantFilter); diff != "" {
				t.Errorf("Filter() mismatch (-want +got):\n%s", diff)
			}

			// TODO(kradalby): Test SSH Policy
		})
	}
}
