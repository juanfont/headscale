package apiv2

import (
	"net/netip"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"tailscale.com/tailcfg"
	"tailscale.com/types/opt"
)

// TestDeviceHostDetail pins where each host detail comes from, and that only
// blocksIncomingConnections leaves the fields=all shape.
func TestDeviceHostDetail(t *testing.T) {
	t.Parallel()

	node := &types.Node{
		GivenName: "host",
		Endpoints: []netip.AddrPort{netip.MustParseAddrPort("192.0.2.1:41641")},
		Hostinfo: &tailcfg.Hostinfo{
			ShieldsUp:      true,
			Distro:         "nixos",
			DistroVersion:  "26.05",
			DistroCodeName: "yarara",
			SSH_HostKeys:   []string{"ssh-ed25519 AAAA"},
			NetInfo: &tailcfg.NetInfo{
				MappingVariesByDestIP: opt.NewBool(true),
				WorkingUDP:            opt.NewBool(true),
				UPnP:                  opt.NewBool(true),
			},
		},
	}

	short := deviceFromView(node.View(), false, "")
	assert.True(t, short.BlocksIncomingConnections)
	assert.Nil(t, short.SSHEnabled)
	assert.Nil(t, short.Distro)
	assert.Nil(t, short.ClientConnectivity)

	all := deviceFromView(node.View(), true, "")
	assert.True(t, *all.SSHEnabled)
	assert.Equal(t, Distro{Name: "nixos", Version: "26.05", CodeName: "yarara"}, *all.Distro)
	assert.Equal(t, ClientConnectivity{
		Endpoints:             []string{"192.0.2.1:41641"},
		MappingVariesByDestIP: true,
		Latency:               map[string]any{},
		ClientSupports:        ClientSupports{UDP: true, UPnP: true},
	}, *all.ClientConnectivity)

	// A node that has reported nothing still has the fields=all shape.
	bare := deviceFromView((&types.Node{GivenName: "bare"}).View(), true, "")
	assert.False(t, *bare.SSHEnabled)
	assert.Equal(t, Distro{}, *bare.Distro)
	assert.Equal(t, []string{}, bare.ClientConnectivity.Endpoints)
}
