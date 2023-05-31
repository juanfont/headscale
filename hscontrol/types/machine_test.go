package types

import (
	"net/netip"
	"testing"

	"tailscale.com/tailcfg"
)

func Test_MachineCanAccess(t *testing.T) {
	tests := []struct {
		name     string
		machine1 Machine
		machine2 Machine
		rules    []tailcfg.FilterRule
		want     bool
	}{
		{
			name: "other-cant-access-src",
			machine1: Machine{
				ID:          0,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.1")},
				Hostname:    "mini",
				User:        User{Name: "mini"},
			},
			machine2: Machine{
				ID:          2,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
				Hostname:    "peer2",
				User:        User{Name: "peer2"},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "dest-cant-access-src",
			machine1: Machine{
				ID:          2,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
				Hostname:    "peer2",
				User:        User{Name: "peer2"},
			},
			machine2: Machine{
				ID:          0,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
				Hostname:    "mini",
				User:        User{Name: "mini"},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: false,
		},
		{
			name: "src-can-access-dest",
			machine1: Machine{
				ID:          0,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.2")},
				Hostname:    "mini",
				User:        User{Name: "mini"},
			},
			machine2: Machine{
				ID:          2,
				IPAddresses: []netip.Addr{netip.MustParseAddr("100.64.0.3")},
				Hostname:    "peer2",
				User:        User{Name: "peer2"},
			},
			rules: []tailcfg.FilterRule{
				{
					SrcIPs: []string{"100.64.0.2/32"},
					DstPorts: []tailcfg.NetPortRange{
						{IP: "100.64.0.3/32", Ports: tailcfg.PortRangeAny},
					},
				},
			},
			want: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.machine1.CanAccess(tt.rules, &tt.machine2)

			if got != tt.want {
				t.Errorf("canAccess() failed: want (%t), got (%t)", tt.want, got)
			}
		})
	}
}
