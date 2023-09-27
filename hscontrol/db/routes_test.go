package db

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"gopkg.in/check.v1"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

func (s *Suite) TestGetRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_get_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix("10.0.0.0/24")
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route},
	}

	node := types.Node{
		ID:             0,
		Hostname:       "test_get_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Hostinfo:       &hostInfo,
	}
	db.db.Save(&node)

	err = db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)

	advertisedRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route, route2},
	}

	node := types.Node{
		ID:             0,
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Hostinfo:       &hostInfo,
	}
	db.db.Save(&node)

	err = db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)

	availableRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	err = db.enableRoutes(&node, "150.0.10.0/25")
	c.Assert(err, check.IsNil)

	enabledRoutesWithAdditionalRoute, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutesWithAdditionalRoute), check.Equals, 2)
}

func (s *Suite) TestIsUniquePrefix(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	route, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	route2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route, route2},
	}
	node1 := types.Node{
		ID:             1,
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Hostinfo:       &hostInfo1,
	}
	db.db.Save(&node1)

	err = db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, route.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, route2.String())
	c.Assert(err, check.IsNil)

	hostInfo2 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{route2},
	}
	node2 := types.Node{
		ID:             2,
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Hostinfo:       &hostInfo2,
	}
	db.db.Save(&node2)

	err = db.SaveNodeRoutes(&node2)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node2, route2.String())
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 2)

	enabledRoutes2, err := db.GetEnabledRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes2), check.Equals, 1)

	routes, err := db.GetNodePrimaryRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 2)

	routes, err = db.GetNodePrimaryRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(len(routes), check.Equals, 0)
}

func (s *Suite) TestDeleteRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.GetNode("test", "test_enable_route_node")
	c.Assert(err, check.NotNil)

	prefix, err := netip.ParsePrefix(
		"10.0.0.0/24",
	)
	c.Assert(err, check.IsNil)

	prefix2, err := netip.ParsePrefix(
		"150.0.10.0/25",
	)
	c.Assert(err, check.IsNil)

	hostInfo1 := tailcfg.Hostinfo{
		RoutableIPs: []netip.Prefix{prefix, prefix2},
	}

	now := time.Now()
	node1 := types.Node{
		ID:             1,
		Hostname:       "test_enable_route_node",
		UserID:         user.ID,
		RegisterMethod: util.RegisterMethodAuthKey,
		AuthKeyID:      uint(pak.ID),
		Hostinfo:       &hostInfo1,
		LastSeen:       &now,
	}
	db.db.Save(&node1)

	err = db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix.String())
	c.Assert(err, check.IsNil)

	err = db.enableRoutes(&node1, prefix2.String())
	c.Assert(err, check.IsNil)

	routes, err := db.GetNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	err = db.DeleteRoute(uint64(routes[0].ID))
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)
}

func TestFailoverRoute(t *testing.T) {
	ipp := func(s string) types.IPPrefix { return types.IPPrefix(netip.MustParsePrefix(s)) }

	// TODO(kradalby): Count/verify updates
	var sink chan types.StateUpdate

	go func() {
		for range sink {
		}
	}()

	machineKeys := []key.MachinePublic{
		key.NewMachine().Public(),
		key.NewMachine().Public(),
		key.NewMachine().Public(),
		key.NewMachine().Public(),
	}

	tests := []struct {
		name         string
		failingRoute types.Route
		routes       types.Routes
		want         []key.MachinePublic
		wantErr      bool
	}{
		{
			name:         "no-route",
			failingRoute: types.Route{},
			routes:       types.Routes{},
			want:         nil,
			wantErr:      false,
		},
		{
			name: "no-prime",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: false,
			},
			routes:  types.Routes{},
			want:    nil,
			wantErr: false,
		},
		{
			name: "exit-node",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("0.0.0.0/0"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
			},
			routes:  types.Routes{},
			want:    nil,
			wantErr: false,
		},
		{
			name: "no-failover-single-route",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: true,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "failover-primary",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: true,
				},
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[1],
					},
					IsPrimary: false,
				},
			},
			want: []key.MachinePublic{
				machineKeys[0],
				machineKeys[1],
			},
			wantErr: false,
		},
		{
			name: "failover-none-primary",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: false,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: true,
				},
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[1],
					},
					IsPrimary: false,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "failover-primary-multi-route",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 2,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[1],
				},
				IsPrimary: true,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: false,
				},
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[1],
					},
					IsPrimary: true,
				},
				types.Route{
					Model: gorm.Model{
						ID: 3,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[2],
					},
					IsPrimary: false,
				},
			},
			want: []key.MachinePublic{
				machineKeys[1],
				machineKeys[0],
			},
			wantErr: false,
		},
		{
			name: "failover-primary-no-online",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: true,
				},
				// Offline
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[3],
					},
					IsPrimary: false,
				},
			},
			want:    nil,
			wantErr: false,
		},
		{
			name: "failover-primary-one-not-online",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
			},
			routes: types.Routes{
				types.Route{
					Model: gorm.Model{
						ID: 1,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[0],
					},
					IsPrimary: true,
				},
				// Offline
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[3],
					},
					IsPrimary: false,
				},
				types.Route{
					Model: gorm.Model{
						ID: 3,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[1],
					},
					IsPrimary: true,
				},
			},
			want: []key.MachinePublic{
				machineKeys[0],
				machineKeys[1],
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "failover-db-test")
			assert.NoError(t, err)

			notif := notifier.NewNotifier()

			db, err = NewHeadscaleDatabase(
				"sqlite3",
				tmpDir+"/headscale_test.db",
				false,
				notif,
				[]netip.Prefix{
					netip.MustParsePrefix("10.27.0.0/23"),
				},
				"",
			)
			assert.NoError(t, err)

			// Pretend that all the nodes are connected to control
			for idx, key := range machineKeys {
				// Pretend one node is offline
				if idx == 3 {
					continue
				}

				notif.AddNode(key, sink)
			}

			for _, route := range tt.routes {
				if err := db.db.Save(&route).Error; err != nil {
					t.Fatalf("failed to create route: %s", err)
				}
			}

			got, err := db.failoverRoute(&tt.failingRoute)

			if (err != nil) != tt.wantErr {
				t.Errorf("failoverRoute() error = %v, wantErr %v", err, tt.wantErr)

				return
			}

			if diff := cmp.Diff(tt.want, got, util.Comparers...); diff != "" {
				t.Errorf("failoverRoute() unexpected result (-want +got):\n%s", diff)
			}
		})
	}
}
