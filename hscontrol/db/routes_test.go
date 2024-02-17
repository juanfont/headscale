package db

import (
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
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

	_, err = db.getNode("test", "test_get_route_node")
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
	db.DB.Save(&node)

	su, err := db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(su, check.Equals, false)

	advertisedRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(advertisedRoutes), check.Equals, 1)

	// TODO(kradalby): check state update
	_, err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	_, err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)
}

func (s *Suite) TestGetEnableRoutes(c *check.C) {
	user, err := db.CreateUser("test")
	c.Assert(err, check.IsNil)

	pak, err := db.CreatePreAuthKey(user.Name, false, false, nil, nil)
	c.Assert(err, check.IsNil)

	_, err = db.getNode("test", "test_enable_route_node")
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
	db.DB.Save(&node)

	sendUpdate, err := db.SaveNodeRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(sendUpdate, check.Equals, false)

	availableRoutes, err := db.GetAdvertisedRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(err, check.IsNil)
	c.Assert(len(availableRoutes), check.Equals, 2)

	noEnabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(noEnabledRoutes), check.Equals, 0)

	_, err = db.enableRoutes(&node, "192.168.0.0/24")
	c.Assert(err, check.NotNil)

	_, err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enabledRoutes, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes), check.Equals, 1)

	// Adding it twice will just let it pass through
	_, err = db.enableRoutes(&node, "10.0.0.0/24")
	c.Assert(err, check.IsNil)

	enableRoutesAfterDoubleApply, err := db.GetEnabledRoutes(&node)
	c.Assert(err, check.IsNil)
	c.Assert(len(enableRoutesAfterDoubleApply), check.Equals, 1)

	_, err = db.enableRoutes(&node, "150.0.10.0/25")
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

	_, err = db.getNode("test", "test_enable_route_node")
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
	db.DB.Save(&node1)

	sendUpdate, err := db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(sendUpdate, check.Equals, false)

	_, err = db.enableRoutes(&node1, route.String())
	c.Assert(err, check.IsNil)

	_, err = db.enableRoutes(&node1, route2.String())
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
	db.DB.Save(&node2)

	sendUpdate, err = db.SaveNodeRoutes(&node2)
	c.Assert(err, check.IsNil)
	c.Assert(sendUpdate, check.Equals, false)

	_, err = db.enableRoutes(&node2, route2.String())
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

	_, err = db.getNode("test", "test_enable_route_node")
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
	db.DB.Save(&node1)

	sendUpdate, err := db.SaveNodeRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(sendUpdate, check.Equals, false)

	_, err = db.enableRoutes(&node1, prefix.String())
	c.Assert(err, check.IsNil)

	_, err = db.enableRoutes(&node1, prefix2.String())
	c.Assert(err, check.IsNil)

	routes, err := db.GetNodeRoutes(&node1)
	c.Assert(err, check.IsNil)

	// TODO(kradalby): check stateupdate
	_, err = db.DeleteRoute(uint64(routes[0].ID), map[key.MachinePublic]bool{})
	c.Assert(err, check.IsNil)

	enabledRoutes1, err := db.GetEnabledRoutes(&node1)
	c.Assert(err, check.IsNil)
	c.Assert(len(enabledRoutes1), check.Equals, 1)
}

var ipp = func(s string) types.IPPrefix { return types.IPPrefix(netip.MustParsePrefix(s)) }

func TestFailoverRoute(t *testing.T) {
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
		isConnected  map[key.MachinePublic]bool
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
				Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
				},
			},
			isConnected: map[key.MachinePublic]bool{
				machineKeys[0]: false,
				machineKeys[1]: true,
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
				Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
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
				Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
				},
			},
			isConnected: map[key.MachinePublic]bool{
				machineKeys[0]: true,
				machineKeys[1]: true,
				machineKeys[2]: true,
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
				Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
				},
			},
			isConnected: map[key.MachinePublic]bool{
				machineKeys[0]: true,
				machineKeys[3]: false,
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
				Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
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
					Enabled:   true,
				},
			},
			isConnected: map[key.MachinePublic]bool{
				machineKeys[0]: false,
				machineKeys[1]: true,
				machineKeys[3]: false,
			},
			want: []key.MachinePublic{
				machineKeys[0],
				machineKeys[1],
			},
			wantErr: false,
		},
		{
			name: "failover-primary-none-enabled",
			failingRoute: types.Route{
				Model: gorm.Model{
					ID: 1,
				},
				Prefix: ipp("10.0.0.0/24"),
				Node: types.Node{
					MachineKey: machineKeys[0],
				},
				IsPrimary: true,
				Enabled:   true,
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
					Enabled:   true,
				},
				// not enabled
				types.Route{
					Model: gorm.Model{
						ID: 2,
					},
					Prefix: ipp("10.0.0.0/24"),
					Node: types.Node{
						MachineKey: machineKeys[1],
					},
					IsPrimary: false,
					Enabled:   false,
				},
			},
			want:    nil,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir, err := os.MkdirTemp("", "failover-db-test")
			assert.NoError(t, err)

			db, err = NewHeadscaleDatabase(
				types.DatabaseConfig{
					Type: "sqlite3",
					Sqlite: types.SqliteConfig{
						Path: tmpDir + "/headscale_test.db",
					},
				},
				"",
			)
			assert.NoError(t, err)

			for _, route := range tt.routes {
				if err := db.DB.Save(&route).Error; err != nil {
					t.Fatalf("failed to create route: %s", err)
				}
			}

			got, err := Write(db.DB, func(tx *gorm.DB) ([]key.MachinePublic, error) {
				return failoverRoute(tx, tt.isConnected, &tt.failingRoute)
			})

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

// func TestDisableRouteFailover(t *testing.T) {
// 	machineKeys := []key.MachinePublic{
// 		key.NewMachine().Public(),
// 		key.NewMachine().Public(),
// 		key.NewMachine().Public(),
// 		key.NewMachine().Public(),
// 	}

// 	tests := []struct {
// 		name  string
// 		nodes types.Nodes

// 		routeID     uint64
// 		isConnected map[key.MachinePublic]bool

// 		wantMachineKey key.MachinePublic
// 		wantErr        string
// 	}{
// 		{
// 			name: "single-route",
// 			nodes: types.Nodes{
// 				&types.Node{
// 					ID:         0,
// 					MachineKey: machineKeys[0],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 1,
// 							},
// 							Prefix: ipp("10.0.0.0/24"),
// 							Node: types.Node{
// 								MachineKey: machineKeys[0],
// 							},
// 							IsPrimary: true,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 			},
// 			routeID:        1,
// 			wantMachineKey: machineKeys[0],
// 		},
// 		{
// 			name: "failover-simple",
// 			nodes: types.Nodes{
// 				&types.Node{
// 					ID:         0,
// 					MachineKey: machineKeys[0],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 1,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: true,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 				&types.Node{
// 					ID:         1,
// 					MachineKey: machineKeys[1],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 2,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: false,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 			},
// 			routeID:        1,
// 			wantMachineKey: machineKeys[1],
// 		},
// 		{
// 			name: "no-failover-offline",
// 			nodes: types.Nodes{
// 				&types.Node{
// 					ID:         0,
// 					MachineKey: machineKeys[0],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 1,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: true,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 				&types.Node{
// 					ID:         1,
// 					MachineKey: machineKeys[1],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 2,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: false,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 			},
// 			isConnected: map[key.MachinePublic]bool{
// 				machineKeys[0]: true,
// 				machineKeys[1]: false,
// 			},
// 			routeID:        1,
// 			wantMachineKey: machineKeys[1],
// 		},
// 		{
// 			name: "failover-to-online",
// 			nodes: types.Nodes{
// 				&types.Node{
// 					ID:         0,
// 					MachineKey: machineKeys[0],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 1,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: true,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 				&types.Node{
// 					ID:         1,
// 					MachineKey: machineKeys[1],
// 					Routes: []types.Route{
// 						{
// 							Model: gorm.Model{
// 								ID: 2,
// 							},
// 							Prefix:    ipp("10.0.0.0/24"),
// 							IsPrimary: false,
// 						},
// 					},
// 					Hostinfo: &tailcfg.Hostinfo{
// 						RoutableIPs: []netip.Prefix{
// 							netip.MustParsePrefix("10.0.0.0/24"),
// 						},
// 					},
// 				},
// 			},
// 			isConnected: map[key.MachinePublic]bool{
// 				machineKeys[0]: true,
// 				machineKeys[1]: true,
// 			},
// 			routeID:        1,
// 			wantMachineKey: machineKeys[1],
// 		},
// 	}

// 	for _, tt := range tests {
// 		t.Run(tt.name, func(t *testing.T) {
// 			datab, err := NewHeadscaleDatabase("sqlite3", ":memory:", false, []netip.Prefix{}, "")
// 			assert.NoError(t, err)

// 			// bootstrap db
// 			datab.DB.Transaction(func(tx *gorm.DB) error {
// 				for _, node := range tt.nodes {
// 					err := tx.Save(node).Error
// 					if err != nil {
// 						return err
// 					}

// 					_, err = SaveNodeRoutes(tx, node)
// 					if err != nil {
// 						return err
// 					}
// 				}

// 				return nil
// 			})

// 			got, err := Write(datab.DB, func(tx *gorm.DB) (*types.StateUpdate, error) {
// 				return DisableRoute(tx, tt.routeID, tt.isConnected)
// 			})

// 			// if (err.Error() != "") != tt.wantErr {
// 			// 	t.Errorf("failoverRoute() error = %v, wantErr %v", err, tt.wantErr)

// 			// 	return
// 			// }

// 			if len(got.ChangeNodes) != 1 {
// 				t.Errorf("expected update with one machine, got %d", len(got.ChangeNodes))
// 			}

// 			if diff := cmp.Diff(tt.wantMachineKey, got.ChangeNodes[0].MachineKey, util.Comparers...); diff != "" {
// 				t.Errorf("DisableRoute() unexpected result (-want +got):\n%s", diff)
// 			}
// 		})
// 	}
// }
