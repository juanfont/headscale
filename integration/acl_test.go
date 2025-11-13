package integration

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

var veryLargeDestination = []policyv2.AliasWithPorts{
	aliasWithPorts(prefixp("0.0.0.0/5"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("8.0.0.0/7"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("11.0.0.0/8"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("12.0.0.0/6"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("16.0.0.0/4"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("32.0.0.0/3"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("64.0.0.0/2"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("128.0.0.0/3"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("160.0.0.0/5"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("168.0.0.0/6"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("172.0.0.0/12"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("172.32.0.0/11"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("172.64.0.0/10"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("172.128.0.0/9"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("173.0.0.0/8"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("174.0.0.0/7"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("176.0.0.0/4"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.0.0.0/9"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.128.0.0/11"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.160.0.0/13"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.169.0.0/16"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.170.0.0/15"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.172.0.0/14"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.176.0.0/12"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("192.192.0.0/10"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("193.0.0.0/8"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("194.0.0.0/7"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("196.0.0.0/6"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("200.0.0.0/5"), tailcfg.PortRangeAny),
	aliasWithPorts(prefixp("208.0.0.0/4"), tailcfg.PortRangeAny),
}

func aclScenario(
	t *testing.T,
	policy *policyv2.Policy,
	clientsPerUser int,
) *Scenario {
	t.Helper()

	spec := ScenarioSpec{
		NodesPerUser: clientsPerUser,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			// Alpine containers dont have ip6tables set up, which causes
			// tailscaled to stop configuring the wgengine, causing it
			// to not configure DNS.
			tsic.WithNetfilter("off"),
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("acl"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	require.NoError(t, err)

	return scenario
}

// This tests a different ACL mechanism, if a host _cannot_ connect
// to another node at all based on ACL, it should just not be part
// of the NetMap sent to the host. This is slightly different than
// the other tests as we can just check if the hosts are present
// or not.
func TestACLHostsInNetMapTable(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1", "user2"},
	}

	// NOTE: All want cases currently checks the
	// total count of expected peers, this would
	// typically be the client count of the users
	// they can access minus one (them self).
	tests := map[string]struct {
		users  ScenarioSpec
		policy policyv2.Policy
		want   map[string]int
	}{
		// Test that when we have no ACL, each client netmap has
		// the amount of peers of the total amount of clients
		"base-acls": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
						},
					},
				},
			}, want: map[string]int{
				"user1@test.no": 3, // ns1 + ns2
				"user2@test.no": 3, // ns2 + ns1
			},
		},
		// Test that when we have two users, which cannot see
		// each other, each node has only the number of pairs from
		// their own user.
		"two-isolated-users": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user1@"), tailcfg.PortRangeAny),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user2@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
						},
					},
				},
			}, want: map[string]int{
				"user1@test.no": 1,
				"user2@test.no": 1,
			},
		},
		// Test that when we have two users, with ACLs and they
		// are restricted to a single port, nodes are still present
		// in the netmap.
		"two-restricted-present-in-netmap": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user1@"), tailcfg.PortRange{First: 22, Last: 22}),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user2@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user2@"), tailcfg.PortRange{First: 22, Last: 22}),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user2@"), tailcfg.PortRange{First: 22, Last: 22}),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user2@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user1@"), tailcfg.PortRange{First: 22, Last: 22}),
						},
					},
				},
			}, want: map[string]int{
				"user1@test.no": 3,
				"user2@test.no": 3,
			},
		},
		// Test that when we have two users, that are isolated,
		// but one can see the others, we have the appropriate number
		// of peers. This will still result in all the peers as we
		// need them present on the other side for the "return path".
		"two-ns-one-isolated": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user1@"), tailcfg.PortRangeAny),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user2@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
						},
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
						},
					},
				},
			}, want: map[string]int{
				"user1@test.no": 3, // ns1 + ns2
				"user2@test.no": 3, // ns1 + ns2 (return path)
			},
		},
		"very-large-destination-prefix-1372": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: append(
							[]policyv2.AliasWithPorts{
								aliasWithPorts(usernamep("user1@"), tailcfg.PortRangeAny),
							},
							veryLargeDestination...,
						),
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user2@")},
						Destinations: append(
							[]policyv2.AliasWithPorts{
								aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
							},
							veryLargeDestination...,
						),
					},
					{
						Action:  "accept",
						Sources: []policyv2.Alias{usernamep("user1@")},
						Destinations: append(
							[]policyv2.AliasWithPorts{
								aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
							},
							veryLargeDestination...,
						),
					},
				},
			}, want: map[string]int{
				"user1@test.no": 3, // ns1 + ns2
				"user2@test.no": 3, // ns1 + ns2 (return path)
			},
		},
		"ipv6-acls-1470": {
			users: spec,
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(prefixp("0.0.0.0/0"), tailcfg.PortRangeAny),
							aliasWithPorts(prefixp("::/0"), tailcfg.PortRangeAny),
						},
					},
				},
			}, want: map[string]int{
				"user1@test.no": 3, // ns1 + ns2
				"user2@test.no": 3, // ns2 + ns1
			},
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			caseSpec := testCase.users
			scenario, err := NewScenario(caseSpec)
			require.NoError(t, err)

			err = scenario.CreateHeadscaleEnv(
				[]tsic.Option{},
				hsic.WithACLPolicy(&testCase.policy),
			)
			require.NoError(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			allClients, err := scenario.ListTailscaleClients()
			require.NoError(t, err)

			err = scenario.WaitForTailscaleSyncWithPeerCount(testCase.want["user1@test.no"], integrationutil.PeerSyncTimeout(), integrationutil.PeerSyncRetryInterval())
			require.NoError(t, err)

			for _, client := range allClients {
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					status, err := client.Status()
					assert.NoError(c, err)

					user := status.User[status.Self.UserID].LoginName

					assert.Len(c, status.Peer, (testCase.want[user]))
				}, 10*time.Second, 200*time.Millisecond, "Waiting for expected peer visibility")
			}
		})
	}
}

// Test to confirm that we can use user:80 from one user
// This should make the node appear in the peer list, but
// disallow ping.
// This ACL will not allow user1 access its own machines.
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowUser80Dst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{usernamep("user1@")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(usernamep("user2@"), tailcfg.PortRange{First: 80, Last: 80}),
					},
				},
			},
		},
		1,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user1 can reach user2")
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user2 cannot reach user1")
		}
	}
}

func TestACLDenyAllPort80(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:integration-acl-test"): []policyv2.Username{policyv2.Username("user1@"), policyv2.Username("user2@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{groupp("group:integration-acl-test")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRange{First: 22, Last: 22}),
					},
				},
			},
		},
		4,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	require.NoError(t, err)

	for _, client := range allClients {
		for _, hostname := range allHostnames {
			// We will always be allowed to check _self_ so shortcircuit
			// the test here.
			if strings.Contains(hostname, client.Hostname()) {
				continue
			}

			url := fmt.Sprintf("http://%s/etc/hostname", hostname)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 20*time.Second, 500*time.Millisecond, "Verifying all traffic is denied")
		}
	}
}

// Test to confirm that we can use user:* from one user.
// This ACL will not allow user1 access its own machines.
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowUserDst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{usernamep("user1@")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
					},
				},
			},
		},
		2,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user1 can reach user2")
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user2 cannot reach user1")
		}
	}
}

// Test to confirm that we can use *:* from one user
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowStarDst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{usernamep("user1@")},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
		},
		2,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user1 can reach user2")
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user2 cannot reach user1")
		}
	}
}

// TestACLNamedHostsCanReachBySubnet is the same as
// TestACLNamedHostsCanReach, but it tests if we expand a
// full CIDR correctly. All routes should work.
func TestACLNamedHostsCanReachBySubnet(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			Hosts: policyv2.Hosts{
				"all": policyv2.Prefix(netip.MustParsePrefix("100.64.0.0/24")),
			},
			ACLs: []policyv2.ACL{
				// Everyone can curl test3
				{
					Action:  "accept",
					Sources: []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(hostp("all"), tailcfg.PortRangeAny),
					},
				},
			},
		},
		3,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user1 can reach user2")
		}
	}

	// Test that user2 can visit all user1
	// Test that user2 can visit all user1, note that this
	// is _not_ symmetric.
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user2 can reach user1")
		}
	}
}

// This test aims to cover cases where individual hosts are allowed and denied
// access based on their assigned hostname
// https://github.com/juanfont/headscale/issues/941
//
//	ACL = [{
//			"DstPorts": [{
//				"Bits": null,
//				"IP": "100.64.0.3/32",
//				"Ports": {
//					"First": 0,
//					"Last": 65535
//				}
//			}],
//			"SrcIPs": ["*"]
//		}, {
//
//			"DstPorts": [{
//				"Bits": null,
//				"IP": "100.64.0.2/32",
//				"Ports": {
//					"First": 0,
//					"Last": 65535
//				}
//			}],
//			"SrcIPs": ["100.64.0.1/32"]
//		}]
//
//	ACL Cache Map= {
//		"*": {
//			"100.64.0.3/32": {}
//		},
//		"100.64.0.1/32": {
//			"100.64.0.2/32": {}
//		}
//	}
//
// https://github.com/juanfont/headscale/issues/941
// Additionally verify ipv6 behaviour, part of
// https://github.com/juanfont/headscale/issues/809
func TestACLNamedHostsCanReach(t *testing.T) {
	IntegrationSkip(t)

	tests := map[string]struct {
		policy policyv2.Policy
	}{
		"ipv4": {
			policy: policyv2.Policy{
				Hosts: policyv2.Hosts{
					"test1": policyv2.Prefix(netip.MustParsePrefix("100.64.0.1/32")),
					"test2": policyv2.Prefix(netip.MustParsePrefix("100.64.0.2/32")),
					"test3": policyv2.Prefix(netip.MustParsePrefix("100.64.0.3/32")),
				},
				ACLs: []policyv2.ACL{
					// Everyone can curl test3
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test3"), tailcfg.PortRangeAny),
						},
					},
					// test1 can curl test2
					{
						Action:  "accept",
						Sources: []policyv2.Alias{hostp("test1")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test2"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		"ipv6": {
			policy: policyv2.Policy{
				Hosts: policyv2.Hosts{
					"test1": policyv2.Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::1/128")),
					"test2": policyv2.Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::2/128")),
					"test3": policyv2.Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::3/128")),
				},
				ACLs: []policyv2.ACL{
					// Everyone can curl test3
					{
						Action:  "accept",
						Sources: []policyv2.Alias{wildcard()},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test3"), tailcfg.PortRangeAny),
						},
					},
					// test1 can curl test2
					{
						Action:  "accept",
						Sources: []policyv2.Alias{hostp("test1")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test2"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := aclScenario(t,
				&testCase.policy,
				2,
			)
			defer scenario.ShutdownAssertNoPanics(t)

			// Since user/users dont matter here, we basically expect that some clients
			// will be assigned these ips and that we can pick them up for our own use.
			test1ip4 := netip.MustParseAddr("100.64.0.1")
			test1ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
			test1, err := scenario.FindTailscaleClientByIP(test1ip6)
			require.NoError(t, err)

			test1fqdn, err := test1.FQDN()
			require.NoError(t, err)
			test1ip4URL := fmt.Sprintf("http://%s/etc/hostname", test1ip4.String())
			test1ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test1ip6.String())
			test1fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test1fqdn)

			test2ip4 := netip.MustParseAddr("100.64.0.2")
			test2ip6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
			test2, err := scenario.FindTailscaleClientByIP(test2ip6)
			require.NoError(t, err)

			test2fqdn, err := test2.FQDN()
			require.NoError(t, err)
			test2ip4URL := fmt.Sprintf("http://%s/etc/hostname", test2ip4.String())
			test2ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test2ip6.String())
			test2fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test2fqdn)

			test3ip4 := netip.MustParseAddr("100.64.0.3")
			test3ip6 := netip.MustParseAddr("fd7a:115c:a1e0::3")
			test3, err := scenario.FindTailscaleClientByIP(test3ip6)
			require.NoError(t, err)

			test3fqdn, err := test3.FQDN()
			require.NoError(t, err)
			test3ip4URL := fmt.Sprintf("http://%s/etc/hostname", test3ip4.String())
			test3ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test3ip6.String())
			test3fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test3fqdn)

			// test1 can query test3
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test3ip4URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3ip4URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test3 via IPv4")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test3ip6URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3ip6URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test3 via IPv6")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test3fqdnURL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3fqdnURL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test3 via FQDN")

			// test2 can query test3
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test3ip4URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3ip4URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test2 should reach test3 via IPv4")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test3ip6URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3ip6URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test2 should reach test3 via IPv6")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test3fqdnURL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
					test3fqdnURL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test2 should reach test3 via FQDN")

			// test3 cannot query test1
			result, err := test3.Curl(test1ip4URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test3.Curl(test1ip6URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test3.Curl(test1fqdnURL)
			assert.Empty(t, result)
			require.Error(t, err)

			// test3 cannot query test2
			result, err = test3.Curl(test2ip4URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test3.Curl(test2ip6URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test3.Curl(test2fqdnURL)
			assert.Empty(t, result)
			require.Error(t, err)

			// test1 can query test2
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2ip4URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
					test2ip4URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via IPv4")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2ip6URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
					test2ip6URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via IPv6")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2fqdnURL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
					test2fqdnURL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via FQDN")

			// test2 cannot query test1
			result, err = test2.Curl(test1ip4URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test2.Curl(test1ip6URL)
			assert.Empty(t, result)
			require.Error(t, err)

			result, err = test2.Curl(test1fqdnURL)
			assert.Empty(t, result)
			require.Error(t, err)
		})
	}
}

// TestACLDevice1CanAccessDevice2 is a table driven test that aims to test
// the various ways to achieve a connection between device1 and device2 where
// device1 can access device2, but not the other way around. This can be
// viewed as one of the most important tests here as it covers most of the
// syntax that can be used.
//
// Before adding new taste cases, consider if it can be reduced to a case
// in this function.
func TestACLDevice1CanAccessDevice2(t *testing.T) {
	IntegrationSkip(t)

	tests := map[string]struct {
		policy policyv2.Policy
	}{
		"ipv4": {
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{prefixp("100.64.0.1/32")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(prefixp("100.64.0.2/32"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		"ipv6": {
			policy: policyv2.Policy{
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{prefixp("fd7a:115c:a1e0::1/128")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(prefixp("fd7a:115c:a1e0::2/128"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		"hostv4cidr": {
			policy: policyv2.Policy{
				Hosts: policyv2.Hosts{
					"test1": policyv2.Prefix(netip.MustParsePrefix("100.64.0.1/32")),
					"test2": policyv2.Prefix(netip.MustParsePrefix("100.64.0.2/32")),
				},
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{hostp("test1")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test2"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		"hostv6cidr": {
			policy: policyv2.Policy{
				Hosts: policyv2.Hosts{
					"test1": policyv2.Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::1/128")),
					"test2": policyv2.Prefix(netip.MustParsePrefix("fd7a:115c:a1e0::2/128")),
				},
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{hostp("test1")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(hostp("test2"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		"group": {
			policy: policyv2.Policy{
				Groups: policyv2.Groups{
					policyv2.Group("group:one"): []policyv2.Username{policyv2.Username("user1@")},
					policyv2.Group("group:two"): []policyv2.Username{policyv2.Username("user2@")},
				},
				ACLs: []policyv2.ACL{
					{
						Action:  "accept",
						Sources: []policyv2.Alias{groupp("group:one")},
						Destinations: []policyv2.AliasWithPorts{
							aliasWithPorts(groupp("group:two"), tailcfg.PortRangeAny),
						},
					},
				},
			},
		},
		// TODO(kradalby): Add similar tests for Tags, might need support
		// in the scenario function when we create or join the clients.
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			scenario := aclScenario(t, &testCase.policy, 1)
			defer scenario.ShutdownAssertNoPanics(t)

			test1ip := netip.MustParseAddr("100.64.0.1")
			test1ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
			test1, err := scenario.FindTailscaleClientByIP(test1ip)
			assert.NotNil(t, test1)
			require.NoError(t, err)

			test1fqdn, err := test1.FQDN()
			require.NoError(t, err)
			test1ipURL := fmt.Sprintf("http://%s/etc/hostname", test1ip.String())
			test1ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test1ip6.String())
			test1fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test1fqdn)

			test2ip := netip.MustParseAddr("100.64.0.2")
			test2ip6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
			test2, err := scenario.FindTailscaleClientByIP(test2ip)
			assert.NotNil(t, test2)
			require.NoError(t, err)

			test2fqdn, err := test2.FQDN()
			require.NoError(t, err)
			test2ipURL := fmt.Sprintf("http://%s/etc/hostname", test2ip.String())
			test2ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test2ip6.String())
			test2fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test2fqdn)

			// test1 can query test2
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2ipURL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
					test2ipURL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via IPv4")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2ip6URL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
					test2ip6URL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via IPv6")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test1.Curl(test2fqdnURL)
				assert.NoError(c, err)
				assert.Lenf(
					c,
					result,
					13,
					"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
					test2fqdnURL,
					result,
				)
			}, 10*time.Second, 200*time.Millisecond, "test1 should reach test2 via FQDN")

			// test2 cannot query test1 (negative test case)
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test1ipURL)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 10*time.Second, 200*time.Millisecond, "test2 should NOT reach test1 via IPv4")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test1ip6URL)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 10*time.Second, 200*time.Millisecond, "test2 should NOT reach test1 via IPv6")

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := test2.Curl(test1fqdnURL)
				assert.Error(c, err)
				assert.Empty(c, result)
			}, 10*time.Second, 200*time.Millisecond, "test2 should NOT reach test1 via FQDN")
		})
	}
}

func TestPolicyUpdateWhileRunningWithCLIInDatabase(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			// Alpine containers dont have ip6tables set up, which causes
			// tailscaled to stop configuring the wgengine, causing it
			// to not configure DNS.
			tsic.WithNetfilter("off"),
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithTestName("policyreload"),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	require.NoError(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	all := append(user1Clients, user2Clients...)

	// Initially all nodes can reach each other
	for _, client := range all {
		for _, peer := range all {
			if client.ContainerID() == peer.ContainerID() {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying user1 can reach user2")
		}
	}

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	p := policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{usernamep("user1@")},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
				},
			},
		},
		Hosts: policyv2.Hosts{},
	}

	err = headscale.SetPolicy(&p)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Get the current policy and check
		// if it is the same as the one we set.
		var output *policyv2.Policy
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"policy",
				"get",
				"--output",
				"json",
			},
			&output,
		)
		assert.NoError(ct, err)

		assert.Len(t, output.ACLs, 1)

		if diff := cmp.Diff(p, *output, cmpopts.IgnoreUnexported(policyv2.Policy{}), cmpopts.EquateEmpty()); diff != "" {
			ct.Errorf("unexpected policy(-want +got):\n%s", diff)
		}
	}, 30*time.Second, 1*time.Second, "verifying that the new policy took place")

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		// Test that user1 can visit all user2
		for _, client := range user1Clients {
			for _, peer := range user2Clients {
				fqdn, err := peer.FQDN()
				assert.NoError(ct, err)

				url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
				t.Logf("url from %s to %s", client.Hostname(), url)

				result, err := client.Curl(url)
				assert.Len(ct, result, 13)
				assert.NoError(ct, err)
			}
		}

		// Test that user2 _cannot_ visit user1
		for _, client := range user2Clients {
			for _, peer := range user1Clients {
				fqdn, err := peer.FQDN()
				assert.NoError(ct, err)

				url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
				t.Logf("url from %s to %s", client.Hostname(), url)

				result, err := client.Curl(url)
				assert.Empty(ct, result)
				assert.Error(ct, err)
			}
		}
	}, 30*time.Second, 1*time.Second, "new policy did not get propagated to nodes")
}

func TestACLAutogroupMember(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:  "accept",
					Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroupMember)},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(ptr.To(policyv2.AutoGroupMember), tailcfg.PortRangeAny),
					},
				},
			},
		},
		2,
	)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	// Test that untagged nodes can access each other
	for _, client := range allClients {
		var clientIsUntagged bool
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)
			clientIsUntagged = status.Self.Tags == nil || status.Self.Tags.Len() == 0
			assert.True(c, clientIsUntagged, "Expected client %s to be untagged for autogroup:member test", client.Hostname())
		}, 10*time.Second, 200*time.Millisecond, "Waiting for client %s to be untagged", client.Hostname())

		if !clientIsUntagged {
			continue
		}

		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			var peerIsUntagged bool
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				status, err := peer.Status()
				assert.NoError(c, err)
				peerIsUntagged = status.Self.Tags == nil || status.Self.Tags.Len() == 0
				assert.True(c, peerIsUntagged, "Expected peer %s to be untagged for autogroup:member test", peer.Hostname())
			}, 10*time.Second, 200*time.Millisecond, "Waiting for peer %s to be untagged", peer.Hostname())

			if !peerIsUntagged {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "Verifying autogroup:member connectivity")
		}
	}
}

func TestACLAutogroupTagged(t *testing.T) {
	IntegrationSkip(t)

	// Create a custom scenario for testing autogroup:tagged
	spec := ScenarioSpec{
		NodesPerUser: 2, // 2 nodes per user - one tagged, one untagged
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:test": policyv2.Owners{usernameOwner("user1@"), usernameOwner("user2@")},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroupTagged)},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(ptr.To(policyv2.AutoGroupTagged), tailcfg.PortRangeAny),
				},
			},
		},
	}

	// Create only the headscale server (not the full environment with users/nodes)
	headscale, err := scenario.Headscale(
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("acl-autogroup-tagged"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	// Create users and nodes manually with specific tags
	for _, userStr := range spec.Users {
		user, err := scenario.CreateUser(userStr)
		require.NoError(t, err)

		// Create a single pre-auth key per user
		authKey, err := scenario.CreatePreAuthKey(user.GetId(), true, false)
		require.NoError(t, err)

		// Create nodes with proper naming
		for i := range spec.NodesPerUser {
			var tags []string
			var version string

			if i == 0 {
				// First node is tagged
				tags = []string{"tag:test"}
				version = "head"
				t.Logf("Creating tagged node for %s", userStr)
			} else {
				// Second node is untagged
				tags = nil
				version = "unstable"
				t.Logf("Creating untagged node for %s", userStr)
			}

			// Get the network for this scenario
			networks := scenario.Networks()
			var network *dockertest.Network
			if len(networks) > 0 {
				network = networks[0]
			}

			// Create the tailscale node with appropriate options
			opts := []tsic.Option{
				tsic.WithCACert(headscale.GetCert()),
				tsic.WithHeadscaleName(headscale.GetHostname()),
				tsic.WithNetwork(network),
				tsic.WithNetfilter("off"),
				tsic.WithDockerEntrypoint([]string{
					"/bin/sh",
					"-c",
					"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
				}),
				tsic.WithDockerWorkdir("/"),
			}

			// Add tags if this is a tagged node
			if len(tags) > 0 {
				opts = append(opts, tsic.WithTags(tags))
			}

			tsClient, err := tsic.New(
				scenario.Pool(),
				version,
				opts...,
			)
			require.NoError(t, err)

			err = tsClient.WaitForNeedsLogin(integrationutil.PeerSyncTimeout())
			require.NoError(t, err)

			// Login with the auth key
			err = tsClient.Login(headscale.GetEndpoint(), authKey.GetKey())
			require.NoError(t, err)

			err = tsClient.WaitForRunning(integrationutil.PeerSyncTimeout())
			require.NoError(t, err)

			// Add client to user
			userObj := scenario.GetOrCreateUser(userStr)
			userObj.Clients[tsClient.Hostname()] = tsClient
		}
	}

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 4) // 2 users * 2 nodes each

	// Wait for nodes to see only their allowed peers
	// Tagged nodes should see each other (2 tagged nodes total)
	// Untagged nodes should see no one
	var taggedClients []TailscaleClient
	var untaggedClients []TailscaleClient

	// First, categorize nodes by checking their tags
	for _, client := range allClients {
		hostname := client.Hostname()

		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(ct, err)

			if status.Self.Tags != nil && status.Self.Tags.Len() > 0 {
				// This is a tagged node
				assert.Len(ct, status.Peers(), 1, "tagged node %s should see exactly 1 peer", hostname)

				// Add to tagged list only once we've verified it
				found := false
				for _, tc := range taggedClients {
					if tc.Hostname() == hostname {
						found = true
						break
					}
				}
				if !found {
					taggedClients = append(taggedClients, client)
				}
			} else {
				// This is an untagged node
				assert.Empty(ct, status.Peers(), "untagged node %s should see 0 peers", hostname)

				// Add to untagged list only once we've verified it
				found := false
				for _, uc := range untaggedClients {
					if uc.Hostname() == hostname {
						found = true
						break
					}
				}
				if !found {
					untaggedClients = append(untaggedClients, client)
				}
			}
		}, 30*time.Second, 1*time.Second, "verifying peer visibility for node %s", hostname)
	}

	// Verify we have the expected number of tagged and untagged nodes
	require.Len(t, taggedClients, 2, "should have exactly 2 tagged nodes")
	require.Len(t, untaggedClients, 2, "should have exactly 2 untagged nodes")

	// Explicitly verify tags on tagged nodes
	for _, client := range taggedClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)
			assert.NotNil(c, status.Self.Tags, "tagged node %s should have tags", client.Hostname())
			assert.Positive(c, status.Self.Tags.Len(), "tagged node %s should have at least one tag", client.Hostname())
		}, 10*time.Second, 200*time.Millisecond, "Waiting for tags to be applied to tagged nodes")
	}

	// Verify untagged nodes have no tags
	for _, client := range untaggedClients {
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)
			if status.Self.Tags != nil {
				assert.Equal(c, 0, status.Self.Tags.Len(), "untagged node %s should have no tags", client.Hostname())
			}
		}, 10*time.Second, 200*time.Millisecond, "Waiting to verify untagged nodes have no tags")
	}

	// Test that tagged nodes can communicate with each other
	for _, client := range taggedClients {
		for _, peer := range taggedClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("Testing connection from tagged node %s to tagged node %s", client.Hostname(), peer.Hostname())

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(ct, err)
				assert.Len(ct, result, 13)
			}, 20*time.Second, 500*time.Millisecond, "tagged nodes should be able to communicate")
		}
	}

	// Test that untagged nodes cannot communicate with anyone
	for _, client := range untaggedClients {
		// Try to reach tagged nodes (should fail)
		for _, peer := range taggedClients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("Testing connection from untagged node %s to tagged node %s (should fail)", client.Hostname(), peer.Hostname())

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				result, err := client.CurlFailFast(url)
				assert.Empty(ct, result)
				assert.Error(ct, err)
			}, 5*time.Second, 200*time.Millisecond, "untagged nodes should not be able to reach tagged nodes")
		}

		// Try to reach other untagged nodes (should also fail)
		for _, peer := range untaggedClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("Testing connection from untagged node %s to untagged node %s (should fail)", client.Hostname(), peer.Hostname())

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				result, err := client.CurlFailFast(url)
				assert.Empty(ct, result)
				assert.Error(ct, err)
			}, 5*time.Second, 200*time.Millisecond, "untagged nodes should not be able to reach other untagged nodes")
		}
	}

	// Test that tagged nodes cannot reach untagged nodes
	for _, client := range taggedClients {
		for _, peer := range untaggedClients {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("Testing connection from tagged node %s to untagged node %s (should fail)", client.Hostname(), peer.Hostname())

			assert.EventuallyWithT(t, func(ct *assert.CollectT) {
				result, err := client.CurlFailFast(url)
				assert.Empty(ct, result)
				assert.Error(ct, err)
			}, 5*time.Second, 200*time.Millisecond, "tagged nodes should not be able to reach untagged nodes")
		}
	}
}

// Test that only devices owned by the same user can access each other and cannot access devices of other users
// Test structure:
// - user1: 2 regular nodes (tests autogroup:self for same-user access)
// - user2: 2 regular nodes (tests autogroup:self for same-user access and cross-user isolation)
// - user-router: 1 node with tag:router-node (tests that autogroup:self doesn't interfere with other rules)
func TestACLAutogroupSelf(t *testing.T) {
	IntegrationSkip(t)

	// Policy with TWO separate ACL rules:
	// 1. autogroup:member -> autogroup:self (same-user access)
	// 2. group:home -> tag:router-node (router access)
	// This tests that autogroup:self doesn't prevent other rules from working
	policy := &policyv2.Policy{
		Groups: policyv2.Groups{
			policyv2.Group("group:home"): []policyv2.Username{
				policyv2.Username("user1@"),
				policyv2.Username("user2@"),
			},
		},
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:router-node"): policyv2.Owners{
				usernameOwner("user-router@"),
			},
		},
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroupMember)},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(ptr.To(policyv2.AutoGroupSelf), tailcfg.PortRangeAny),
				},
			},
			{
				Action:  "accept",
				Sources: []policyv2.Alias{groupp("group:home")},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(tagp("tag:router-node"), tailcfg.PortRangeAny),
				},
			},
			{
				Action:  "accept",
				Sources: []policyv2.Alias{tagp("tag:router-node")},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(groupp("group:home"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	// Create custom scenario: user1 and user2 with regular nodes, plus user-router with tagged node
	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithNetfilter("off"),
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("acl-autogroup-self"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	require.NoError(t, err)

	// Add router node for user-router (single shared router node)
	networks := scenario.Networks()
	var network *dockertest.Network
	if len(networks) > 0 {
		network = networks[0]
	}

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	routerUser, err := scenario.CreateUser("user-router")
	require.NoError(t, err)

	authKey, err := scenario.CreatePreAuthKey(routerUser.GetId(), true, false)
	require.NoError(t, err)

	// Create router node (tagged with tag:router-node)
	routerClient, err := tsic.New(
		scenario.Pool(),
		"unstable",
		tsic.WithCACert(headscale.GetCert()),
		tsic.WithHeadscaleName(headscale.GetHostname()),
		tsic.WithNetwork(network),
		tsic.WithTags([]string{"tag:router-node"}),
		tsic.WithNetfilter("off"),
		tsic.WithDockerEntrypoint([]string{
			"/bin/sh",
			"-c",
			"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
		}),
		tsic.WithDockerWorkdir("/"),
	)
	require.NoError(t, err)

	err = routerClient.WaitForNeedsLogin(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	err = routerClient.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	err = routerClient.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	userRouterObj := scenario.GetOrCreateUser("user-router")
	userRouterObj.Clients[routerClient.Hostname()] = routerClient

	user1Clients, err := scenario.GetClients("user1")
	require.NoError(t, err)
	user2Clients, err := scenario.GetClients("user2")
	require.NoError(t, err)

	var user1Regular, user2Regular []TailscaleClient
	for _, client := range user1Clients {
		status, err := client.Status()
		require.NoError(t, err)
		if status.Self != nil && (status.Self.Tags == nil || status.Self.Tags.Len() == 0) {
			user1Regular = append(user1Regular, client)
		}
	}
	for _, client := range user2Clients {
		status, err := client.Status()
		require.NoError(t, err)
		if status.Self != nil && (status.Self.Tags == nil || status.Self.Tags.Len() == 0) {
			user2Regular = append(user2Regular, client)
		}
	}

	require.NotEmpty(t, user1Regular, "user1 should have regular (untagged) devices")
	require.NotEmpty(t, user2Regular, "user2 should have regular (untagged) devices")
	require.NotNil(t, routerClient, "router node should exist")

	// Wait for all nodes to sync with their expected peer counts
	// With our ACL policy:
	// - Regular nodes (user1/user2): 1 same-user regular peer + 1 router-node = 2 peers
	// - Router node: 2 user1 regular + 2 user2 regular = 4 peers
	for _, client := range user1Regular {
		err := client.WaitForPeers(2, integrationutil.PeerSyncTimeout(), integrationutil.PeerSyncRetryInterval())
		require.NoError(t, err, "user1 regular device %s should see 2 peers (1 same-user peer + 1 router)", client.Hostname())
	}
	for _, client := range user2Regular {
		err := client.WaitForPeers(2, integrationutil.PeerSyncTimeout(), integrationutil.PeerSyncRetryInterval())
		require.NoError(t, err, "user2 regular device %s should see 2 peers (1 same-user peer + 1 router)", client.Hostname())
	}
	err = routerClient.WaitForPeers(4, integrationutil.PeerSyncTimeout(), integrationutil.PeerSyncRetryInterval())
	require.NoError(t, err, "router should see 4 peers (all group:home regular nodes)")

	// Test that user1's regular devices can access each other
	for _, client := range user1Regular {
		for _, peer := range user1Regular {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s (user1) to %s (user1)", client.Hostname(), fqdn)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 10*time.Second, 200*time.Millisecond, "user1 device should reach other user1 device via autogroup:self")
		}
	}

	// Test that user2's regular devices can access each other
	for _, client := range user2Regular {
		for _, peer := range user2Regular {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s (user2) to %s (user2)", client.Hostname(), fqdn)

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				result, err := client.Curl(url)
				assert.NoError(c, err)
				assert.Len(c, result, 13)
			}, 10*time.Second, 200*time.Millisecond, "user2 device should reach other user2 device via autogroup:self")
		}
	}

	// Test that user1's regular devices can access router-node
	for _, client := range user1Regular {
		fqdn, err := routerClient.FQDN()
		require.NoError(t, err)
		url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
		t.Logf("url from %s (user1) to %s (router-node) - should SUCCEED", client.Hostname(), fqdn)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			result, err := client.Curl(url)
			assert.NoError(c, err)
			assert.NotEmpty(c, result, "user1 should be able to access router-node via group:home -> tag:router-node rule")
		}, 10*time.Second, 200*time.Millisecond, "user1 device should reach router-node (proves autogroup:self doesn't interfere)")
	}

	// Test that user2's regular devices can access router-node
	for _, client := range user2Regular {
		fqdn, err := routerClient.FQDN()
		require.NoError(t, err)
		url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
		t.Logf("url from %s (user2) to %s (router-node) - should SUCCEED", client.Hostname(), fqdn)

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			result, err := client.Curl(url)
			assert.NoError(c, err)
			assert.NotEmpty(c, result, "user2 should be able to access router-node via group:home -> tag:router-node rule")
		}, 10*time.Second, 200*time.Millisecond, "user2 device should reach router-node (proves autogroup:self doesn't interfere)")
	}

	// Test that devices from different users cannot access each other's regular devices
	for _, client := range user1Regular {
		for _, peer := range user2Regular {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s (user1) to %s (user2 regular) - should FAIL", client.Hostname(), fqdn)

			result, err := client.Curl(url)
			assert.Empty(t, result, "user1 should not be able to access user2's regular devices (autogroup:self isolation)")
			assert.Error(t, err, "connection from user1 to user2 regular device should fail")
		}
	}

	for _, client := range user2Regular {
		for _, peer := range user1Regular {
			fqdn, err := peer.FQDN()
			require.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s (user2) to %s (user1 regular) - should FAIL", client.Hostname(), fqdn)

			result, err := client.Curl(url)
			assert.Empty(t, result, "user2 should not be able to access user1's regular devices (autogroup:self isolation)")
			assert.Error(t, err, "connection from user2 to user1 regular device should fail")
		}
	}
}

func TestACLPolicyPropagationOverTime(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			// Install iptables to enable packet filtering for ACL tests.
			// Packet filters are essential for testing autogroup:self and other ACL policies.
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl iptables ip6tables ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithTestName("aclpropagation"),
		hsic.WithPolicyMode(types.PolicyModeDB),
	)
	require.NoError(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	require.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	require.NoError(t, err)

	allClients := append(user1Clients, user2Clients...)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Define the four policies we'll cycle through
	allowAllPolicy := &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
	}

	autogroupSelfPolicy := &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{ptr.To(policyv2.AutoGroupMember)},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(ptr.To(policyv2.AutoGroupSelf), tailcfg.PortRangeAny),
				},
			},
		},
	}

	user1ToUser2Policy := &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:  "accept",
				Sources: []policyv2.Alias{usernamep("user1@")},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(usernamep("user2@"), tailcfg.PortRangeAny),
				},
			},
		},
	}

	// Run through the policy cycle 5 times
	for i := range 5 {
		iteration := i + 1 // range 5 gives 0-4, we want 1-5 for logging
		t.Logf("=== Iteration %d/5 ===", iteration)

		// Phase 1: Allow all policy
		t.Logf("Iteration %d: Setting allow-all policy", iteration)
		err = headscale.SetPolicy(allowAllPolicy)
		require.NoError(t, err)

		// Wait for peer lists to sync with allow-all policy
		t.Logf("Iteration %d: Phase 1 - Waiting for peer lists to sync with allow-all policy", iteration)
		err = scenario.WaitForTailscaleSync()
		require.NoError(t, err, "iteration %d: Phase 1 - failed to sync after allow-all policy", iteration)

		// Test all-to-all connectivity after state is settled
		t.Logf("Iteration %d: Phase 1 - Testing all-to-all connectivity", iteration)
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			for _, client := range allClients {
				for _, peer := range allClients {
					if client.ContainerID() == peer.ContainerID() {
						continue
					}

					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.NoError(ct, err, "iteration %d: %s should reach %s with allow-all policy", iteration, client.Hostname(), fqdn)
					assert.Len(ct, result, 13, "iteration %d: response from %s to %s should be valid", iteration, client.Hostname(), fqdn)
				}
			}
		}, 90*time.Second, 500*time.Millisecond, "iteration %d: Phase 1 - all connectivity tests with allow-all policy", iteration)

		// Phase 2: Autogroup:self policy (only same user can access)
		t.Logf("Iteration %d: Phase 2 - Setting autogroup:self policy", iteration)
		err = headscale.SetPolicy(autogroupSelfPolicy)
		require.NoError(t, err)

		// Wait for peer lists to sync with autogroup:self - ensures cross-user peers are removed
		t.Logf("Iteration %d: Phase 2 - Waiting for peer lists to sync with autogroup:self", iteration)
		err = scenario.WaitForTailscaleSyncPerUser(60*time.Second, 500*time.Millisecond)
		require.NoError(t, err, "iteration %d: Phase 2 - failed to sync after autogroup:self policy", iteration)

		// Test ALL connectivity (positive and negative) in one block after state is settled
		t.Logf("Iteration %d: Phase 2 - Testing all connectivity with autogroup:self", iteration)
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			// Positive: user1 can access user1's nodes
			for _, client := range user1Clients {
				for _, peer := range user1Clients {
					if client.ContainerID() == peer.ContainerID() {
						continue
					}

					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user1 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.NoError(ct, err, "iteration %d: user1 node %s should reach user1 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Len(ct, result, 13, "iteration %d: response from %s to %s should be valid", iteration, client.Hostname(), peer.Hostname())
				}
			}

			// Positive: user2 can access user2's nodes
			for _, client := range user2Clients {
				for _, peer := range user2Clients {
					if client.ContainerID() == peer.ContainerID() {
						continue
					}

					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user2 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.NoError(ct, err, "iteration %d: user2 %s should reach user2's node %s", iteration, client.Hostname(), fqdn)
					assert.Len(ct, result, 13, "iteration %d: response from %s to %s should be valid", iteration, client.Hostname(), fqdn)
				}
			}

			// Negative: user1 cannot access user2's nodes
			for _, client := range user1Clients {
				for _, peer := range user2Clients {
					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user2 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.Error(ct, err, "iteration %d: user1 %s should NOT reach user2's node %s with autogroup:self", iteration, client.Hostname(), fqdn)
					assert.Empty(ct, result, "iteration %d: user1 %s->user2 %s should fail", iteration, client.Hostname(), fqdn)
				}
			}

			// Negative: user2 cannot access user1's nodes
			for _, client := range user2Clients {
				for _, peer := range user1Clients {
					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user1 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.Error(ct, err, "iteration %d: user2 node %s should NOT reach user1 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Empty(ct, result, "iteration %d: user2->user1 connection from %s to %s should fail", iteration, client.Hostname(), peer.Hostname())
				}
			}
		}, 90*time.Second, 500*time.Millisecond, "iteration %d: Phase 2 - all connectivity tests with autogroup:self", iteration)

		// Phase 2b: Add a new node to user1 and validate policy propagation
		t.Logf("Iteration %d: Phase 2b - Adding new node to user1 during autogroup:self policy", iteration)

		// Add a new node with the same options as the initial setup
		// Get the network to use (scenario uses first network in list)
		networks := scenario.Networks()
		require.NotEmpty(t, networks, "scenario should have at least one network")

		newClient := scenario.MustAddAndLoginClient(t, "user1", "all", headscale,
			tsic.WithNetfilter("off"),
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add python3 curl ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
			tsic.WithNetwork(networks[0]),
		)
		t.Logf("Iteration %d: Phase 2b - Added and logged in new node %s", iteration, newClient.Hostname())

		// Wait for peer lists to sync after new node addition (now 3 user1 nodes, still autogroup:self)
		t.Logf("Iteration %d: Phase 2b - Waiting for peer lists to sync after new node addition", iteration)
		err = scenario.WaitForTailscaleSyncPerUser(60*time.Second, 500*time.Millisecond)
		require.NoError(t, err, "iteration %d: Phase 2b - failed to sync after new node addition", iteration)

		// Test ALL connectivity (positive and negative) in one block after state is settled
		t.Logf("Iteration %d: Phase 2b - Testing all connectivity after new node addition", iteration)
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			// Re-fetch client list to ensure latest state
			user1ClientsWithNew, err := scenario.ListTailscaleClients("user1")
			assert.NoError(ct, err, "iteration %d: failed to list user1 clients", iteration)
			assert.Len(ct, user1ClientsWithNew, 3, "iteration %d: user1 should have 3 nodes", iteration)

			// Positive: all user1 nodes can access each other
			for _, client := range user1ClientsWithNew {
				for _, peer := range user1ClientsWithNew {
					if client.ContainerID() == peer.ContainerID() {
						continue
					}

					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.NoError(ct, err, "iteration %d: user1 node %s should reach user1 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Len(ct, result, 13, "iteration %d: response from %s to %s should be valid", iteration, client.Hostname(), peer.Hostname())
				}
			}

			// Negative: user1 nodes cannot access user2's nodes
			for _, client := range user1ClientsWithNew {
				for _, peer := range user2Clients {
					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user2 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.Error(ct, err, "iteration %d: user1 node %s should NOT reach user2 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Empty(ct, result, "iteration %d: user1->user2 connection from %s to %s should fail", iteration, client.Hostname(), peer.Hostname())
				}
			}
		}, 90*time.Second, 500*time.Millisecond, "iteration %d: Phase 2b - all connectivity tests after new node addition", iteration)

		// Delete the newly added node before Phase 3
		t.Logf("Iteration %d: Phase 2b - Deleting the newly added node from user1", iteration)

		// Get the node list and find the newest node (highest ID)
		var nodeList []*v1.Node
		var nodeToDeleteID uint64
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nodeList, err = headscale.ListNodes("user1")
			assert.NoError(ct, err)
			assert.Len(ct, nodeList, 3, "should have 3 user1 nodes before deletion")

			// Find the node with the highest ID (the newest one)
			for _, node := range nodeList {
				if node.GetId() > nodeToDeleteID {
					nodeToDeleteID = node.GetId()
				}
			}
		}, 10*time.Second, 500*time.Millisecond, "iteration %d: Phase 2b - listing nodes before deletion", iteration)

		// Delete the node via headscale helper
		t.Logf("Iteration %d: Phase 2b - Deleting node ID %d from headscale", iteration, nodeToDeleteID)
		err = headscale.DeleteNode(nodeToDeleteID)
		require.NoError(t, err, "iteration %d: failed to delete node %d", iteration, nodeToDeleteID)

		// Remove the deleted client from the scenario's user.Clients map
		// This is necessary for WaitForTailscaleSyncPerUser to calculate correct peer counts
		t.Logf("Iteration %d: Phase 2b - Removing deleted client from scenario", iteration)
		for clientName, client := range scenario.users["user1"].Clients {
			status := client.MustStatus()
			nodeID, err := strconv.ParseUint(string(status.Self.ID), 10, 64)
			if err != nil {
				continue
			}
			if nodeID == nodeToDeleteID {
				delete(scenario.users["user1"].Clients, clientName)
				t.Logf("Iteration %d: Phase 2b - Removed client %s (node ID %d) from scenario", iteration, clientName, nodeToDeleteID)
				break
			}
		}

		// Verify the node has been deleted
		t.Logf("Iteration %d: Phase 2b - Verifying node deletion (expecting 2 user1 nodes)", iteration)
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			nodeListAfter, err := headscale.ListNodes("user1")
			assert.NoError(ct, err, "failed to list nodes after deletion")
			assert.Len(ct, nodeListAfter, 2, "iteration %d: should have 2 user1 nodes after deletion, got %d", iteration, len(nodeListAfter))
		}, 10*time.Second, 500*time.Millisecond, "iteration %d: Phase 2b - node should be deleted", iteration)

		// Wait for sync after deletion to ensure peer counts are correct
		// Use WaitForTailscaleSyncPerUser because autogroup:self is still active,
		// so nodes only see same-user peers, not all nodes
		t.Logf("Iteration %d: Phase 2b - Waiting for sync after node deletion (with autogroup:self)", iteration)
		err = scenario.WaitForTailscaleSyncPerUser(60*time.Second, 500*time.Millisecond)
		require.NoError(t, err, "iteration %d: failed to sync after node deletion", iteration)

		// Refresh client lists after deletion to ensure we don't reference the deleted node
		user1Clients, err = scenario.ListTailscaleClients("user1")
		require.NoError(t, err, "iteration %d: failed to refresh user1 client list after deletion", iteration)
		user2Clients, err = scenario.ListTailscaleClients("user2")
		require.NoError(t, err, "iteration %d: failed to refresh user2 client list after deletion", iteration)
		// Create NEW slice instead of appending to old allClients which still has deleted client
		allClients = make([]TailscaleClient, 0, len(user1Clients)+len(user2Clients))
		allClients = append(allClients, user1Clients...)
		allClients = append(allClients, user2Clients...)

		t.Logf("Iteration %d: Phase 2b completed - New node added, validated, and removed successfully", iteration)

		// Phase 3: User1 can access user2 but not reverse
		t.Logf("Iteration %d: Phase 3 - Setting user1->user2 directional policy", iteration)
		err = headscale.SetPolicy(user1ToUser2Policy)
		require.NoError(t, err)

		// Note: Cannot use WaitForTailscaleSync() here because directional policy means
		// user2 nodes don't see user1 nodes in their peer list (asymmetric visibility).
		// The EventuallyWithT block below will handle waiting for policy propagation.

		// Test ALL connectivity (positive and negative) in one block after policy settles
		t.Logf("Iteration %d: Phase 3 - Testing all connectivity with directional policy", iteration)
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			// Positive: user1 can access user2's nodes
			for _, client := range user1Clients {
				for _, peer := range user2Clients {
					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user2 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.NoError(ct, err, "iteration %d: user1 node %s should reach user2 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Len(ct, result, 13, "iteration %d: response from %s to %s should be valid", iteration, client.Hostname(), peer.Hostname())
				}
			}

			// Negative: user2 cannot access user1's nodes
			for _, client := range user2Clients {
				for _, peer := range user1Clients {
					fqdn, err := peer.FQDN()
					if !assert.NoError(ct, err, "iteration %d: failed to get FQDN for user1 peer %s", iteration, peer.Hostname()) {
						continue
					}

					url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
					result, err := client.Curl(url)
					assert.Error(ct, err, "iteration %d: user2 node %s should NOT reach user1 node %s", iteration, client.Hostname(), peer.Hostname())
					assert.Empty(ct, result, "iteration %d: user2->user1 from %s to %s should fail", iteration, client.Hostname(), peer.Hostname())
				}
			}
		}, 90*time.Second, 500*time.Millisecond, "iteration %d: Phase 3 - all connectivity tests with directional policy", iteration)

		t.Logf("=== Iteration %d/5 completed successfully - All 3 phases passed ===", iteration)
	}

	t.Log("All 5 iterations completed successfully - ACL propagation is working correctly")
}
