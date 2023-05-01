package integration

import (
	"fmt"
	"net/netip"
	"strings"
	"testing"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

func aclScenario(t *testing.T, policy *headscale.ACLPolicy, clientsPerUser int) *Scenario {
	t.Helper()
	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"user1": clientsPerUser,
		"user2": clientsPerUser,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{
			tsic.WithDockerEntrypoint([]string{
				"/bin/bash",
				"-c",
				"/bin/sleep 3 ; update-ca-certificates ; python3 -m http.server --bind :: 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("acl"),
	)
	assert.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	assert.NoError(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assert.NoError(t, err)

	return scenario
}

// This tests a different ACL mechanism, if a host _cannot_ connect
// to another node at all based on ACL, it should just not be part
// of the NetMap sent to the host. This is slightly different than
// the other tests as we can just check if the hosts are present
// or not.
func TestACLHostsInNetMapTable(t *testing.T) {
	IntegrationSkip(t)

	// NOTE: All want cases currently checks the
	// total count of expected peers, this would
	// typically be the client count of the users
	// they can access minus one (them self).
	tests := map[string]struct {
		users  map[string]int
		policy headscale.ACLPolicy
		want   map[string]int
	}{
		// Test that when we have no ACL, each client netmap has
		// the amount of peers of the total amount of clients
		"base-acls": {
			users: map[string]int{
				"user1": 2,
				"user2": 2,
			},
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
			}, want: map[string]int{
				"user1": 3, // ns1 + ns2
				"user2": 3, // ns2 + ns1
			},
		},
		// Test that when we have two users, which cannot see
		// eachother, each node has only the number of pairs from
		// their own user.
		"two-isolated-users": {
			users: map[string]int{
				"user1": 2,
				"user2": 2,
			},
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"user1"},
						Destinations: []string{"user1:*"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user2"},
						Destinations: []string{"user2:*"},
					},
				},
			}, want: map[string]int{
				"user1": 1,
				"user2": 1,
			},
		},
		// Test that when we have two users, with ACLs and they
		// are restricted to a single port, nodes are still present
		// in the netmap.
		"two-restricted-present-in-netmap": {
			users: map[string]int{
				"user1": 2,
				"user2": 2,
			},
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"user1"},
						Destinations: []string{"user1:22"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user2"},
						Destinations: []string{"user2:22"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user1"},
						Destinations: []string{"user2:22"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user2"},
						Destinations: []string{"user1:22"},
					},
				},
			}, want: map[string]int{
				"user1": 3,
				"user2": 3,
			},
		},
		// Test that when we have two users, that are isolated,
		// but one can see the others, we have the appropriate number
		// of peers. This will still result in all the peers as we
		// need them present on the other side for the "return path".
		"two-ns-one-isolated": {
			users: map[string]int{
				"user1": 2,
				"user2": 2,
			},
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"user1"},
						Destinations: []string{"user1:*"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user2"},
						Destinations: []string{"user2:*"},
					},
					{
						Action:       "accept",
						Sources:      []string{"user1"},
						Destinations: []string{"user2:*"},
					},
				},
			}, want: map[string]int{
				"user1": 3, // ns1 + ns2
				"user2": 3, // ns1 + ns2 (return path)
			},
		},
	}

	for name, testCase := range tests {
		t.Run(name, func(t *testing.T) {
			scenario, err := NewScenario()
			assert.NoError(t, err)

			spec := testCase.users

			err = scenario.CreateHeadscaleEnv(spec,
				[]tsic.Option{},
				hsic.WithACLPolicy(&testCase.policy),
				// hsic.WithTestName(fmt.Sprintf("aclinnetmap%s", name)),
			)
			assert.NoError(t, err)

			allClients, err := scenario.ListTailscaleClients()
			assert.NoError(t, err)

			err = scenario.WaitForTailscaleSync()
			assert.NoError(t, err)

			// allHostnames, err := scenario.ListTailscaleClientsFQDNs()
			// assert.NoError(t, err)

			for _, client := range allClients {
				status, err := client.Status()
				assert.NoError(t, err)

				user := status.User[status.Self.UserID].LoginName

				assert.Equal(t, (testCase.want[user]), len(status.Peer))
			}

			err = scenario.Shutdown()
			assert.NoError(t, err)
		})
	}
}

// Test to confirm that we can use user:80 from one user
// This should make the node appear in the peer list, but
// disallow ping.
// This ACL will not allow user1 access its own nodes.
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowUser80Dst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&headscale.ACLPolicy{
			ACLs: []headscale.ACL{
				{
					Action:       "accept",
					Sources:      []string{"user1"},
					Destinations: []string{"user2:80"},
				},
			},
		},
		1,
	)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	assert.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	assert.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assert.NoError(t, err)
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

func TestACLDenyAllPort80(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&headscale.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-acl-test": {"user1", "user2"},
			},
			ACLs: []headscale.ACL{
				{
					Action:       "accept",
					Sources:      []string{"group:integration-acl-test"},
					Destinations: []string{"*:22"},
				},
			},
		},
		4,
	)

	allClients, err := scenario.ListTailscaleClients()
	assert.NoError(t, err)

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	assert.NoError(t, err)

	for _, client := range allClients {
		for _, hostname := range allHostnames {
			// We will always be allowed to check _self_ so shortcircuit
			// the test here.
			if strings.Contains(hostname, client.Hostname()) {
				continue
			}

			url := fmt.Sprintf("http://%s/etc/hostname", hostname)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

// Test to confirm that we can use user:* from one user.
// This ACL will not allow user1 access its own nodes.
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowUserDst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&headscale.ACLPolicy{
			ACLs: []headscale.ACL{
				{
					Action:       "accept",
					Sources:      []string{"user1"},
					Destinations: []string{"user2:*"},
				},
			},
		},
		2,
	)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	assert.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	assert.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assert.NoError(t, err)
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

// Test to confirm that we can use *:* from one user
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowStarDst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&headscale.ACLPolicy{
			ACLs: []headscale.ACL{
				{
					Action:       "accept",
					Sources:      []string{"user1"},
					Destinations: []string{"*:*"},
				},
			},
		},
		2,
	)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	assert.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	assert.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assert.NoError(t, err)
		}
	}

	// Test that user2 _cannot_ visit user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Empty(t, result)
			assert.Error(t, err)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
}

// TestACLNamedHostsCanReachBySubnet is the same as
// TestACLNamedHostsCanReach, but it tests if we expand a
// full CIDR correctly. All routes should work.
func TestACLNamedHostsCanReachBySubnet(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		&headscale.ACLPolicy{
			Hosts: headscale.Hosts{
				"all": netip.MustParsePrefix("100.64.0.0/24"),
			},
			ACLs: []headscale.ACL{
				// Everyone can curl test3
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"all:*"},
				},
			},
		},
		3,
	)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	assert.NoError(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	assert.NoError(t, err)

	// Test that user1 can visit all user2
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assert.NoError(t, err)
		}
	}

	// Test that user2 can visit all user1
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			fqdn, err := peer.FQDN()
			assert.NoError(t, err)

			url := fmt.Sprintf("http://%s/etc/hostname", fqdn)
			t.Logf("url from %s to %s", client.Hostname(), url)

			result, err := client.Curl(url)
			assert.Len(t, result, 13)
			assert.NoError(t, err)
		}
	}

	err = scenario.Shutdown()
	assert.NoError(t, err)
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
		policy headscale.ACLPolicy
	}{
		"ipv4": {
			policy: headscale.ACLPolicy{
				Hosts: headscale.Hosts{
					"test1": netip.MustParsePrefix("100.64.0.1/32"),
					"test2": netip.MustParsePrefix("100.64.0.2/32"),
					"test3": netip.MustParsePrefix("100.64.0.3/32"),
				},
				ACLs: []headscale.ACL{
					// Everyone can curl test3
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"test3:*"},
					},
					// test1 can curl test2
					{
						Action:       "accept",
						Sources:      []string{"test1"},
						Destinations: []string{"test2:*"},
					},
				},
			},
		},
		"ipv6": {
			policy: headscale.ACLPolicy{
				Hosts: headscale.Hosts{
					"test1": netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					"test2": netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
					"test3": netip.MustParsePrefix("fd7a:115c:a1e0::3/128"),
				},
				ACLs: []headscale.ACL{
					// Everyone can curl test3
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"test3:*"},
					},
					// test1 can curl test2
					{
						Action:       "accept",
						Sources:      []string{"test1"},
						Destinations: []string{"test2:*"},
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

			// Since user/users dont matter here, we basically expect that some clients
			// will be assigned these ips and that we can pick them up for our own use.
			test1ip4 := netip.MustParseAddr("100.64.0.1")
			test1ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
			test1, err := scenario.FindTailscaleClientByIP(test1ip6)
			assert.NoError(t, err)

			test1fqdn, err := test1.FQDN()
			assert.NoError(t, err)
			test1ip4URL := fmt.Sprintf("http://%s/etc/hostname", test1ip4.String())
			test1ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test1ip6.String())
			test1fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test1fqdn)

			test2ip4 := netip.MustParseAddr("100.64.0.2")
			test2ip6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
			test2, err := scenario.FindTailscaleClientByIP(test2ip6)
			assert.NoError(t, err)

			test2fqdn, err := test2.FQDN()
			assert.NoError(t, err)
			test2ip4URL := fmt.Sprintf("http://%s/etc/hostname", test2ip4.String())
			test2ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test2ip6.String())
			test2fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test2fqdn)

			test3ip4 := netip.MustParseAddr("100.64.0.3")
			test3ip6 := netip.MustParseAddr("fd7a:115c:a1e0::3")
			test3, err := scenario.FindTailscaleClientByIP(test3ip6)
			assert.NoError(t, err)

			test3fqdn, err := test3.FQDN()
			assert.NoError(t, err)
			test3ip4URL := fmt.Sprintf("http://%s/etc/hostname", test3ip4.String())
			test3ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test3ip6.String())
			test3fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test3fqdn)

			// test1 can query test3
			result, err := test1.Curl(test3ip4URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3ip4URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test1.Curl(test3ip6URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3ip6URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test1.Curl(test3fqdnURL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3fqdnURL,
				result,
			)
			assert.NoError(t, err)

			// test2 can query test3
			result, err = test2.Curl(test3ip4URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3ip4URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test2.Curl(test3ip6URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3ip6URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test2.Curl(test3fqdnURL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test3 with URL %s, expected hostname of 13 chars, got %s",
				test3fqdnURL,
				result,
			)
			assert.NoError(t, err)

			// test3 cannot query test1
			result, err = test3.Curl(test1ip4URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test3.Curl(test1ip6URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test3.Curl(test1fqdnURL)
			assert.Empty(t, result)
			assert.Error(t, err)

			// test3 cannot query test2
			result, err = test3.Curl(test2ip4URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test3.Curl(test2ip6URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test3.Curl(test2fqdnURL)
			assert.Empty(t, result)
			assert.Error(t, err)

			// test1 can query test2
			result, err = test1.Curl(test2ip4URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
				test2ip4URL,
				result,
			)

			assert.NoError(t, err)
			result, err = test1.Curl(test2ip6URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
				test2ip6URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test1.Curl(test2fqdnURL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test2 with URL %s, expected hostname of 13 chars, got %s",
				test2fqdnURL,
				result,
			)
			assert.NoError(t, err)

			// test2 cannot query test1
			result, err = test2.Curl(test1ip4URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test2.Curl(test1ip6URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test2.Curl(test1fqdnURL)
			assert.Empty(t, result)
			assert.Error(t, err)

			err = scenario.Shutdown()
			assert.NoError(t, err)
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
		policy headscale.ACLPolicy
	}{
		"ipv4": {
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"100.64.0.1"},
						Destinations: []string{"100.64.0.2:*"},
					},
				},
			},
		},
		"ipv6": {
			policy: headscale.ACLPolicy{
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"fd7a:115c:a1e0::1"},
						Destinations: []string{"fd7a:115c:a1e0::2:*"},
					},
				},
			},
		},
		"hostv4cidr": {
			policy: headscale.ACLPolicy{
				Hosts: headscale.Hosts{
					"test1": netip.MustParsePrefix("100.64.0.1/32"),
					"test2": netip.MustParsePrefix("100.64.0.2/32"),
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"test1"},
						Destinations: []string{"test2:*"},
					},
				},
			},
		},
		"hostv6cidr": {
			policy: headscale.ACLPolicy{
				Hosts: headscale.Hosts{
					"test1": netip.MustParsePrefix("fd7a:115c:a1e0::1/128"),
					"test2": netip.MustParsePrefix("fd7a:115c:a1e0::2/128"),
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"test1"},
						Destinations: []string{"test2:*"},
					},
				},
			},
		},
		"group": {
			policy: headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:one": {"user1"},
					"group:two": {"user2"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"group:one"},
						Destinations: []string{"group:two:*"},
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

			test1ip := netip.MustParseAddr("100.64.0.1")
			test1ip6 := netip.MustParseAddr("fd7a:115c:a1e0::1")
			test1, err := scenario.FindTailscaleClientByIP(test1ip)
			assert.NotNil(t, test1)
			assert.NoError(t, err)

			test1fqdn, err := test1.FQDN()
			assert.NoError(t, err)
			test1ipURL := fmt.Sprintf("http://%s/etc/hostname", test1ip.String())
			test1ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test1ip6.String())
			test1fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test1fqdn)

			test2ip := netip.MustParseAddr("100.64.0.2")
			test2ip6 := netip.MustParseAddr("fd7a:115c:a1e0::2")
			test2, err := scenario.FindTailscaleClientByIP(test2ip)
			assert.NotNil(t, test2)
			assert.NoError(t, err)

			test2fqdn, err := test2.FQDN()
			assert.NoError(t, err)
			test2ipURL := fmt.Sprintf("http://%s/etc/hostname", test2ip.String())
			test2ip6URL := fmt.Sprintf("http://[%s]/etc/hostname", test2ip6.String())
			test2fqdnURL := fmt.Sprintf("http://%s/etc/hostname", test2fqdn)

			// test1 can query test2
			result, err := test1.Curl(test2ipURL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
				test2ipURL,
				result,
			)
			assert.NoError(t, err)

			result, err = test1.Curl(test2ip6URL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
				test2ip6URL,
				result,
			)
			assert.NoError(t, err)

			result, err = test1.Curl(test2fqdnURL)
			assert.Lenf(
				t,
				result,
				13,
				"failed to connect from test1 to test with URL %s, expected hostname of 13 chars, got %s",
				test2fqdnURL,
				result,
			)
			assert.NoError(t, err)

			result, err = test2.Curl(test1ipURL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test2.Curl(test1ip6URL)
			assert.Empty(t, result)
			assert.Error(t, err)

			result, err = test2.Curl(test1fqdnURL)
			assert.Empty(t, result)
			assert.Error(t, err)

			err = scenario.Shutdown()
			assert.NoError(t, err)
		})
	}
}
