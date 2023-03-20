package integration

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

const numberOfTestClients = 2

func aclScenario(t *testing.T, policy headscale.ACLPolicy) *Scenario {
	t.Helper()
	scenario, err := NewScenario()
	assert.NoError(t, err)

	spec := map[string]int{
		"user1": numberOfTestClients,
		"user2": numberOfTestClients,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{
			tsic.WithDockerEntrypoint([]string{
				"/bin/bash",
				"-c",
				"/bin/sleep 3 ; update-ca-certificates ; python3 -m http.server 80 & tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(&policy),
		hsic.WithTestName("acldenyallping"),
	)
	assert.NoError(t, err)

	// allClients, err := scenario.ListTailscaleClients()
	// assert.NoError(t, err)

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
// This ACL will not allow user1 access its own machines.
// Reported: https://github.com/juanfont/headscale/issues/699
func TestACLAllowUser80Dst(t *testing.T) {
	IntegrationSkip(t)

	scenario := aclScenario(t,
		headscale.ACLPolicy{
			ACLs: []headscale.ACL{
				{
					Action:       "accept",
					Sources:      []string{"user1"},
					Destinations: []string{"user2:80"},
				},
			},
		},
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
