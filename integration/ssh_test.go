package integration

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

func isSSHNoAccessStdError(stderr string) bool {
	return strings.Contains(stderr, "Permission denied (tailscale)") ||
		// Since https://github.com/tailscale/tailscale/pull/14853
		strings.Contains(stderr, "failed to evaluate SSH policy") ||
		// Since https://github.com/tailscale/tailscale/pull/16127
		strings.Contains(stderr, "tailnet policy does not permit you to SSH to this node")
}

func sshScenario(t *testing.T, policy *policyv2.Policy, clientsPerUser int) *Scenario {
	t.Helper()

	spec := ScenarioSpec{
		NodesPerUser: clientsPerUser,
		Users:        []string{"user1", "user2"},
	}
	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithSSH(),

			// Alpine containers dont have ip6tables set up, which causes
			// tailscaled to stop configuring the wgengine, causing it
			// to not configure DNS.
			tsic.WithNetfilter("off"),
			tsic.WithPackages("openssh"),
			tsic.WithExtraCommands("adduser ssh-it-user"),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("ssh"),
	)
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	require.NoError(t, err)

	return scenario
}

func TestSSHOneUserToAll(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:integration-test"): []policyv2.Username{policyv2.Username("user1@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
			SSHs: []policyv2.SSH{
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{groupp("group:integration-test")},
					Destinations: policyv2.SSHDstAliases{wildcard()},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
			},
		},
		len(MustTestVersions),
	)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	for _, client := range user2Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

// TestSSHMultipleUsersAllToAll tests that users in the same group can SSH to each other's devices.
// Per Tailscale rules, user->user SSH requires separate rules for each user:
// - user1@ can SSH to user1@ devices (same user)
// - user2@ can SSH to user2@ devices (same user)
// Note: Cross-user SSH (user1@ -> user2@) requires using tags as destinations.
func TestSSHMultipleUsersAllToAll(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:integration-test"): []policyv2.Username{policyv2.Username("user1@"), policyv2.Username("user2@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
			// Per Tailscale rules: when dst is a username, src must be only the same username.
			// Use autogroup:self to allow same-user SSH across all users.
			SSHs: []policyv2.SSH{
				{
					Action: "accept",
					Sources: policyv2.SSHSrcAliases{
						ptr.To(policyv2.AutoGroupMember),
					},
					Destinations: policyv2.SSHDstAliases{
						ptr.To(policyv2.AutoGroupSelf),
					},
					Users: []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
			},
		},
		len(MustTestVersions),
	)
	defer scenario.ShutdownAssertNoPanics(t)

	nsOneClients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	nsTwoClients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// With autogroup:self, users can only SSH to their own devices
	// Test same-user SSH works
	for _, client := range nsOneClients {
		for _, peer := range nsOneClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	for _, client := range nsTwoClients {
		for _, peer := range nsTwoClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	// Test cross-user SSH is denied (autogroup:self restricts to same user)
	for _, client := range nsOneClients {
		for _, peer := range nsTwoClients {
			assertSSHPermissionDenied(t, client, peer)
		}
	}

	for _, client := range nsTwoClients {
		for _, peer := range nsOneClients {
			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

func TestSSHNoSSHConfigured(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:integration-test"): []policyv2.Username{policyv2.Username("user1@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
			SSHs: []policyv2.SSH{},
		},
		len(MustTestVersions),
	)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

// TestSSHIsBlockedInACL tests that SSH connections timeout when ACL doesn't allow port 22.
// Uses autogroup:self for SSH policy (valid), but ACL only allows port 80.
func TestSSHIsBlockedInACL(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:integration-test"): []policyv2.Username{policyv2.Username("user1@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRange{First: 80, Last: 80}),
					},
				},
			},
			// Use autogroup:self which is a valid SSH src/dst combination
			SSHs: []policyv2.SSH{
				{
					Action: "accept",
					Sources: policyv2.SSHSrcAliases{
						ptr.To(policyv2.AutoGroupMember),
					},
					Destinations: policyv2.SSHDstAliases{
						ptr.To(policyv2.AutoGroupSelf),
					},
					Users: []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
			},
		},
		len(MustTestVersions),
	)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHTimeout(t, client, peer)
		}
	}
}

// TestSSHUserOnlyIsolation tests that users can only SSH to their own devices.
// Uses user@->user@ rules (valid: same user as src and dst) to achieve isolation.
func TestSSHUserOnlyIsolation(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			Groups: policyv2.Groups{
				policyv2.Group("group:ssh1"): []policyv2.Username{policyv2.Username("user1@")},
				policyv2.Group("group:ssh2"): []policyv2.Username{policyv2.Username("user2@")},
			},
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
			// Per Tailscale rules: when dst is a username, src must be only the same username.
			// Valid: user1@ -> user1@, user2@ -> user2@
			SSHs: []policyv2.SSH{
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{usernamep("user1@")},
					Destinations: policyv2.SSHDstAliases{usernamep("user1@")},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{usernamep("user2@")},
					Destinations: policyv2.SSHDstAliases{usernamep("user2@")},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
			},
		},
		len(MustTestVersions),
	)
	defer scenario.ShutdownAssertNoPanics(t)

	ssh1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	ssh2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	for _, client := range ssh1Clients {
		for _, peer := range ssh2Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}

	for _, client := range ssh2Clients {
		for _, peer := range ssh1Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}

	for _, client := range ssh1Clients {
		for _, peer := range ssh1Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	for _, client := range ssh2Clients {
		for _, peer := range ssh2Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}
}

func doSSH(t *testing.T, client TailscaleClient, peer TailscaleClient) (string, string, error) {
	t.Helper()
	return doSSHWithRetry(t, client, peer, true)
}

func doSSHWithoutRetry(t *testing.T, client TailscaleClient, peer TailscaleClient) (string, string, error) {
	t.Helper()
	return doSSHWithRetry(t, client, peer, false)
}

func doSSHWithRetry(t *testing.T, client TailscaleClient, peer TailscaleClient, retry bool) (string, string, error) {
	t.Helper()

	peerFQDN, _ := peer.FQDN()

	command := []string{
		"/usr/bin/ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
		fmt.Sprintf("%s@%s", "ssh-it-user", peerFQDN),
		"'hostname'",
	}

	log.Printf("Running from %s to %s", client.Hostname(), peer.Hostname())
	log.Printf("Command: %s", strings.Join(command, " "))

	var (
		result, stderr string
		err            error
	)

	if retry {
		// Use assert.EventuallyWithT to retry SSH connections for success cases
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			result, stderr, err = client.Execute(command)

			// If we get a permission denied error, we can fail immediately
			// since that is something we won't recover from by retrying.
			if err != nil && isSSHNoAccessStdError(stderr) {
				return // Don't retry permission denied errors
			}

			// For all other errors, assert no error to trigger retry
			assert.NoError(ct, err)
		}, 10*time.Second, 200*time.Millisecond)
	} else {
		// For failure cases, just execute once
		result, stderr, err = client.Execute(command)
	}

	return result, stderr, err
}

func assertSSHHostname(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, _, err := doSSH(t, client, peer)
	require.NoError(t, err)

	require.Contains(t, peer.ContainerID(), strings.ReplaceAll(result, "\n", ""))
}

func assertSSHPermissionDenied(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, stderr, err := doSSHWithoutRetry(t, client, peer)

	assert.Empty(t, result)

	assertSSHNoAccessStdError(t, err, stderr)
}

func assertSSHTimeout(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, stderr, _ := doSSHWithoutRetry(t, client, peer)

	assert.Empty(t, result)

	if !strings.Contains(stderr, "Connection timed out") &&
		!strings.Contains(stderr, "Operation timed out") {
		t.Fatalf("connection did not time out")
	}
}

func assertSSHNoAccessStdError(t *testing.T, err error, stderr string) {
	t.Helper()
	assert.Error(t, err)

	if !isSSHNoAccessStdError(stderr) {
		t.Errorf("expected stderr output suggesting access denied, got: %s", stderr)
	}
}

// TestSSHAutogroupSelf tests that SSH with autogroup:self works correctly:
// - Users can SSH to their own devices
// - Users cannot SSH to other users' devices.
func TestSSHAutogroupSelf(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t,
		&policyv2.Policy{
			ACLs: []policyv2.ACL{
				{
					Action:   "accept",
					Protocol: "tcp",
					Sources:  []policyv2.Alias{wildcard()},
					Destinations: []policyv2.AliasWithPorts{
						aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
					},
				},
			},
			SSHs: []policyv2.SSH{
				{
					Action: "accept",
					Sources: policyv2.SSHSrcAliases{
						ptr.To(policyv2.AutoGroupMember),
					},
					Destinations: policyv2.SSHDstAliases{
						ptr.To(policyv2.AutoGroupSelf),
					},
					Users: []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
			},
		},
		2, // 2 clients per user
	)
	defer scenario.ShutdownAssertNoPanics(t)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// Test that user1's devices can SSH to each other
	for _, client := range user1Clients {
		for _, peer := range user1Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	// Test that user2's devices can SSH to each other
	for _, client := range user2Clients {
		for _, peer := range user2Clients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	// Test that user1 cannot SSH to user2's devices
	for _, client := range user1Clients {
		for _, peer := range user2Clients {
			assertSSHPermissionDenied(t, client, peer)
		}
	}

	// Test that user2 cannot SSH to user1's devices
	for _, client := range user2Clients {
		for _, peer := range user1Clients {
			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

// TestSSHInvalidPolicySrcDstValidation tests that invalid SSH src/dst combinations
// are rejected at policy validation time.
// Per Tailscale docs: when dst contains a username, src must contain only the same username.
// See: https://tailscale.com/kb/1337/policy-syntax#dst-1
// This test verifies #3010 is fixed: SSH from tagged device to user device should be denied.
func TestSSHInvalidPolicySrcDstValidation(t *testing.T) {
	// This test doesn't need Docker - it validates policy parsing via NewPolicyManager
	// which unmarshals and validates the policy JSON
	tests := []struct {
		name      string
		policy    string
		expectErr bool
		errMsg    string
	}{
		{
			name: "tag-src-user-dst-rejected",
			policy: `{
				"tagOwners": {
					"tag:server": ["user1@"]
				},
				"ssh": [{
					"action": "accept",
					"src": ["tag:server"],
					"dst": ["user1@"],
					"users": ["root"]
				}]
			}`,
			expectErr: true,
			errMsg:    "tags in src cannot SSH to user-owned devices",
		},
		{
			name: "group-src-user-dst-rejected",
			policy: `{
				"groups": {
					"group:admins": ["user1@"]
				},
				"ssh": [{
					"action": "accept",
					"src": ["group:admins"],
					"dst": ["user1@"],
					"users": ["root"]
				}]
			}`,
			expectErr: true,
			errMsg:    "groups in src cannot SSH to user-owned devices",
		},
		{
			name: "different-user-src-dst-rejected",
			policy: `{
				"ssh": [{
					"action": "accept",
					"src": ["user2@"],
					"dst": ["user1@"],
					"users": ["root"]
				}]
			}`,
			expectErr: true,
			errMsg:    "users in dst are only allowed from the same user",
		},
		{
			name: "same-user-src-dst-allowed",
			policy: `{
				"ssh": [{
					"action": "accept",
					"src": ["user1@"],
					"dst": ["user1@"],
					"users": ["root"]
				}]
			}`,
			expectErr: false,
		},
		{
			name: "tag-src-tag-dst-allowed",
			policy: `{
				"tagOwners": {
					"tag:client": ["user1@"],
					"tag:server": ["user1@"]
				},
				"ssh": [{
					"action": "accept",
					"src": ["tag:client"],
					"dst": ["tag:server"],
					"users": ["root"]
				}]
			}`,
			expectErr: false,
		},
		{
			name: "group-src-tag-dst-allowed",
			policy: `{
				"groups": {
					"group:admins": ["user1@"]
				},
				"tagOwners": {
					"tag:server": ["user1@"]
				},
				"ssh": [{
					"action": "accept",
					"src": ["group:admins"],
					"dst": ["tag:server"],
					"users": ["root"]
				}]
			}`,
			expectErr: false,
		},
		{
			name: "autogroup-self-allowed",
			policy: `{
				"ssh": [{
					"action": "accept",
					"src": ["autogroup:member"],
					"dst": ["autogroup:self"],
					"users": ["root"]
				}]
			}`,
			expectErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate the policy using NewPolicyManager which parses and validates JSON.
			// These tests only exercise SSH src/dst validation, so no users/nodes are needed.
			_, err := policyv2.NewPolicyManager(
				[]byte(tt.policy),
				nil,                       // users not needed for src/dst validation tests
				types.Nodes{}.ViewSlice(), // empty nodes sufficient for src/dst validation tests
			)

			if tt.expectErr {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.errMsg)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
