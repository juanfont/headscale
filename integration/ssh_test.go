package integration

import (
	"fmt"
	"log"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func isSSHNoAccessStdError(stderr string) bool {
	return strings.Contains(stderr, "Permission denied (tailscale)") ||
		// Since https://github.com/tailscale/tailscale/pull/14853
		strings.Contains(stderr, "failed to evaluate SSH policy") ||
		// Since https://github.com/tailscale/tailscale/pull/16127
		// Covers both "to this node" and "as user <name>" variants.
		strings.Contains(stderr, "tailnet policy does not permit you to SSH")
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
					Action:  "accept",
					Sources: policyv2.SSHSrcAliases{groupp("group:integration-test")},
					// Use autogroup:member and autogroup:tagged instead of wildcard
					// since wildcard (*) is no longer supported for SSH destinations
					Destinations: policyv2.SSHDstAliases{
						new(policyv2.AutoGroupMember),
						new(policyv2.AutoGroupTagged),
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

// TestSSHMultipleUsersAllToAll tests that users in a group can SSH to each other's devices
// using autogroup:self as the destination, which allows same-user SSH access.
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
			SSHs: []policyv2.SSH{
				{
					Action:  "accept",
					Sources: policyv2.SSHSrcAliases{groupp("group:integration-test")},
					// Use autogroup:self to allow users to SSH to their own devices.
					// Username destinations (e.g., "user1@") now require the source
					// to be that exact same user only. For group-to-group SSH access,
					// use autogroup:self instead.
					Destinations: policyv2.SSHDstAliases{new(policyv2.AutoGroupSelf)},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
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

	// With autogroup:self, users can SSH to their own devices, but not to other users' devices.
	// Test that user1's devices can SSH to each other
	for _, client := range nsOneClients {
		for _, peer := range nsOneClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	// Test that user2's devices can SSH to each other
	for _, client := range nsTwoClients {
		for _, peer := range nsTwoClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	// Test that user1 cannot SSH to user2's devices (autogroup:self only allows same-user)
	for _, client := range nsOneClients {
		for _, peer := range nsTwoClients {
			assertSSHPermissionDenied(t, client, peer)
		}
	}

	// Test that user2 cannot SSH to user1's devices (autogroup:self only allows same-user)
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
			SSHs: []policyv2.SSH{
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{groupp("group:integration-test")},
					Destinations: policyv2.SSHDstAliases{new(policyv2.AutoGroupSelf)},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
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
			SSHs: []policyv2.SSH{
				// Use autogroup:self to allow users in each group to SSH to their own devices.
				// Username destinations (e.g., "user1@") require the source to be that
				// exact same user only, not a group containing that user.
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{groupp("group:ssh1")},
					Destinations: policyv2.SSHDstAliases{new(policyv2.AutoGroupSelf)},
					Users:        []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				},
				{
					Action:       "accept",
					Sources:      policyv2.SSHSrcAliases{groupp("group:ssh2")},
					Destinations: policyv2.SSHDstAliases{new(policyv2.AutoGroupSelf)},
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

	return doSSHWithRetryAsUser(t, client, peer, "ssh-it-user", retry)
}

func doSSHWithRetryAsUser(
	t *testing.T,
	client TailscaleClient,
	peer TailscaleClient,
	sshUser string,
	retry bool,
) (string, string, error) {
	t.Helper()

	peerFQDN, _ := peer.FQDN()

	command := []string{
		"/usr/bin/ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
		fmt.Sprintf("%s@%s", sshUser, peerFQDN),
		"'hostname'",
	}

	log.Printf("Running from %s to %s as %s", client.Hostname(), peer.Hostname(), sshUser)
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
	require.Error(t, err)

	if !isSSHNoAccessStdError(stderr) {
		t.Errorf("expected stderr output suggesting access denied, got: %s", stderr)
	}
}

func doSSHAsUser(t *testing.T, client TailscaleClient, peer TailscaleClient, sshUser string) (string, string, error) {
	t.Helper()

	return doSSHWithRetryAsUser(t, client, peer, sshUser, true)
}

func assertSSHHostnameAsUser(t *testing.T, client TailscaleClient, peer TailscaleClient, sshUser string) {
	t.Helper()

	result, _, err := doSSHAsUser(t, client, peer, sshUser)
	require.NoError(t, err)

	require.Contains(t, peer.ContainerID(), strings.ReplaceAll(result, "\n", ""))
}

func assertSSHPermissionDeniedAsUser(t *testing.T, client TailscaleClient, peer TailscaleClient, sshUser string) {
	t.Helper()

	result, stderr, err := doSSHWithRetryAsUser(t, client, peer, sshUser, false)

	assert.Empty(t, result)

	assertSSHNoAccessStdError(t, err, stderr)
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
						new(policyv2.AutoGroupMember),
					},
					Destinations: policyv2.SSHDstAliases{
						new(policyv2.AutoGroupSelf),
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

// TestSSHLocalpart tests that SSH with localpart:*@<domain> works correctly.
// localpart maps the local-part of each user's OIDC email to an OS user,
// so user1@headscale.net can SSH as local user "user1".
// This requires OIDC login so that users have real email addresses.
func TestSSHLocalpart(t *testing.T) {
	IntegrationSkip(t)

	baseACLs := []policyv2.ACL{
		{
			Action:   "accept",
			Protocol: "tcp",
			Sources:  []policyv2.Alias{wildcard()},
			Destinations: []policyv2.AliasWithPorts{
				aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
			},
		},
	}

	tests := []struct {
		name   string
		policy *policyv2.Policy
		testFn func(t *testing.T, scenario *Scenario)
	}{
		{
			name: "MemberAndTagged",
			policy: &policyv2.Policy{
				ACLs: baseACLs,
				SSHs: []policyv2.SSH{
					{
						Action:  "accept",
						Sources: policyv2.SSHSrcAliases{new(policyv2.AutoGroupMember)},
						Destinations: policyv2.SSHDstAliases{
							new(policyv2.AutoGroupMember),
							new(policyv2.AutoGroupTagged),
						},
						Users: []policyv2.SSHUser{"localpart:*@headscale.net"},
					},
				},
			},
			testFn: func(t *testing.T, scenario *Scenario) {
				t.Helper()

				user1Clients, err := scenario.ListTailscaleClients("user1")
				requireNoErrListClients(t, err)

				user2Clients, err := scenario.ListTailscaleClients("user2")
				requireNoErrListClients(t, err)

				// user1 can SSH to user2's nodes as "user1" (localpart of user1@headscale.net)
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHHostnameAsUser(t, client, peer, "user1")
					}
				}

				// user2 can SSH to user1's nodes as "user2" (localpart of user2@headscale.net)
				for _, client := range user2Clients {
					for _, peer := range user1Clients {
						assertSSHHostnameAsUser(t, client, peer, "user2")
					}
				}

				// user1 CANNOT SSH as "user2" — no rule maps user1's IPs to user2
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHPermissionDeniedAsUser(t, client, peer, "user2")
					}
				}

				// user2 CANNOT SSH as "user1" — no rule maps user2's IPs to user1
				for _, client := range user2Clients {
					for _, peer := range user1Clients {
						assertSSHPermissionDeniedAsUser(t, client, peer, "user1")
					}
				}
			},
		},
		{
			name: "AutogroupSelf",
			policy: &policyv2.Policy{
				ACLs: baseACLs,
				SSHs: []policyv2.SSH{
					{
						Action:       "accept",
						Sources:      policyv2.SSHSrcAliases{new(policyv2.AutoGroupMember)},
						Destinations: policyv2.SSHDstAliases{new(policyv2.AutoGroupSelf)},
						Users:        []policyv2.SSHUser{"localpart:*@headscale.net"},
					},
				},
			},
			testFn: func(t *testing.T, scenario *Scenario) {
				t.Helper()

				user1Clients, err := scenario.ListTailscaleClients("user1")
				requireNoErrListClients(t, err)

				user2Clients, err := scenario.ListTailscaleClients("user2")
				requireNoErrListClients(t, err)

				// With autogroup:self, cross-user SSH should be denied regardless of localpart.
				// user1 cannot SSH to user2's nodes as "user1"
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHPermissionDeniedAsUser(t, client, peer, "user1")
					}
				}

				// user2 cannot SSH to user1's nodes as "user2"
				for _, client := range user2Clients {
					for _, peer := range user1Clients {
						assertSSHPermissionDeniedAsUser(t, client, peer, "user2")
					}
				}

				// user1 also cannot SSH to user2's nodes as "user2"
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHPermissionDeniedAsUser(t, client, peer, "user2")
					}
				}
			},
		},
		{
			name: "LocalpartPlusRoot",
			policy: &policyv2.Policy{
				ACLs: baseACLs,
				SSHs: []policyv2.SSH{
					{
						Action:  "accept",
						Sources: policyv2.SSHSrcAliases{new(policyv2.AutoGroupMember)},
						Destinations: policyv2.SSHDstAliases{
							new(policyv2.AutoGroupMember),
							new(policyv2.AutoGroupTagged),
						},
						Users: []policyv2.SSHUser{
							"localpart:*@headscale.net",
							"root",
						},
					},
				},
			},
			testFn: func(t *testing.T, scenario *Scenario) {
				t.Helper()

				user1Clients, err := scenario.ListTailscaleClients("user1")
				requireNoErrListClients(t, err)

				user2Clients, err := scenario.ListTailscaleClients("user2")
				requireNoErrListClients(t, err)

				// localpart works: user1 can SSH to user2's nodes as "user1"
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHHostnameAsUser(t, client, peer, "user1")
					}
				}

				// root also works: user1 can SSH to user2's nodes as "root"
				for _, client := range user1Clients {
					for _, peer := range user2Clients {
						assertSSHHostnameAsUser(t, client, peer, "root")
					}
				}

				// user2 can SSH as "user2" (localpart)
				for _, client := range user2Clients {
					for _, peer := range user1Clients {
						assertSSHHostnameAsUser(t, client, peer, "user2")
					}
				}

				// user2 can SSH as "root"
				for _, client := range user2Clients {
					for _, peer := range user1Clients {
						assertSSHHostnameAsUser(t, client, peer, "root")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec := ScenarioSpec{
				NodesPerUser: 1,
				Users:        []string{"user1", "user2"},
				OIDCUsers: []mockoidc.MockUser{
					oidcMockUser("user1", true),
					oidcMockUser("user2", true),
				},
			}

			scenario, err := NewScenario(spec)

			require.NoError(t, err)
			defer scenario.ShutdownAssertNoPanics(t)

			oidcMap := map[string]string{
				"HEADSCALE_OIDC_ISSUER":             scenario.mockOIDC.Issuer(),
				"HEADSCALE_OIDC_CLIENT_ID":          scenario.mockOIDC.ClientID(),
				"CREDENTIALS_DIRECTORY_TEST":        "/tmp",
				"HEADSCALE_OIDC_CLIENT_SECRET_PATH": "${CREDENTIALS_DIRECTORY_TEST}/hs_client_oidc_secret",
			}

			err = scenario.CreateHeadscaleEnvWithLoginURL(
				[]tsic.Option{
					tsic.WithSSH(),
					tsic.WithNetfilter("off"),
					tsic.WithPackages("openssh"),
					tsic.WithExtraCommands("adduser user1", "adduser user2"),
					tsic.WithDockerWorkdir("/"),
				},
				hsic.WithTestName("sshlocalpart"),
				hsic.WithACLPolicy(tt.policy),
				hsic.WithConfigEnv(oidcMap),
				hsic.WithTLS(),
				hsic.WithFileInContainer("/tmp/hs_client_oidc_secret", []byte(scenario.mockOIDC.ClientSecret())),
			)
			requireNoErrHeadscaleEnv(t, err)

			err = scenario.WaitForTailscaleSync()
			requireNoErrSync(t, err)

			_, err = scenario.ListTailscaleClientsFQDNs()
			requireNoErrListFQDN(t, err)

			tt.testFn(t, scenario)
		})
	}
}
