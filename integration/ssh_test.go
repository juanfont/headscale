package integration

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/dockertestutil"
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

type sshCheckResult struct {
	stdout string
	stderr string
	err    error
}

// doSSHCheck runs SSH in a goroutine with a longer timeout, returning a channel
// for the result. The SSH command will block while waiting for auth approval in
// check mode.
func doSSHCheck(
	t *testing.T,
	client TailscaleClient,
	peer TailscaleClient,
) chan sshCheckResult {
	t.Helper()

	peerFQDN, _ := peer.FQDN()

	command := []string{
		"/usr/bin/ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=30",
		fmt.Sprintf("%s@%s", "ssh-it-user", peerFQDN),
		"'hostname'",
	}

	log.Printf(
		"[SSH check] Running from %s to %s",
		client.Hostname(),
		peer.Hostname(),
	)

	ch := make(chan sshCheckResult, 1)

	go func() {
		stdout, stderr, err := client.Execute(
			command,
			dockertestutil.ExecuteCommandTimeout(60*time.Second),
		)
		ch <- sshCheckResult{stdout, stderr, err}
	}()

	return ch
}

// findSSHCheckAuthID polls headscale container logs for the SSH action auth-id.
// The SSH action handler logs "SSH action follow-up" with the auth_id on the
// follow-up request (where auth_id is non-empty).
func findSSHCheckAuthID(t *testing.T, headscale ControlServer) string {
	t.Helper()

	var authID string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, stderr, err := headscale.ReadLog()
		assert.NoError(c, err)

		for line := range strings.SplitSeq(stderr, "\n") {
			if !strings.Contains(line, "SSH action follow-up") {
				continue
			}

			if idx := strings.Index(line, "auth_id="); idx != -1 {
				start := idx + len("auth_id=")

				end := strings.IndexByte(line[start:], ' ')
				if end == -1 {
					end = len(line[start:])
				}

				authID = line[start : start+end]
			}
		}

		assert.NotEmpty(c, authID, "auth-id not found in headscale logs")
	}, 10*time.Second, 500*time.Millisecond, "waiting for SSH check auth-id in headscale logs")

	return authID
}

// sshCheckPolicy returns a policy with SSH "check" mode for group:integration-test
// targeting autogroup:member and autogroup:tagged destinations.
func sshCheckPolicy() *policyv2.Policy {
	return &policyv2.Policy{
		Groups: policyv2.Groups{
			policyv2.Group("group:integration-test"): []policyv2.Username{
				policyv2.Username("user1@"),
			},
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
				Action:  "check",
				Sources: policyv2.SSHSrcAliases{groupp("group:integration-test")},
				Destinations: policyv2.SSHDstAliases{
					new(policyv2.AutoGroupMember),
					new(policyv2.AutoGroupTagged),
				},
				Users: []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
			},
		},
	}
}

// sshCheckPolicyWithPeriod returns a policy with SSH "check" mode and a
// specified checkPeriod for session duration.
func sshCheckPolicyWithPeriod(period time.Duration) *policyv2.Policy {
	return &policyv2.Policy{
		Groups: policyv2.Groups{
			policyv2.Group("group:integration-test"): []policyv2.Username{
				policyv2.Username("user1@"),
			},
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
				Action:  "check",
				Sources: policyv2.SSHSrcAliases{groupp("group:integration-test")},
				Destinations: policyv2.SSHDstAliases{
					new(policyv2.AutoGroupMember),
					new(policyv2.AutoGroupTagged),
				},
				Users:       []policyv2.SSHUser{policyv2.SSHUser("ssh-it-user")},
				CheckPeriod: &policyv2.SSHCheckPeriod{Duration: period},
			},
		},
	}
}

// findNewSSHCheckAuthID polls headscale logs for an SSH check auth-id
// that differs from excludeID. Used to verify re-authentication after
// session expiry.
func findNewSSHCheckAuthID(
	t *testing.T,
	headscale ControlServer,
	excludeID string,
) string {
	t.Helper()

	var authID string

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, stderr, err := headscale.ReadLog()
		assert.NoError(c, err)

		for line := range strings.SplitSeq(stderr, "\n") {
			if !strings.Contains(line, "SSH action follow-up") {
				continue
			}

			if idx := strings.Index(line, "auth_id="); idx != -1 {
				start := idx + len("auth_id=")

				end := strings.IndexByte(line[start:], ' ')
				if end == -1 {
					end = len(line[start:])
				}

				id := line[start : start+end]
				if id != excludeID {
					authID = id
				}
			}
		}

		assert.NotEmpty(c, authID, "new auth-id not found in headscale logs")
	}, 10*time.Second, 500*time.Millisecond, "waiting for new SSH check auth-id")

	return authID
}

func TestSSHOneUserToOneCheckModeCLI(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t, sshCheckPolicy(), 1)
	// defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// user1 can SSH (via check) to all peers
	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			// Start SSH — will block waiting for check auth
			sshResult := doSSHCheck(t, client, peer)

			// Find the auth-id from headscale logs
			authID := findSSHCheckAuthID(t, headscale)

			// Approve via CLI
			_, err := headscale.Execute(
				[]string{
					"headscale", "auth", "approve",
					"--auth-id", authID,
				},
			)
			require.NoError(t, err)

			// Wait for SSH to complete
			select {
			case result := <-sshResult:
				require.NoError(t, result.err)
				require.Contains(
					t,
					peer.ContainerID(),
					strings.ReplaceAll(result.stdout, "\n", ""),
				)
			case <-time.After(30 * time.Second):
				t.Fatal("SSH did not complete after auth approval")
			}
		}
	}

	// user2 cannot SSH — not in the check policy group
	for _, client := range user2Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

func TestSSHOneUserToOneCheckModeOIDC(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser:         1,
		Users:                []string{"user1", "user2"},
		OIDCSkipUserCreation: true,
		OIDCUsers: []mockoidc.MockUser{
			// First 2: consumed during node registration
			oidcMockUser("user1", true),
			oidcMockUser("user2", true),
			// Extra: consumed during SSH check auth flows.
			// Each SSH check pops one user from the queue.
			oidcMockUser("user1", true),
		},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	// defer scenario.ShutdownAssertNoPanics(t)

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
			tsic.WithExtraCommands("adduser ssh-it-user"),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(sshCheckPolicy()),
		hsic.WithTestName("sshcheckoidc"),
		hsic.WithConfigEnv(oidcMap),
		hsic.WithTLS(),
		hsic.WithFileInContainer(
			"/tmp/hs_client_oidc_secret",
			[]byte(scenario.mockOIDC.ClientSecret()),
		),
	)
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// user1 can SSH (via check) to all peers
	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			// Start SSH — will block waiting for check auth
			sshResult := doSSHCheck(t, client, peer)

			// Find the auth-id from headscale logs
			authID := findSSHCheckAuthID(t, headscale)

			// Build auth URL and visit it to trigger OIDC flow.
			// The mock OIDC server auto-authenticates from the user queue.
			authURL := headscale.GetEndpoint() + "/auth/" + authID
			parsedURL, err := url.Parse(authURL)
			require.NoError(t, err)

			_, err = doLoginURL("ssh-check-oidc", parsedURL)
			require.NoError(t, err)

			// Wait for SSH to complete
			select {
			case result := <-sshResult:
				require.NoError(t, result.err)
				require.Contains(
					t,
					peer.ContainerID(),
					strings.ReplaceAll(result.stdout, "\n", ""),
				)
			case <-time.After(30 * time.Second):
				t.Fatal("SSH did not complete after OIDC auth")
			}
		}
	}

	// user2 cannot SSH — not in the check policy group
	for _, client := range user2Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

// TestSSHCheckModeUnapprovedTimeout verifies that SSH in check mode is rejected
// when nobody approves the auth request and the registration cache entry expires.
func TestSSHCheckModeUnapprovedTimeout(t *testing.T) {
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
			tsic.WithSSH(),
			tsic.WithNetfilter("off"),
			tsic.WithPackages("openssh"),
			tsic.WithExtraCommands("adduser ssh-it-user"),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(sshCheckPolicy()),
		hsic.WithTestName("sshchecktimeout"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_TUNING_REGISTER_CACHE_EXPIRATION": "15s",
			"HEADSCALE_TUNING_REGISTER_CACHE_CLEANUP":    "5s",
		}),
	)
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	user2Clients, err := scenario.ListTailscaleClients("user2")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// user1 attempts SSH — enters check flow, but nobody approves
	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			sshResult := doSSHCheck(t, client, peer)

			// Confirm the check flow was entered
			_ = findSSHCheckAuthID(t, headscale)

			// Do NOT approve — wait for cache expiry and SSH rejection
			select {
			case result := <-sshResult:
				require.Error(t, result.err, "SSH should be rejected when unapproved")
				assert.Empty(t, result.stdout, "no command output expected on rejection")
			case <-time.After(60 * time.Second):
				t.Fatal("SSH did not complete after cache expiry timeout")
			}
		}
	}

	// user2 still gets immediate Permission Denied
	for _, client := range user2Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}
}

// TestSSHCheckModeCheckPeriodCLI verifies that after approval with a short
// checkPeriod, the session expires and the next SSH connection requires
// re-authentication via a new check flow.
func TestSSHCheckModeCheckPeriodCLI(t *testing.T) {
	IntegrationSkip(t)

	// 1 minute is the documented minimum checkPeriod
	scenario := sshScenario(t, sshCheckPolicyWithPeriod(time.Minute), 1)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// === Phase 1: First SSH check — approve, verify success ===
	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			sshResult := doSSHCheck(t, client, peer)
			firstAuthID := findSSHCheckAuthID(t, headscale)

			_, err := headscale.Execute(
				[]string{
					"headscale", "auth", "approve",
					"--auth-id", firstAuthID,
				},
			)
			require.NoError(t, err)

			select {
			case result := <-sshResult:
				require.NoError(t, result.err, "first SSH should succeed after approval")
				require.Contains(
					t,
					peer.ContainerID(),
					strings.ReplaceAll(result.stdout, "\n", ""),
				)
			case <-time.After(30 * time.Second):
				t.Fatal("first SSH did not complete after auth approval")
			}

			// === Phase 2: Wait for checkPeriod to expire ===
			//nolint:forbidigo // Intentional sleep: waiting for the check period session
			// to expire. This is a time-based expiry, not a pollable condition — the
			// Tailscale client caches the approval for SessionDuration and only
			// re-triggers the check flow after it elapses.
			time.Sleep(70 * time.Second)

			// === Phase 3: Second SSH — must re-authenticate ===
			sshResult2 := doSSHCheck(t, client, peer)
			secondAuthID := findNewSSHCheckAuthID(t, headscale, firstAuthID)

			require.NotEqual(
				t,
				firstAuthID,
				secondAuthID,
				"second SSH should trigger a new auth flow after checkPeriod expiry",
			)

			_, err = headscale.Execute(
				[]string{
					"headscale", "auth", "approve",
					"--auth-id", secondAuthID,
				},
			)
			require.NoError(t, err)

			select {
			case result := <-sshResult2:
				require.NoError(t, result.err, "second SSH should succeed after re-approval")
				require.Contains(
					t,
					peer.ContainerID(),
					strings.ReplaceAll(result.stdout, "\n", ""),
				)
			case <-time.After(30 * time.Second):
				t.Fatal("second SSH did not complete after re-auth approval")
			}
		}
	}
}

// TestSSHCheckModeAutoApprove verifies that after SSH check approval, a second
// SSH within the checkPeriod is auto-approved without requiring manual approval.
func TestSSHCheckModeAutoApprove(t *testing.T) {
	IntegrationSkip(t)

	// 5 minute checkPeriod — long enough not to expire during test
	scenario := sshScenario(t, sshCheckPolicyWithPeriod(5*time.Minute), 1)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	// === Phase 1: First SSH check — approve, verify success ===
	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			sshResult := doSSHCheck(t, client, peer)
			firstAuthID := findSSHCheckAuthID(t, headscale)

			_, err := headscale.Execute(
				[]string{
					"headscale", "auth", "approve",
					"--auth-id", firstAuthID,
				},
			)
			require.NoError(t, err)

			select {
			case result := <-sshResult:
				require.NoError(t, result.err, "first SSH should succeed after approval")
				require.Contains(
					t,
					peer.ContainerID(),
					strings.ReplaceAll(result.stdout, "\n", ""),
				)
			case <-time.After(30 * time.Second):
				t.Fatal("first SSH did not complete after auth approval")
			}

			// === Phase 2: Immediate retry — should auto-approve ===
			result, _, err := doSSH(t, client, peer)
			require.NoError(t, err, "second SSH should auto-approve without manual auth")
			require.Contains(
				t,
				peer.ContainerID(),
				strings.ReplaceAll(result, "\n", ""),
			)
		}
	}
}

// TestSSHCheckModeNegativeCLI verifies that `headscale auth reject`
// properly denies an SSH check.
func TestSSHCheckModeNegativeCLI(t *testing.T) {
	IntegrationSkip(t)

	scenario := sshScenario(t, sshCheckPolicy(), 1)
	defer scenario.ShutdownAssertNoPanics(t)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	user1Clients, err := scenario.ListTailscaleClients("user1")
	requireNoErrListClients(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	requireNoErrListFQDN(t, err)

	for _, client := range user1Clients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			sshResult := doSSHCheck(t, client, peer)
			authID := findSSHCheckAuthID(t, headscale)

			// Reject via CLI
			_, err := headscale.Execute(
				[]string{
					"headscale", "auth", "reject",
					"--auth-id", authID,
				},
			)
			require.NoError(t, err)

			select {
			case result := <-sshResult:
				require.Error(t, result.err, "SSH should be rejected")
				assert.Empty(t, result.stdout, "no command output expected on rejection")
			case <-time.After(30 * time.Second):
				t.Fatal("SSH did not complete after auth rejection")
			}
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
