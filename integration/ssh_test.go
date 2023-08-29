package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
)

var retry = func(times int, sleepInterval time.Duration,
	doWork func() (string, string, error),
) (string, string, error) {
	var result string
	var stderr string
	var err error

	for attempts := 0; attempts < times; attempts++ {
		tempResult, tempStderr, err := doWork()

		result += tempResult
		stderr += tempStderr

		if err == nil {
			return result, stderr, nil
		}

		// If we get a permission denied error, we can fail immediately
		// since that is something we wont recover from by retrying.
		if err != nil && strings.Contains(stderr, "Permission denied (tailscale)") {
			return result, stderr, err
		}

		time.Sleep(sleepInterval)
	}

	return result, stderr, err
}

func sshScenario(t *testing.T, policy *policy.ACLPolicy, clientsPerUser int) *Scenario {
	t.Helper()
	scenario, err := NewScenario()
	assertNoErr(t, err)

	spec := map[string]int{
		"user1": clientsPerUser,
		"user2": clientsPerUser,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{
			tsic.WithDockerEntrypoint([]string{
				"/bin/sh",
				"-c",
				"/bin/sleep 3 ; apk add openssh ; update-ca-certificates ; tailscaled --tun=tsdev",
			}),
			tsic.WithDockerWorkdir("/"),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("ssh"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	assertNoErr(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErr(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErr(t, err)

	return scenario
}

func TestSSHOneUserAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario := sshScenario(t,
		&policy.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"user1"},
			},
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			SSHs: []policy.SSH{
				{
					Action:       "accept",
					Sources:      []string{"group:integration-test"},
					Destinations: []string{"group:integration-test"},
					Users:        []string{"ssh-it-user"},
				},
			},
		},
		len(TailscaleVersions)-5,
	)
	defer scenario.Shutdown()

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}
}

func TestSSHMultipleUsersAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario := sshScenario(t,
		&policy.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"user1", "user2"},
			},
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			SSHs: []policy.SSH{
				{
					Action:       "accept",
					Sources:      []string{"group:integration-test"},
					Destinations: []string{"group:integration-test"},
					Users:        []string{"ssh-it-user"},
				},
			},
		},
		len(TailscaleVersions)-5,
	)
	defer scenario.Shutdown()

	nsOneClients, err := scenario.ListTailscaleClients("user1")
	assertNoErrListClients(t, err)

	nsTwoClients, err := scenario.ListTailscaleClients("user2")
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	testInterUserSSH := func(sourceClients []TailscaleClient, targetClients []TailscaleClient) {
		for _, client := range sourceClients {
			for _, peer := range targetClients {
				assertSSHHostname(t, client, peer)
			}
		}
	}

	testInterUserSSH(nsOneClients, nsTwoClients)
	testInterUserSSH(nsTwoClients, nsOneClients)
}

func TestSSHNoSSHConfigured(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario := sshScenario(t,
		&policy.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"user1"},
			},
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			SSHs: []policy.SSH{},
		},
		len(TailscaleVersions)-5,
	)
	defer scenario.Shutdown()

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

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
	t.Parallel()

	scenario := sshScenario(t,
		&policy.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"user1"},
			},
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:80"},
				},
			},
			SSHs: []policy.SSH{
				{
					Action:       "accept",
					Sources:      []string{"group:integration-test"},
					Destinations: []string{"group:integration-test"},
					Users:        []string{"ssh-it-user"},
				},
			},
		},
		len(TailscaleVersions)-5,
	)
	defer scenario.Shutdown()

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHTimeout(t, client, peer)
		}
	}
}

func TestSSUserOnlyIsolation(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario := sshScenario(t,
		&policy.ACLPolicy{
			Groups: map[string][]string{
				"group:ssh1": {"user1"},
				"group:ssh2": {"user2"},
			},
			ACLs: []policy.ACL{
				{
					Action:       "accept",
					Sources:      []string{"*"},
					Destinations: []string{"*:*"},
				},
			},
			SSHs: []policy.SSH{
				{
					Action:       "accept",
					Sources:      []string{"group:ssh1"},
					Destinations: []string{"group:ssh1"},
					Users:        []string{"ssh-it-user"},
				},
				{
					Action:       "accept",
					Sources:      []string{"group:ssh2"},
					Destinations: []string{"group:ssh2"},
					Users:        []string{"ssh-it-user"},
				},
			},
		},
		len(TailscaleVersions)-5,
	)
	defer scenario.Shutdown()

	ssh1Clients, err := scenario.ListTailscaleClients("user1")
	assertNoErrListClients(t, err)

	ssh2Clients, err := scenario.ListTailscaleClients("user2")
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	_, err = scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

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

	peerFQDN, _ := peer.FQDN()

	command := []string{
		"ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
		fmt.Sprintf("%s@%s", "ssh-it-user", peerFQDN),
		"'hostname'",
	}

	return retry(10, 1*time.Second, func() (string, string, error) {
		return client.Execute(command)
	})
}

func assertSSHHostname(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, _, err := doSSH(t, client, peer)
	assertNoErr(t, err)

	assert.Contains(t, peer.ID(), strings.ReplaceAll(result, "\n", ""))
}

func assertSSHPermissionDenied(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, stderr, err := doSSH(t, client, peer)
	assert.Error(t, err)

	assert.Empty(t, result)

	assert.Contains(t, stderr, "Permission denied (tailscale)")
}

func assertSSHTimeout(t *testing.T, client TailscaleClient, peer TailscaleClient) {
	t.Helper()

	result, stderr, err := doSSH(t, client, peer)
	assertNoErr(t, err)

	assert.Empty(t, result)

	assert.Contains(t, stderr, "Connection timed out")
}
