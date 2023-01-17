package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale"
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

func TestSSHOneUserAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions) - 5,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"user1"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []headscale.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHHostname(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHMultipleUsersAllToAll(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions) - 5,
		"user2": len(TailscaleVersions) - 5,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"user1", "user2"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []headscale.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	nsOneClients, err := scenario.ListTailscaleClients("user1")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	nsTwoClients, err := scenario.ListTailscaleClients("user2")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	testInterUserSSH := func(sourceClients []TailscaleClient, targetClients []TailscaleClient) {
		for _, client := range sourceClients {
			for _, peer := range targetClients {
				assertSSHHostname(t, client, peer)
			}
		}
	}

	testInterUserSSH(nsOneClients, nsTwoClients)
	testInterUserSSH(nsTwoClients, nsOneClients)

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHNoSSHConfigured(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions) - 5,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"user1"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []headscale.SSH{},
			},
		),
		hsic.WithTestName("sshnoneconfigured"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHPermissionDenied(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSHIsBlockedInACL(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions) - 5,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:integration-test": {"user1"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:80"},
					},
				},
				SSHs: []headscale.SSH{
					{
						Action:       "accept",
						Sources:      []string{"group:integration-test"},
						Destinations: []string{"group:integration-test"},
						Users:        []string{"ssh-it-user"},
					},
				},
			},
		),
		hsic.WithTestName("sshisblockedinacl"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			assertSSHTimeout(t, client, peer)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestSSUserOnlyIsolation(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"useracl1": len(TailscaleVersions) - 5,
		"useracl2": len(TailscaleVersions) - 5,
	}

	err = scenario.CreateHeadscaleEnv(spec,
		[]tsic.Option{tsic.WithSSH()},
		hsic.WithACLPolicy(
			&headscale.ACLPolicy{
				Groups: map[string][]string{
					"group:ssh1": {"useracl1"},
					"group:ssh2": {"useracl2"},
				},
				ACLs: []headscale.ACL{
					{
						Action:       "accept",
						Sources:      []string{"*"},
						Destinations: []string{"*:*"},
					},
				},
				SSHs: []headscale.SSH{
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
		),
		hsic.WithTestName("sshtwouseraclblock"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_EXPERIMENTAL_FEATURE_SSH": "1",
		}),
	)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	ssh1Clients, err := scenario.ListTailscaleClients("useracl1")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	ssh2Clients, err := scenario.ListTailscaleClients("useracl2")
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	_, err = scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	// TODO(kradalby,evenh): ACLs do currently not cover reject
	// cases properly, and currently will accept all incomming connections
	// as long as a rule is present.
	//
	// for _, client := range ssh1Clients {
	// 	for _, peer := range ssh2Clients {
	// 		if client.Hostname() == peer.Hostname() {
	// 			continue
	// 		}
	//
	// 		assertSSHPermissionDenied(t, client, peer)
	// 	}
	// }
	//
	// for _, client := range ssh2Clients {
	// 	for _, peer := range ssh1Clients {
	// 		if client.Hostname() == peer.Hostname() {
	// 			continue
	// 		}
	//
	// 		assertSSHPermissionDenied(t, client, peer)
	// 	}
	// }

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

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
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
	assert.NoError(t, err)

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
	assert.NoError(t, err)

	assert.Empty(t, result)

	assert.Contains(t, stderr, "Connection timed out")
}
