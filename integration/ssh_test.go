package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale"
)

func TestSSHOneNamespaceAllToAll(t *testing.T) {
	IntegrationSkip(t)

	retry := func(times int, sleepInterval time.Duration, doWork func() (string, error)) (string, error) {
		var err error
		for attempts := 0; attempts < times; attempts++ {
			var result string
			result, err = doWork()
			if err == nil {
				return result, nil
			}
			time.Sleep(sleepInterval)
		}

		return "", err
	}

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := &HeadscaleSpec{
		namespaces: map[string]int{
			"namespace1": len(TailscaleVersions) - 5,
		},
		enableSSH: true,
		acl: &headscale.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"namespace1"},
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
	}

	err = scenario.CreateHeadscaleEnv(spec)
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

	success := 0

	for _, client := range allClients {
		for _, peer := range allClients {
			if client.Hostname() == peer.Hostname() {
				continue
			}

			clientFQDN, _ := client.FQDN()
			peerFQDN, _ := peer.FQDN()

			t.Run(
				fmt.Sprintf("%s-%s", clientFQDN, peerFQDN),
				func(t *testing.T) {
					command := []string{
						"ssh", "-o StrictHostKeyChecking=no", "-o ConnectTimeout=1",
						fmt.Sprintf("%s@%s", "ssh-it-user", peer.Hostname()),
						"'hostname'",
					}

					result, err := retry(10, 1*time.Second, func() (string, error) {
						return client.Execute(command)
					})
					if err != nil {
						t.Errorf("failed to execute command over SSH: %s", err)
					}

					if strings.Contains(peer.ID(), result) {
						t.Logf(
							"failed to get correct container ID from %s, expected: %s, got: %s",
							peer.Hostname(),
							peer.ID(),
							result,
						)
						t.Fail()
					} else {
						success++
					}
				},
			)
		}
	}

	t.Logf(
		"%d successful pings out of %d",
		success,
		(len(allClients)*len(allClients))-len(allClients),
	)

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
