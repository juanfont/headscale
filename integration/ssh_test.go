package integration

import (
	"fmt"
	"testing"

	"github.com/juanfont/headscale"
)

func TestSSHIntoAll(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := &HeadscaleSpec{
		namespaces: map[string]int{
			// Omit versions before 1.24 because they don't support SSH
			"namespace1": len(TailscaleVersions) - 4,
			"namespace2": len(TailscaleVersions) - 4,
		},
		enableSSH: true,
		acl: &headscale.ACLPolicy{
			Groups: map[string][]string{
				"group:integration-test": {"namespace1", "namespace2"},
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
	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	for namespace := range spec.namespaces {
		// This will essentially fetch and cache all the FQDNs for the given namespace
		nsFQDNs, err := scenario.ListTailscaleClientsFQDNs(namespace)
		if err != nil {
			t.Errorf("failed to get FQDNs: %s", err)
		}

		nsClients, err := scenario.ListTailscaleClients(namespace)
		if err != nil {
			t.Errorf("failed to get clients: %s", err)
		}

		for _, client := range nsClients {
			currentClientFqdn, _ := client.FQDN()
			sshTargets := removeFromSlice(nsFQDNs, currentClientFqdn)

			for _, target := range sshTargets {
				t.Run(
					fmt.Sprintf("%s-%s", currentClientFqdn, target),
					func(t *testing.T) {
						command := []string{
							"ssh", "-o StrictHostKeyChecking=no",
							fmt.Sprintf("%s@%s", "ssh-it-user", target),
							"'hostname'",
						}

						result, err := client.Execute(command)
						if err != nil {
							t.Errorf("failed to execute command over SSH: %s", err)
						}

						if result != target {
							t.Logf("result=%s, target=%s", result, target)
							t.Fail()
						}

						t.Logf("Result for %s: %s\n", target, result)
					},
				)
			}

			// t.Logf("%s wants to SSH into %+v", currentClientFqdn, sshTargets)
		}
	}

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func removeFromSlice(haystack []string, needle string) []string {
	for i, value := range haystack {
		if needle == value {
			return append(haystack[:i], haystack[i+1:]...)
		}
	}

	return haystack
}
