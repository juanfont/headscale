package integration

import (
	"net/netip"
	"testing"
)

func TestPingAllByIP(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace1": len(TailscaleVersions),
		"namespace2": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	var allIps []netip.Addr
	var allClients []TailscaleClient

	for namespace, count := range spec {
		ips, err := scenario.GetIPs(namespace)
		if err != nil {
			t.Errorf("failed to get tailscale ips: %s", err)
		}

		if len(ips) != count*2 {
			t.Errorf(
				"got the wrong amount of tailscale ips, %d != %d",
				len(ips),
				count*2,
			)
		}

		clients, err := scenario.GetClients(namespace)
		if err != nil {
			t.Errorf("failed to get tailscale clients: %s", err)
		}

		allIps = append(allIps, ips...)
		allClients = append(allClients, clients...)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	success := 0

	for _, client := range allClients {
		for _, ip := range allIps {
			err := client.Ping(ip.String())
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", ip, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func TestPingAllByHostname(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		// Omit 1.16.2 (-1) because it does not have the FQDN field
		"namespace3": len(TailscaleVersions) - 1,
		"namespace4": len(TailscaleVersions) - 1,
	}

	err = scenario.CreateHeadscaleEnv(spec)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	var allClients []TailscaleClient
	var allHostnames []string

	for namespace := range spec {
		clients, err := scenario.GetClients(namespace)
		if err != nil {
			t.Errorf("failed to get tailscale clients: %s", err)
		}

		allClients = append(allClients, clients...)
	}

	err = scenario.WaitForTailscaleSync()
	if err != nil {
		t.Errorf("failed wait for tailscale clients to be in sync: %s", err)
	}

	for _, client := range allClients {
		fqdn, err := client.FQDN()
		if err != nil {
			t.Errorf("failed to get fqdn of client %s: %s", client.Hostname(), err)
		}

		allHostnames = append(allHostnames, fqdn)
	}

	success := 0

	for _, client := range allClients {
		for _, hostname := range allHostnames {
			err := client.Ping(hostname)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", hostname, client.Hostname(), err)
			} else {
				success++
			}
		}
	}

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allClients))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}
