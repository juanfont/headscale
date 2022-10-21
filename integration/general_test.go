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

	// err = scenario.Shutdown()
	// if err != nil {
	// 	t.Errorf("failed to tear down scenario: %s", err)
	// }
}

func TestPingAllByHostname(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	spec := map[string]int{
		"namespace3": len(TailscaleVersions),
		"namespace4": len(TailscaleVersions),
	}

	err = scenario.CreateHeadscaleEnv(spec)
	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	var allClients []*tsic.TailscaleInContainer

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

	success := 0

	for _, client := range allClients {
		for _, peer := range allClients {
			err := client.Ping(peer.Hostname)
			if err != nil {
				t.Errorf("failed to ping %s from %s: %s", peer.Hostname, client.Hostname, err)
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
