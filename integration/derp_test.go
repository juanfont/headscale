package integration

import (
	"testing"

	"github.com/juanfont/headscale/integration/hsic"
)

func TestDERPPingAllByHostname(t *testing.T) {
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

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithPort(8443),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_CONFIG_NAMESERVERS":       "127.0.0.11 1.1.1.1",
			"HEADSCALE_DERP_URLS":                    " ",
			"HEADSCALE_DERP_SERVER_ENABLED":          "true",
			"HEADSCALE_DERP_SERVER_REGION_ID":        "999",
			"HEADSCALE_DERP_SERVER_REGION_CODE":      "headscale",
			"HEADSCALE_DERP_SERVER_REGION_NAME":      "Headscale Embedded DERP",
			"HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR": "0.0.0.0:3478",
		}),
		hsic.WithTLS(),
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

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	if err != nil {
		t.Errorf("failed to get FQDNs: %s", err)
	}

	success := 0

	for _, client := range allClients {
		for _, hostname := range allHostnames {
			err := client.PingViaDERP(hostname)
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
