package integration

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dsic"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"tailscale.com/tailcfg"
)

func TestDERPVerifyEndpoint(t *testing.T) {
	IntegrationSkip(t)

	// Generate random hostname for the headscale instance
	hash, err := util.GenerateRandomStringDNSSafe(6)
	assertNoErr(t, err)
	testName := "derpverify"
	hostname := fmt.Sprintf("hs-%s-%s", testName, hash)

	headscalePort := 8080

	// Create cert for headscale
	certHeadscale, keyHeadscale, err := integrationutil.CreateCertificate(hostname)
	assertNoErr(t, err)

	scenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 10,
	}

	derper, err := scenario.CreateDERPServer("head",
		dsic.WithCACert(certHeadscale),
		dsic.WithVerifyClientURL(fmt.Sprintf("https://%s/verify", net.JoinHostPort(hostname, strconv.Itoa(headscalePort)))),
	)
	assertNoErr(t, err)

	derpMap := tailcfg.DERPMap{
		Regions: map[int]*tailcfg.DERPRegion{
			900: {
				RegionID:   900,
				RegionCode: "test-derpverify",
				RegionName: "TestDerpVerify",
				Nodes: []*tailcfg.DERPNode{
					{
						Name:     "TestDerpVerify",
						RegionID: 900,
						HostName: derper.GetHostname(),
						STUNPort: derper.GetSTUNPort(),
						STUNOnly: false,
						DERPPort: derper.GetDERPPort(),
					},
				},
			},
		},
	}

	headscale, err := scenario.Headscale(
		hsic.WithHostname(hostname),
		hsic.WithPort(headscalePort),
		hsic.WithCustomTLS(certHeadscale, keyHeadscale),
		hsic.WithHostnameAsServerURL(),
		hsic.WithDERPConfig(derpMap),
	)
	assertNoErrHeadscaleEnv(t, err)

	for userName, clientCount := range spec {
		err = scenario.CreateUser(userName)
		if err != nil {
			t.Fatalf("failed to create user %s: %s", userName, err)
		}

		err = scenario.CreateTailscaleNodesInUser(userName, "all", clientCount, tsic.WithCACert(derper.GetCert()))
		if err != nil {
			t.Fatalf("failed to create tailscale nodes in user %s: %s", userName, err)
		}

		key, err := scenario.CreatePreAuthKey(userName, true, true)
		if err != nil {
			t.Fatalf("failed to create pre-auth key for user %s: %s", userName, err)
		}

		err = scenario.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			t.Fatalf("failed to run tailscale up for user %s: %s", userName, err)
		}
	}

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	for _, client := range allClients {
		report, err := client.DebugDERPRegion("test-derpverify")
		assertNoErr(t, err)
		successful := false
		for _, line := range report.Info {
			if strings.Contains(line, "Successfully established a DERP connection with node") {
				successful = true

				break
			}
		}
		if !successful {
			stJSON, err := json.Marshal(report)
			assertNoErr(t, err)
			t.Errorf("Client %s could not establish a DERP connection: %s", client.Hostname(), string(stJSON))
		}
	}
}
