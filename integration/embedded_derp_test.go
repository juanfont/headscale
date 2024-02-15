package integration

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"tailscale.com/ipn/ipnstate"
)

type EmbeddedDERPServerScenario struct {
	*Scenario

	tsicNetworks map[string]*dockertest.Network
}

func TestDERPServerScenario(t *testing.T) {
	IntegrationSkip(t)
	// t.Parallel()

	baseScenario, err := NewScenario()
	assertNoErr(t, err)

	scenario := EmbeddedDERPServerScenario{
		Scenario:     baseScenario,
		tsicNetworks: map[string]*dockertest.Network{},
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 10,
		// "user1": len(MustTestVersions),
	}

	headscaleConfig := map[string]string{
		"HEADSCALE_DERP_URLS":                    "",
		"HEADSCALE_DERP_SERVER_ENABLED":          "true",
		"HEADSCALE_DERP_SERVER_REGION_ID":        "999",
		"HEADSCALE_DERP_SERVER_REGION_CODE":      "headscale",
		"HEADSCALE_DERP_SERVER_REGION_NAME":      "Headscale Embedded DERP",
		"HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR": "0.0.0.0:3478",
		"HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH": "/tmp/derp.key",

		// Envknob for enabling DERP debug logs
		"DERP_DEBUG_LOGS":        "true",
		"DERP_PROBER_DEBUG_LOGS": "true",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithConfigEnv(headscaleConfig),
		hsic.WithTestName("derpserver"),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	assertClientsState(t, allClients)

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	success := pingDerpAllHelper(t, allClients, allHostnames)

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestDERPValidateEmbedded(t *testing.T) {
	IntegrationSkip(t)

	scenario, err := NewScenario()
	assertNoErr(t, err)
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": 1,
	}

	headscaleConfig := map[string]string{
		"HEADSCALE_DERP_URLS":                    "",
		"HEADSCALE_DERP_SERVER_ENABLED":          "true",
		"HEADSCALE_DERP_SERVER_REGION_ID":        "999",
		"HEADSCALE_DERP_SERVER_REGION_CODE":      "headscale",
		"HEADSCALE_DERP_SERVER_REGION_NAME":      "Headscale Embedded DERP",
		"HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR": "0.0.0.0:3478",
		"HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH": "/tmp/derp.key",

		// Envknob for enabling DERP debug logs
		"DERP_DEBUG_LOGS":        "true",
		"DERP_PROBER_DEBUG_LOGS": "true",
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		[]tsic.Option{},
		hsic.WithConfigEnv(headscaleConfig),
		hsic.WithTestName("derpvalidate"),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
		hsic.WithPort(80),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	assertClientsState(t, allClients)

	if len(allClients) != 1 {
		t.Fatalf("expected 1 client, got: %d", len(allClients))
	}

	client := allClients[0]

	var derpReport ipnstate.DebugDERPRegionReport
	stdout, stderr, err := client.Execute([]string{"tailscale", "debug", "derp", "999"})
	if err != nil {
		t.Fatalf("executing debug derp report, stderr: %s, err: %s", stderr, err)
	}

	t.Logf("DERP report: \n%s", stdout)

	err = json.Unmarshal([]byte(stdout), &derpReport)
	if err != nil {
		t.Fatalf("unmarshalling debug derp report, content: %s, err: %s", stdout, err)
	}

	for _, warn := range derpReport.Warnings {
		if strings.Contains(warn, "captive portal check") {
			t.Errorf("derp report contains warning about portal check, generate_204 endpoint not working")
		}
	}
}

func (s *EmbeddedDERPServerScenario) CreateHeadscaleEnv(
	users map[string]int,
	opts ...hsic.Option,
) error {
	hsServer, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	headscaleEndpoint := hsServer.GetEndpoint()
	headscaleURL, err := url.Parse(headscaleEndpoint)
	if err != nil {
		return err
	}

	headscaleURL.Host = fmt.Sprintf("%s:%s", hsServer.GetHostname(), headscaleURL.Port())

	err = hsServer.WaitForRunning()
	if err != nil {
		return err
	}

	hash, err := util.GenerateRandomStringDNSSafe(scenarioHashLength)
	if err != nil {
		return err
	}

	for userName, clientCount := range users {
		err = s.CreateUser(userName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleIsolatedNodesInUser(
			hash,
			userName,
			"all",
			clientCount,
		)
		if err != nil {
			return err
		}

		key, err := s.CreatePreAuthKey(userName, true, false)
		if err != nil {
			return err
		}

		err = s.RunTailscaleUp(userName, headscaleURL.String(), key.GetKey())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *EmbeddedDERPServerScenario) CreateTailscaleIsolatedNodesInUser(
	hash string,
	userStr string,
	requestedVersion string,
	count int,
	opts ...tsic.Option,
) error {
	hsServer, err := s.Headscale()
	if err != nil {
		return err
	}

	if user, ok := s.users[userStr]; ok {
		for clientN := 0; clientN < count; clientN++ {
			networkName := fmt.Sprintf("tsnet-%s-%s-%d",
				hash,
				userStr,
				clientN,
			)
			network, err := dockertestutil.GetFirstOrCreateNetwork(
				s.pool,
				networkName,
			)
			if err != nil {
				return fmt.Errorf("failed to create or get %s network: %w", networkName, err)
			}

			s.tsicNetworks[networkName] = network

			err = hsServer.ConnectToNetwork(network)
			if err != nil {
				return fmt.Errorf("failed to connect headscale to %s network: %w", networkName, err)
			}

			version := requestedVersion
			if requestedVersion == "all" {
				version = MustTestVersions[clientN%len(MustTestVersions)]
			}

			cert := hsServer.GetCert()

			opts = append(opts,
				tsic.WithHeadscaleTLS(cert),
			)

			user.createWaitGroup.Go(func() error {
				tsClient, err := tsic.New(
					s.pool,
					version,
					network,
					opts...,
				)
				if err != nil {
					return fmt.Errorf(
						"failed to create tailscale (%s) node: %w",
						tsClient.Hostname(),
						err,
					)
				}

				err = tsClient.WaitForNeedsLogin()
				if err != nil {
					return fmt.Errorf(
						"failed to wait for tailscaled (%s) to need login: %w",
						tsClient.Hostname(),
						err,
					)
				}

				s.mu.Lock()
				user.Clients[tsClient.Hostname()] = tsClient
				s.mu.Unlock()

				return nil
			})
		}

		if err := user.createWaitGroup.Wait(); err != nil {
			return err
		}

		return nil
	}

	return fmt.Errorf("failed to add tailscale nodes: %w", errNoUserAvailable)
}

func (s *EmbeddedDERPServerScenario) Shutdown() {
	for _, network := range s.tsicNetworks {
		err := s.pool.RemoveNetwork(network)
		if err != nil {
			log.Printf("failed to remove DERP network %s", network.Network.Name)
		}
	}

	s.Scenario.Shutdown()
}
