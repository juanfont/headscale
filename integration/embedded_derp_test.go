package integration

import (
	"fmt"
	"log"
	"net/url"
	"testing"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
)

type EmbeddedDERPServerScenario struct {
	*Scenario

	tsicNetworks map[string]*dockertest.Network
}

func TestDERPServerScenario(t *testing.T) {
	IntegrationSkip(t)
	// t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := EmbeddedDERPServerScenario{
		Scenario:     baseScenario,
		tsicNetworks: map[string]*dockertest.Network{},
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
	}

	headscaleConfig := hsic.DefaultConfigEnv()
	headscaleConfig["HEADSCALE_LISTEN_ADDR"] = "0.0.0.0:8443"
	headscaleConfig["HEADSCALE_DERP_URLS"] = ""
	headscaleConfig["HEADSCALE_DERP_SERVER_ENABLED"] = "true"
	headscaleConfig["HEADSCALE_DERP_SERVER_REGION_ID"] = "999"
	headscaleConfig["HEADSCALE_DERP_SERVER_REGION_CODE"] = "headscale"
	headscaleConfig["HEADSCALE_DERP_SERVER_REGION_NAME"] = "Headscale Embedded DERP"
	headscaleConfig["HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR"] = "0.0.0.0:3478"

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithConfigEnv(headscaleConfig),
		hsic.WithPort(8443),
		hsic.WithTestName("derpserver"),
		hsic.WithHostPortBindings(
			map[string][]string{
				"8443/tcp": {"8443"},
				"3478/udp": {"3478"},
			},
		),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
	)

	if err != nil {
		t.Errorf("failed to create headscale environment: %s", err)
	}

	allClients, err := scenario.ListTailscaleClients()
	if err != nil {
		t.Errorf("failed to get clients: %s", err)
	}

	allIps, err := scenario.ListTailscaleClientsIPs()
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

	success := pingDerpAllHelper(t, allClients, allHostnames)

	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
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

	extraHosts := []string{
		"host.docker.internal:host-gateway",
		fmt.Sprintf("%s:host-gateway", hsServer.GetHostname()),
	}

	err = hsServer.WaitForReady()
	if err != nil {
		return err
	}

	hash, err := headscale.GenerateRandomStringDNSSafe(scenarioHashLength)
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
			tsic.WithExtraHosts(extraHosts),
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

			version := requestedVersion
			if requestedVersion == "all" {
				version = TailscaleVersions[clientN%len(TailscaleVersions)]
			}

			headscale, err := s.Headscale()
			if err != nil {
				return fmt.Errorf("failed to create tailscale node: %w", err)
			}

			cert := headscale.GetCert()
			hostname := headscale.GetHostname()

			user.createWaitGroup.Add(1)

			opts = append(opts,
				tsic.WithHeadscaleTLS(cert),
				tsic.WithHeadscaleName(hostname),
			)

			go func() {
				defer user.createWaitGroup.Done()

				// TODO(kradalby): error handle this
				tsClient, err := tsic.New(
					s.pool,
					version,
					network,
					opts...,
				)
				if err != nil {
					// return fmt.Errorf("failed to add tailscale node: %w", err)
					log.Printf("failed to create tailscale node: %s", err)
				}

				err = tsClient.WaitForReady()
				if err != nil {
					// return fmt.Errorf("failed to add tailscale node: %w", err)
					log.Printf("failed to wait for tailscaled: %s", err)
				}

				user.Clients[tsClient.Hostname()] = tsClient
			}()
		}
		user.createWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to add tailscale node: %w", errNoUserAvailable)
}

func (s *EmbeddedDERPServerScenario) Shutdown() error {
	for _, network := range s.tsicNetworks {
		err := s.pool.RemoveNetwork(network)
		if err != nil {
			return err
		}
	}

	return s.Scenario.Shutdown()
}
