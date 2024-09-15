package integration

import (
	"fmt"
	"log"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
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

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := EmbeddedDERPServerScenario{
		Scenario:     baseScenario,
		tsicNetworks: map[string]*dockertest.Network{},
	}
	defer scenario.Shutdown()

	spec := map[string]int{
		"user1": len(MustTestVersions),
	}

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("derpserver"),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
		hsic.WithHostnameAsServerURL(),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DERP_AUTO_UPDATE_ENABLED": "true",
			"HEADSCALE_DERP_UPDATE_FREQUENCY":    "10s",
		}),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	allHostnames, err := scenario.ListTailscaleClientsFQDNs()
	assertNoErrListFQDN(t, err)

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, health := range status.Health {
			if strings.Contains(health, "could not connect to any relay server") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
			if strings.Contains(health, "could not connect to the 'Headscale Embedded DERP' relay server.") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
		}
	}

	success := pingDerpAllHelper(t, allClients, allHostnames)

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, health := range status.Health {
			if strings.Contains(health, "could not connect to any relay server") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
			if strings.Contains(health, "could not connect to the 'Headscale Embedded DERP' relay server.") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
		}
	}

	t.Logf("Run 1: %d successful pings out of %d", success, len(allClients)*len(allHostnames))

	// Let the DERP updater run a couple of times to ensure it does not
	// break the DERPMap.
	time.Sleep(30 * time.Second)

	success = pingDerpAllHelper(t, allClients, allHostnames)

	for _, client := range allClients {
		status, err := client.Status()
		assertNoErr(t, err)

		for _, health := range status.Health {
			if strings.Contains(health, "could not connect to any relay server") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
			if strings.Contains(health, "could not connect to the 'Headscale Embedded DERP' relay server.") {
				t.Errorf("expected to be connected to derp, found: %s", health)
			}
		}
	}

	t.Logf("Run2: %d successful pings out of %d", success, len(allClients)*len(allHostnames))
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
