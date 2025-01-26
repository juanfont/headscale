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

type ClientsSpec struct {
	Plain         int
	WebsocketDERP int
}

type EmbeddedDERPServerScenario struct {
	*Scenario

	tsicNetworks map[string]*dockertest.Network
}

func TestDERPServerScenario(t *testing.T) {
	spec := map[string]ClientsSpec{
		"user1": {
			Plain:         len(MustTestVersions),
			WebsocketDERP: 0,
		},
	}

	derpServerScenario(t, spec, func(scenario *EmbeddedDERPServerScenario) {
		allClients, err := scenario.ListTailscaleClients()
		assertNoErrListClients(t, err)
		t.Logf("checking %d clients for websocket connections", len(allClients))

		for _, client := range allClients {
			if didClientUseWebsocketForDERP(t, client) {
				t.Logf(
					"client %q used websocket a connection, but was not expected to",
					client.Hostname(),
				)
				t.Fail()
			}
		}
	})
}

func TestDERPServerWebsocketScenario(t *testing.T) {
	spec := map[string]ClientsSpec{
		"user1": {
			Plain:         0,
			WebsocketDERP: 2,
		},
	}

	derpServerScenario(t, spec, func(scenario *EmbeddedDERPServerScenario) {
		allClients, err := scenario.ListTailscaleClients()
		assertNoErrListClients(t, err)
		t.Logf("checking %d clients for websocket connections", len(allClients))

		for _, client := range allClients {
			if !didClientUseWebsocketForDERP(t, client) {
				t.Logf(
					"client %q does not seem to have used a websocket connection, even though it was expected to do so",
					client.Hostname(),
				)
				t.Fail()
			}
		}
	})
}

// This function implements the common parts of a DERP scenario,
// we *want* it to show up in stacktraces,
// so marking it as a test helper would be counterproductive.
//
//nolint:thelper
func derpServerScenario(
	t *testing.T,
	spec map[string]ClientsSpec,
	furtherAssertions ...func(*EmbeddedDERPServerScenario),
) {
	IntegrationSkip(t)
	// t.Parallel()

	baseScenario, err := NewScenario(dockertestMaxWait())
	assertNoErr(t, err)

	scenario := EmbeddedDERPServerScenario{
		Scenario:     baseScenario,
		tsicNetworks: map[string]*dockertest.Network{},
	}
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithTestName("derpserver"),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithPort(443),
		hsic.WithTLS(),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DERP_AUTO_UPDATE_ENABLED": "true",
			"HEADSCALE_DERP_UPDATE_FREQUENCY":    "10s",
			"HEADSCALE_LISTEN_ADDR":              "0.0.0.0:443",
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
	if len(allHostnames)*len(allClients) > success {
		t.FailNow()

		return
	}

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
	if len(allHostnames)*len(allClients) > success {
		t.Fail()
	}

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

	for _, check := range furtherAssertions {
		check(&scenario)
	}
}

func (s *EmbeddedDERPServerScenario) CreateHeadscaleEnv(
	users map[string]ClientsSpec,
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
	log.Printf("headscale server ip address: %s", hsServer.GetIP())

	hash, err := util.GenerateRandomStringDNSSafe(scenarioHashLength)
	if err != nil {
		return err
	}

	for userName, clientCount := range users {
		err = s.CreateUser(userName)
		if err != nil {
			return err
		}

		if clientCount.Plain > 0 {
			// Containers that use default DERP config
			err = s.CreateTailscaleIsolatedNodesInUser(
				hash,
				userName,
				"all",
				clientCount.Plain,
			)
			if err != nil {
				return err
			}
		}

		if clientCount.WebsocketDERP > 0 {
			// Containers that use DERP-over-WebSocket
			// Note that these clients *must* be built
			// from source, which is currently
			// only done for HEAD.
			err = s.CreateTailscaleIsolatedNodesInUser(
				hash,
				userName,
				tsic.VersionHead,
				clientCount.WebsocketDERP,
				tsic.WithWebsocketDERP(true),
			)
			if err != nil {
				return err
			}
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
				tsic.WithCACert(cert),
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
