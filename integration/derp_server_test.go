package integration

import (
	"fmt"
	"log"
	"net/netip"
	"testing"

	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"github.com/samber/lo"
)

type DERPServerScenario struct {
	*Scenario

	tsicNetworks map[string]*dockertest.Network
}

func TestDERPServerScenario(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	baseScenario, err := NewScenario()
	if err != nil {
		t.Errorf("failed to create scenario: %s", err)
	}

	scenario := DERPServerScenario{
		Scenario:     baseScenario,
		tsicNetworks: map[string]*dockertest.Network{},
	}

	spec := map[string]int{
		"user1": len(TailscaleVersions),
	}

	headscaleConfig := hsic.DefaultConfigEnv()
	// headscaleConfig["HEADSCALE_DERP_URLS"] = ""
	// headscaleConfig["HEADSCALE_DERP_SERVER_ENABLED"] = "true"
	// headscaleConfig["HEADSCALE_DERP_SERVER_REGION_ID"] = "999"
	// headscaleConfig["HEADSCALE_DERP_SERVER_REGION_CODE"] = "headscale"
	// headscaleConfig["HEADSCALE_DERP_SERVER_REGION_NAME"] = "Headscale Embedded DERP"
	// headscaleConfig["HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR"] = "0.0.0.0:3478"

	err = scenario.CreateHeadscaleEnv(
		spec,
		hsic.WithHostnameAsServerURL(),
		hsic.WithTestName("derpserver"),
		hsic.WithConfigEnv(headscaleConfig),
		hsic.WithExtraPorts([]string{"3478/udp"}),
		hsic.WithTLS(),
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

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	err = scenario.Shutdown()
	if err != nil {
		t.Errorf("failed to tear down scenario: %s", err)
	}
}

func (s *DERPServerScenario) CreateHeadscaleEnv(
	users map[string]int,
	opts ...hsic.Option,
) error {
	hs, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	err = hs.WaitForReady()
	if err != nil {
		return err
	}

	hash, err := headscale.GenerateRandomStringDNSSafe(scenarioHashLength)
	if err != nil {
		return err
	}

	for userName, clientCount := range users {
		log.Printf("creating user %s with %d clients", userName, clientCount)
		err = s.CreateUser(userName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleIsolatedNodesInUser(hash, userName, "all", clientCount)
		if err != nil {
			return err
		}

		key, err := s.CreatePreAuthKey(userName, true, false)
		if err != nil {
			return err
		}

		err = s.RunTailscaleUp(userName, hs.GetEndpoint(), key.GetKey())
		if err != nil {
			return err
		}
	}

	return nil
}

func (s *DERPServerScenario) CreateTailscaleIsolatedNodesInUser(
	hash string,
	userStr string,
	requestedVersion string,
	count int,
	opts ...tsic.Option,
) error {
	if user, ok := s.users[userStr]; ok {
		for i := 0; i < count; i++ {
			networkName := fmt.Sprintf("tsnet-%s-%s-%d",
				hash,
				userStr,
				i,
			)
			network, err := dockertestutil.GetFirstOrCreateNetwork(
				s.pool,
				networkName,
			)
			if err != nil {
				return fmt.Errorf("failed to create or get %s network: %w", networkName, err)
			}

			log.Printf("created network %s", networkName)

			s.tsicNetworks[networkName] = network

			version := requestedVersion
			if requestedVersion == "all" {
				version = TailscaleVersions[i%len(TailscaleVersions)]
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

	}

	return fmt.Errorf("failed to add tailscale node: %w", errNoUserAvailable)
}

func (s *DERPServerScenario) Shutdown() error {
	for _, network := range s.tsicNetworks {
		err := s.pool.RemoveNetwork(network)
		if err != nil {
			return err
		}
	}

	return s.Scenario.Shutdown()
}
