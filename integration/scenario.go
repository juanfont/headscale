package integration

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"

	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
)

const scenarioHashLength = 6

var errNoHeadscaleAvailable = errors.New("no headscale available")
var errNoNamespaceAvailable = errors.New("no namespace available")

type Namespace struct {
	Clients map[string]*tsic.TailscaleInContainer

	createWaitGroup sync.WaitGroup
	joinWaitGroup   sync.WaitGroup
}

// TODO(kradalby): make control server configurable, test test correctness with
// Tailscale SaaS.
type Scenario struct {
	// TODO(kradalby): support multiple headcales for later, currently only
	// use one.
	controlServers map[string]ControlServer

	namespaces map[string]*Namespace

	pool    *dockertest.Pool
	network *dockertest.Network
}

func NewScenario() (*Scenario, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(scenarioHashLength)
	if err != nil {
		return nil, err
	}

	pool, err := dockertest.NewPool("")
	if err != nil {
		return nil, fmt.Errorf("could not connect to docker: %w", err)
	}

	networkName := fmt.Sprintf("hs-%s", hash)
	if overrideNetworkName := os.Getenv("HEADSCALE_TEST_NETWORK_NAME"); overrideNetworkName != "" {
		networkName = overrideNetworkName
	}

	network, err := dockertestutil.GetFirstOrCreateNetwork(pool, networkName)
	if err != nil {
		return nil, fmt.Errorf("failed to create or get network: %w", err)
	}

	// We run the test suite in a docker container that calls a couple of endpoints for
	// readiness checks, this ensures that we can run the tests with individual networks
	// and have the client reach the different containers
	err = dockertestutil.AddContainerToNetwork(pool, network, "headscale-test-suite")
	if err != nil {
		return nil, fmt.Errorf("failed to add test suite container to network: %w", err)
	}

	return &Scenario{
		controlServers: make(map[string]ControlServer),
		namespaces:     make(map[string]*Namespace),

		pool:    pool,
		network: network,
	}, nil
}

func (s *Scenario) Shutdown() error {
	for _, control := range s.controlServers {
		err := control.Shutdown()
		if err != nil {
			return fmt.Errorf("failed to tear down control: %w", err)
		}
	}

	for namespaceName, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			log.Printf("removing client %s in namespace %s", client.Hostname, namespaceName)
			err := client.Shutdown()
			if err != nil {
				return fmt.Errorf("failed to tear down client: %w", err)
			}
		}
	}

	if err := s.pool.RemoveNetwork(s.network); err != nil {
		return fmt.Errorf("failed to remove network: %w", err)
	}

	// TODO(kradalby): This seem redundant to the previous call
	// if err := s.network.Close(); err != nil {
	// 	return fmt.Errorf("failed to tear down network: %w", err)
	// }

	return nil
}

/// Headscale related stuff
// Note: These functions assume that there is a _single_ headscale instance for now

// TODO(kradalby): make port and headscale configurable, multiple instances support?
func (s *Scenario) StartHeadscale() error {
	headscale, err := hsic.New(s.pool, 8080, s.network)
	if err != nil {
		return fmt.Errorf("failed to create headscale container: %w", err)
	}

	s.controlServers["headscale"] = headscale

	return nil
}

func (s *Scenario) Headscale() *hsic.HeadscaleInContainer {
	return s.controlServers["headscale"].(*hsic.HeadscaleInContainer)
}

func (s *Scenario) CreatePreAuthKey(namespace string) (*v1.PreAuthKey, error) {
	if headscale, ok := s.controlServers["headscale"]; ok {
		key, err := headscale.CreateAuthKey(namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to create namespace: %w", err)
		}

		return key, nil
	}

	return nil, fmt.Errorf("failed to create namespace: %w", errNoHeadscaleAvailable)
}

func (s *Scenario) CreateNamespace(namespace string) error {
	if headscale, ok := s.controlServers["headscale"]; ok {
		err := headscale.CreateNamespace(namespace)
		if err != nil {
			return fmt.Errorf("failed to create namespace: %w", err)
		}

		s.namespaces[namespace] = &Namespace{
			Clients: make(map[string]*tsic.TailscaleInContainer),
		}

		return nil
	}

	return fmt.Errorf("failed to create namespace: %w", errNoHeadscaleAvailable)
}

/// Client related stuff

func (s *Scenario) CreateTailscaleNodesInNamespace(
	namespace string,
	version string,
	count int,
) error {
	if ns, ok := s.namespaces[namespace]; ok {
		for i := 0; i < count; i++ {
			ns.createWaitGroup.Add(1)

			go func() {
				defer ns.createWaitGroup.Done()

				// TODO(kradalby): error handle this
				ts, err := tsic.New(s.pool, version, s.network)
				if err != nil {
					// return fmt.Errorf("failed to add tailscale node: %w", err)
					fmt.Printf("failed to add tailscale node: %s", err)
				}

				ns.Clients[ts.Hostname] = ts
			}()
		}
		ns.createWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to add tailscale node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) RunTailscaleUp(
	namespace, loginServer, authKey string,
) error {
	if ns, ok := s.namespaces[namespace]; ok {
		for _, client := range ns.Clients {
			ns.joinWaitGroup.Add(1)

			go func() {
				defer ns.joinWaitGroup.Done()

				// TODO(kradalby): error handle this
				_ = client.Up(loginServer, authKey)
			}()
		}
		ns.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) GetIPs(namespace string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ns, ok := s.namespaces[namespace]; ok {
		for _, client := range ns.Clients {
			clientIps, err := client.IPs()
			if err != nil {
				return ips, fmt.Errorf("failed to get ips: %w", err)
			}
			ips = append(ips, clientIps...)
		}

		return ips, nil
	}

	return ips, fmt.Errorf("failed to get ips: %w", errNoNamespaceAvailable)
}
