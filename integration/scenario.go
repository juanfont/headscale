package integration

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"github.com/puzpuzpuz/xsync/v2"
)

const (
	scenarioHashLength = 6
	maxWait            = 60 * time.Second
)

var (
	errNoHeadscaleAvailable = errors.New("no headscale available")
	errNoNamespaceAvailable = errors.New("no namespace available")

	// Tailscale started adding TS2021 support in CapabilityVersion>=28 (v1.24.0), but
	// proper support in Headscale was only added for CapabilityVersion>=39 clients (v1.30.0).
	tailscaleVersions2021 = []string{
		"head",
		"unstable",
		"1.34.0",
		"1.32.3",
		"1.30.2",
	}

	tailscaleVersions2019 = []string{
		"1.28.0",
		"1.26.2",
		"1.24.2",
		"1.22.2",
		"1.20.4",
	}

	// tailscaleVersionsUnavailable = []string{
	// 	// These versions seem to fail when fetching from apt.
	//  "1.18.2",
	// 	"1.16.2",
	// 	"1.14.6",
	// 	"1.12.4",
	// 	"1.10.2",
	// 	"1.8.7",
	// }.

	TailscaleVersions = append(
		tailscaleVersions2021,
		tailscaleVersions2019...,
	)
)

type Namespace struct {
	Clients map[string]TailscaleClient

	createWaitGroup sync.WaitGroup
	joinWaitGroup   sync.WaitGroup
	syncWaitGroup   sync.WaitGroup
}

// TODO(kradalby): make control server configurable, test correctness with Tailscale SaaS.
type Scenario struct {
	// TODO(kradalby): support multiple headcales for later, currently only
	// use one.
	controlServers *xsync.MapOf[string, ControlServer]

	namespaces map[string]*Namespace

	pool    *dockertest.Pool
	network *dockertest.Network

	headscaleLock sync.Mutex
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

	pool.MaxWait = maxWait

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
		controlServers: xsync.NewMapOf[ControlServer](),
		namespaces:     make(map[string]*Namespace),

		pool:    pool,
		network: network,
	}, nil
}

func (s *Scenario) Shutdown() error {
	s.controlServers.Range(func(_ string, control ControlServer) bool {
		err := control.Shutdown()
		if err != nil {
			log.Printf(
				"Failed to shut down control: %s",
				fmt.Errorf("failed to tear down control: %w", err),
			)
		}

		return true
	})

	for namespaceName, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			log.Printf("removing client %s in namespace %s", client.Hostname(), namespaceName)
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

func (s *Scenario) Namespaces() []string {
	namespaces := make([]string, 0)
	for namespace := range s.namespaces {
		namespaces = append(namespaces, namespace)
	}

	return namespaces
}

/// Headscale related stuff
// Note: These functions assume that there is a _single_ headscale instance for now

// TODO(kradalby): make port and headscale configurable, multiple instances support?
func (s *Scenario) Headscale(opts ...hsic.Option) (ControlServer, error) {
	s.headscaleLock.Lock()
	defer s.headscaleLock.Unlock()

	if headscale, ok := s.controlServers.Load("headscale"); ok {
		return headscale, nil
	}

	headscale, err := hsic.New(s.pool, s.network, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create headscale container: %w", err)
	}

	err = headscale.WaitForReady()
	if err != nil {
		return nil, fmt.Errorf("failed reach headscale container: %w", err)
	}

	s.controlServers.Store("headscale", headscale)

	return headscale, nil
}

func (s *Scenario) CreatePreAuthKey(namespace string, reusable bool, ephemeral bool) (*v1.PreAuthKey, error) {
	if headscale, err := s.Headscale(); err == nil {
		key, err := headscale.CreateAuthKey(namespace, reusable, ephemeral)
		if err != nil {
			return nil, fmt.Errorf("failed to create namespace: %w", err)
		}

		return key, nil
	}

	return nil, fmt.Errorf("failed to create namespace: %w", errNoHeadscaleAvailable)
}

func (s *Scenario) CreateNamespace(namespace string) error {
	if headscale, err := s.Headscale(); err == nil {
		err := headscale.CreateNamespace(namespace)
		if err != nil {
			return fmt.Errorf("failed to create namespace: %w", err)
		}

		s.namespaces[namespace] = &Namespace{
			Clients: make(map[string]TailscaleClient),
		}

		return nil
	}

	return fmt.Errorf("failed to create namespace: %w", errNoHeadscaleAvailable)
}

/// Client related stuff

func (s *Scenario) CreateTailscaleNodesInNamespace(
	namespaceStr string,
	requestedVersion string,
	count int,
	opts ...tsic.Option,
) error {
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for i := 0; i < count; i++ {
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

			namespace.createWaitGroup.Add(1)

			opts = append(opts,
				tsic.WithHeadscaleTLS(cert),
				tsic.WithHeadscaleName(hostname),
			)

			go func() {
				defer namespace.createWaitGroup.Done()

				// TODO(kradalby): error handle this
				tsClient, err := tsic.New(
					s.pool,
					version,
					s.network,
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

				namespace.Clients[tsClient.Hostname()] = tsClient
			}()
		}
		namespace.createWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to add tailscale node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) RunTailscaleUp(
	namespaceStr, loginServer, authKey string,
) error {
	if namespace, ok := s.namespaces[namespaceStr]; ok {
		for _, client := range namespace.Clients {
			namespace.joinWaitGroup.Add(1)

			go func(c TailscaleClient) {
				defer namespace.joinWaitGroup.Done()

				// TODO(kradalby): error handle this
				_ = c.Up(loginServer, authKey)
			}(client)

			err := client.WaitForReady()
			if err != nil {
				log.Printf("error waiting for client %s to be ready: %s", client.Hostname(), err)
			}
		}

		namespace.joinWaitGroup.Wait()

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoNamespaceAvailable)
}

func (s *Scenario) CountTailscale() int {
	count := 0

	for _, namespace := range s.namespaces {
		count += len(namespace.Clients)
	}

	return count
}

func (s *Scenario) WaitForTailscaleSync() error {
	tsCount := s.CountTailscale()

	for _, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			namespace.syncWaitGroup.Add(1)

			go func(c TailscaleClient) {
				defer namespace.syncWaitGroup.Done()

				// TODO(kradalby): error handle this
				_ = c.WaitForPeers(tsCount)
			}(client)
		}
		namespace.syncWaitGroup.Wait()
	}

	return nil
}

// CreateHeadscaleEnv is a conventient method returning a set up Headcale
// test environment with nodes of all versions, joined to the server with X
// namespaces.
func (s *Scenario) CreateHeadscaleEnv(
	namespaces map[string]int,
	tsOpts []tsic.Option,
	opts ...hsic.Option,
) error {
	headscale, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	for namespaceName, clientCount := range namespaces {
		err = s.CreateNamespace(namespaceName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleNodesInNamespace(namespaceName, "all", clientCount, tsOpts...)
		if err != nil {
			return err
		}

		key, err := s.CreatePreAuthKey(namespaceName, true, false)
		if err != nil {
			return err
		}

		err = s.RunTailscaleUp(namespaceName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			return err
		}
	}

	return nil
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

func (s *Scenario) GetClients(namespace string) ([]TailscaleClient, error) {
	var clients []TailscaleClient
	if ns, ok := s.namespaces[namespace]; ok {
		for _, client := range ns.Clients {
			clients = append(clients, client)
		}

		return clients, nil
	}

	return clients, fmt.Errorf("failed to get clients: %w", errNoNamespaceAvailable)
}

func (s *Scenario) ListTailscaleClients(namespaces ...string) ([]TailscaleClient, error) {
	var allClients []TailscaleClient

	if len(namespaces) == 0 {
		namespaces = s.Namespaces()
	}

	for _, namespace := range namespaces {
		clients, err := s.GetClients(namespace)
		if err != nil {
			return nil, err
		}

		allClients = append(allClients, clients...)
	}

	return allClients, nil
}

func (s *Scenario) ListTailscaleClientsIPs(namespaces ...string) ([]netip.Addr, error) {
	var allIps []netip.Addr

	if len(namespaces) == 0 {
		namespaces = s.Namespaces()
	}

	for _, namespace := range namespaces {
		ips, err := s.GetIPs(namespace)
		if err != nil {
			return nil, err
		}

		allIps = append(allIps, ips...)
	}

	return allIps, nil
}

func (s *Scenario) ListTailscaleClientsFQDNs(namespaces ...string) ([]string, error) {
	allFQDNs := make([]string, 0)

	clients, err := s.ListTailscaleClients(namespaces...)
	if err != nil {
		return nil, err
	}

	for _, client := range clients {
		fqdn, err := client.FQDN()
		if err != nil {
			return nil, err
		}

		allFQDNs = append(allFQDNs, fqdn)
	}

	return allFQDNs, nil
}

func (s *Scenario) WaitForTailscaleLogout() {
	for _, namespace := range s.namespaces {
		for _, client := range namespace.Clients {
			namespace.syncWaitGroup.Add(1)

			go func(c TailscaleClient) {
				defer namespace.syncWaitGroup.Done()

				// TODO(kradalby): error handle this
				_ = c.WaitForLogout()
			}(client)
		}
		namespace.syncWaitGroup.Wait()
	}
}
