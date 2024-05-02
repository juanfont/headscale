package integration

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"sort"
	"sync"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"github.com/puzpuzpuz/xsync/v3"
	"github.com/samber/lo"
	"golang.org/x/sync/errgroup"
	"tailscale.com/envknob"
)

const (
	scenarioHashLength = 6
)

var usePostgresForTest = envknob.Bool("HEADSCALE_INTEGRATION_POSTGRES")

func enabledVersions(vs map[string]bool) []string {
	var ret []string
	for version, enabled := range vs {
		if enabled {
			ret = append(ret, version)
		}
	}

	sort.Sort(sort.Reverse(sort.StringSlice(ret)))

	return ret
}

var (
	errNoHeadscaleAvailable = errors.New("no headscale available")
	errNoUserAvailable      = errors.New("no user available")
	errNoClientFound        = errors.New("client not found")

	// Tailscale started adding TS2021 support in CapabilityVersion>=28 (v1.24.0), but
	// proper support in Headscale was only added for CapabilityVersion>=39 clients (v1.30.0).
	tailscaleVersions2021 = map[string]bool{
		"head":     true,
		"unstable": true,
		"1.60":     true,  // CapVer: 82
		"1.58":     true,  // CapVer: 82
		"1.56":     true,  // CapVer: 82
		"1.54":     true,  // CapVer: 79
		"1.52":     true,  // CapVer: 79
		"1.50":     true,  // CapVer: 74
		"1.48":     true,  // CapVer: 68
		"1.46":     true,  // CapVer: 65
		"1.44":     true,  // CapVer: 63
		"1.42":     true,  // CapVer: 61
		"1.40":     true,  // CapVer: 61
		"1.38":     true,  // Oldest supported version, CapVer: 58
		"1.36":     false, // CapVer: 56
		"1.34":     false, // CapVer: 51
		"1.32":     false, // CapVer: 46
		"1.30":     false,
	}

	tailscaleVersions2019 = map[string]bool{
		"1.28": false,
		"1.26": false,
		"1.24": false, // Tailscale SSH
		"1.22": false,
		"1.20": false,
		"1.18": false,
	}

	// tailscaleVersionsUnavailable = []string{
	// 	// These versions seem to fail when fetching from apt.
	// "1.14.6",
	// "1.12.4",
	// "1.10.2",
	// "1.8.7",
	// }.

	// AllVersions represents a list of Tailscale versions the suite
	// uses to test compatibility with the ControlServer.
	//
	// The list contains two special cases, "head" and "unstable" which
	// points to the current tip of Tailscale's main branch and the latest
	// released unstable version.
	//
	// The rest of the version represents Tailscale versions that can be
	// found in Tailscale's apt repository.
	AllVersions = append(
		enabledVersions(tailscaleVersions2021),
		enabledVersions(tailscaleVersions2019)...,
	)

	// MustTestVersions is the minimum set of versions we should test.
	// At the moment, this is arbitrarily chosen as:
	//
	// - Two unstable (HEAD and unstable)
	// - Two latest versions
	// - Two oldest supported version.
	MustTestVersions = append(
		AllVersions[0:4],
		AllVersions[len(AllVersions)-2:]...,
	)
)

// User represents a User in the ControlServer and a map of TailscaleClient's
// associated with the User.
type User struct {
	Clients map[string]TailscaleClient

	createWaitGroup errgroup.Group
	joinWaitGroup   errgroup.Group
	syncWaitGroup   errgroup.Group
}

// Scenario is a representation of an environment with one ControlServer and
// one or more User's and its associated TailscaleClients.
// A Scenario is intended to simplify setting up a new testcase for testing
// a ControlServer with TailscaleClients.
// TODO(kradalby): make control server configurable, test correctness with Tailscale SaaS.
type Scenario struct {
	// TODO(kradalby): support multiple headcales for later, currently only
	// use one.
	controlServers *xsync.MapOf[string, ControlServer]

	users map[string]*User

	pool    *dockertest.Pool
	network *dockertest.Network

	mu sync.Mutex
}

// NewScenario creates a test Scenario which can be used to bootstraps a ControlServer with
// a set of Users and TailscaleClients.
func NewScenario(maxWait time.Duration) (*Scenario, error) {
	hash, err := util.GenerateRandomStringDNSSafe(scenarioHashLength)
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
		controlServers: xsync.NewMapOf[string, ControlServer](),
		users:          make(map[string]*User),

		pool:    pool,
		network: network,
	}, nil
}

// Shutdown shuts down and cleans up all the containers (ControlServer, TailscaleClient)
// and networks associated with it.
// In addition, it will save the logs of the ControlServer to `/tmp/control` in the
// environment running the tests.
func (s *Scenario) Shutdown() {
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

	for userName, user := range s.users {
		for _, client := range user.Clients {
			log.Printf("removing client %s in user %s", client.Hostname(), userName)
			err := client.Shutdown()
			if err != nil {
				log.Printf("failed to tear down client: %s", err)
			}
		}
	}

	if err := s.pool.RemoveNetwork(s.network); err != nil {
		log.Printf("failed to remove network: %s", err)
	}

	// TODO(kradalby): This seem redundant to the previous call
	// if err := s.network.Close(); err != nil {
	// 	return fmt.Errorf("failed to tear down network: %w", err)
	// }
}

// Users returns the name of all users associated with the Scenario.
func (s *Scenario) Users() []string {
	users := make([]string, 0)
	for user := range s.users {
		users = append(users, user)
	}

	return users
}

/// Headscale related stuff
// Note: These functions assume that there is a _single_ headscale instance for now

// Headscale returns a ControlServer instance based on hsic (HeadscaleInContainer)
// If the Scenario already has an instance, the pointer to the running container
// will be return, otherwise a new instance will be created.
// TODO(kradalby): make port and headscale configurable, multiple instances support?
func (s *Scenario) Headscale(opts ...hsic.Option) (ControlServer, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if headscale, ok := s.controlServers.Load("headscale"); ok {
		return headscale, nil
	}

	headscale, err := hsic.New(s.pool, s.network, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to create headscale container: %w", err)
	}

	err = headscale.WaitForRunning()
	if err != nil {
		return nil, fmt.Errorf("failed reach headscale container: %w", err)
	}

	s.controlServers.Store("headscale", headscale)

	return headscale, nil
}

// CreatePreAuthKey creates a "pre authentorised key" to be created in the
// Headscale instance on behalf of the Scenario.
func (s *Scenario) CreatePreAuthKey(
	user string,
	reusable bool,
	ephemeral bool,
) (*v1.PreAuthKey, error) {
	if headscale, err := s.Headscale(); err == nil {
		key, err := headscale.CreateAuthKey(user, reusable, ephemeral)
		if err != nil {
			return nil, fmt.Errorf("failed to create user: %w", err)
		}

		return key, nil
	}

	return nil, fmt.Errorf("failed to create user: %w", errNoHeadscaleAvailable)
}

// CreateUser creates a User to be created in the
// Headscale instance on behalf of the Scenario.
func (s *Scenario) CreateUser(user string) error {
	if headscale, err := s.Headscale(); err == nil {
		err := headscale.CreateUser(user)
		if err != nil {
			return fmt.Errorf("failed to create user: %w", err)
		}

		s.users[user] = &User{
			Clients: make(map[string]TailscaleClient),
		}

		return nil
	}

	return fmt.Errorf("failed to create user: %w", errNoHeadscaleAvailable)
}

/// Client related stuff

// CreateTailscaleNodesInUser creates and adds a new TailscaleClient to a
// User in the Scenario.
func (s *Scenario) CreateTailscaleNodesInUser(
	userStr string,
	requestedVersion string,
	count int,
	opts ...tsic.Option,
) error {
	if user, ok := s.users[userStr]; ok {
		var versions []string
		for i := 0; i < count; i++ {
			version := requestedVersion
			if requestedVersion == "all" {
				version = MustTestVersions[i%len(MustTestVersions)]
			}
			versions = append(versions, version)

			headscale, err := s.Headscale()
			if err != nil {
				return fmt.Errorf("failed to create tailscale node (version: %s): %w", version, err)
			}

			cert := headscale.GetCert()
			hostname := headscale.GetHostname()

			opts = append(opts,
				tsic.WithHeadscaleTLS(cert),
				tsic.WithHeadscaleName(hostname),
			)

			user.createWaitGroup.Go(func() error {
				tsClient, err := tsic.New(
					s.pool,
					version,
					s.network,
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

		log.Printf("testing versions %v, MustTestVersions %v", lo.Uniq(versions), MustTestVersions)

		return nil
	}

	return fmt.Errorf("failed to add tailscale node: %w", errNoUserAvailable)
}

// RunTailscaleUp will log in all of the TailscaleClients associated with a
// User to the given ControlServer (by URL).
func (s *Scenario) RunTailscaleUp(
	userStr, loginServer, authKey string,
) error {
	if user, ok := s.users[userStr]; ok {
		for _, client := range user.Clients {
			c := client
			user.joinWaitGroup.Go(func() error {
				return c.Login(loginServer, authKey)
			})
		}

		if err := user.joinWaitGroup.Wait(); err != nil {
			return err
		}

		for _, client := range user.Clients {
			err := client.WaitForRunning()
			if err != nil {
				return fmt.Errorf("%s failed to up tailscale node: %w", client.Hostname(), err)
			}
		}

		return nil
	}

	return fmt.Errorf("failed to up tailscale node: %w", errNoUserAvailable)
}

// CountTailscale returns the total number of TailscaleClients in a Scenario.
// This is the sum of Users x TailscaleClients.
func (s *Scenario) CountTailscale() int {
	count := 0

	for _, user := range s.users {
		count += len(user.Clients)
	}

	return count
}

// WaitForTailscaleSync blocks execution until all the TailscaleClient reports
// to have all other TailscaleClients present in their netmap.NetworkMap.
func (s *Scenario) WaitForTailscaleSync() error {
	tsCount := s.CountTailscale()

	err := s.WaitForTailscaleSyncWithPeerCount(tsCount - 1)
	if err != nil {
		for _, user := range s.users {
			for _, client := range user.Clients {
				peers, _ := client.PrettyPeers()
				log.Println(peers)
			}
		}
	}

	return err
}

// WaitForTailscaleSyncWithPeerCount blocks execution until all the TailscaleClient reports
// to have all other TailscaleClients present in their netmap.NetworkMap.
func (s *Scenario) WaitForTailscaleSyncWithPeerCount(peerCount int) error {
	for _, user := range s.users {
		for _, client := range user.Clients {
			c := client
			user.syncWaitGroup.Go(func() error {
				return c.WaitForPeers(peerCount)
			})
		}
		if err := user.syncWaitGroup.Wait(); err != nil {
			return err
		}
	}

	return nil
}

// CreateHeadscaleEnv is a conventient method returning a complete Headcale
// test environment with nodes of all versions, joined to the server with X
// users.
func (s *Scenario) CreateHeadscaleEnv(
	users map[string]int,
	tsOpts []tsic.Option,
	opts ...hsic.Option,
) error {
	if usePostgresForTest {
		opts = append(opts, hsic.WithPostgres())
	}

	headscale, err := s.Headscale(opts...)
	if err != nil {
		return err
	}

	for userName, clientCount := range users {
		err = s.CreateUser(userName)
		if err != nil {
			return err
		}

		err = s.CreateTailscaleNodesInUser(userName, "all", clientCount, tsOpts...)
		if err != nil {
			return err
		}

		key, err := s.CreatePreAuthKey(userName, true, false)
		if err != nil {
			return err
		}

		err = s.RunTailscaleUp(userName, headscale.GetEndpoint(), key.GetKey())
		if err != nil {
			return err
		}
	}

	return nil
}

// GetIPs returns all netip.Addr of TailscaleClients associated with a User
// in a Scenario.
func (s *Scenario) GetIPs(user string) ([]netip.Addr, error) {
	var ips []netip.Addr
	if ns, ok := s.users[user]; ok {
		for _, client := range ns.Clients {
			clientIps, err := client.IPs()
			if err != nil {
				return ips, fmt.Errorf("failed to get ips: %w", err)
			}
			ips = append(ips, clientIps...)
		}

		return ips, nil
	}

	return ips, fmt.Errorf("failed to get ips: %w", errNoUserAvailable)
}

// GetClients returns all TailscaleClients associated with a User in a Scenario.
func (s *Scenario) GetClients(user string) ([]TailscaleClient, error) {
	var clients []TailscaleClient
	if ns, ok := s.users[user]; ok {
		for _, client := range ns.Clients {
			clients = append(clients, client)
		}

		return clients, nil
	}

	return clients, fmt.Errorf("failed to get clients: %w", errNoUserAvailable)
}

// ListTailscaleClients returns a list of TailscaleClients given the Users
// passed as parameters.
func (s *Scenario) ListTailscaleClients(users ...string) ([]TailscaleClient, error) {
	var allClients []TailscaleClient

	if len(users) == 0 {
		users = s.Users()
	}

	for _, user := range users {
		clients, err := s.GetClients(user)
		if err != nil {
			return nil, err
		}

		allClients = append(allClients, clients...)
	}

	return allClients, nil
}

// FindTailscaleClientByIP returns a TailscaleClient associated with an IP address
// if it exists.
func (s *Scenario) FindTailscaleClientByIP(ip netip.Addr) (TailscaleClient, error) {
	clients, err := s.ListTailscaleClients()
	if err != nil {
		return nil, err
	}

	for _, client := range clients {
		ips, _ := client.IPs()
		for _, ip2 := range ips {
			if ip == ip2 {
				return client, nil
			}
		}
	}

	return nil, errNoClientFound
}

// ListTailscaleClientsIPs returns a list of netip.Addr based on Users
// passed as parameters.
func (s *Scenario) ListTailscaleClientsIPs(users ...string) ([]netip.Addr, error) {
	var allIps []netip.Addr

	if len(users) == 0 {
		users = s.Users()
	}

	for _, user := range users {
		ips, err := s.GetIPs(user)
		if err != nil {
			return nil, err
		}

		allIps = append(allIps, ips...)
	}

	return allIps, nil
}

// ListTailscaleClientsFQDNs returns a list of FQDN based on Users
// passed as parameters.
func (s *Scenario) ListTailscaleClientsFQDNs(users ...string) ([]string, error) {
	allFQDNs := make([]string, 0)

	clients, err := s.ListTailscaleClients(users...)
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

// WaitForTailscaleLogout blocks execution until all TailscaleClients have
// logged out of the ControlServer.
func (s *Scenario) WaitForTailscaleLogout() error {
	for _, user := range s.users {
		for _, client := range user.Clients {
			c := client
			user.syncWaitGroup.Go(func() error {
				return c.WaitForNeedsLogin()
			})
		}
		if err := user.syncWaitGroup.Wait(); err != nil {
			return err
		}
	}

	return nil
}
