//go:build integration_oidc

package headscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oauth2-proxy/mockoidc"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"
)

const (
	oidcHeadscaleHostname = "headscale"
	oidcNamespaceName     = "oidcnamespace"
	totalOidcContainers   = 3
)

type IntegrationOIDCTestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	oidc      *mockoidc.MockOIDC
	pool      dockertest.Pool
	network   dockertest.Network
	headscale dockertest.Resource
	saveLogs  bool

	tailscales    map[string]dockertest.Resource
	joinWaitGroup sync.WaitGroup
}

func TestOIDCIntegrationTestSuite(t *testing.T) {
	saveLogs, err := GetEnvBool("HEADSCALE_INTEGRATION_SAVE_LOG")
	if err != nil {
		saveLogs = false
	}

	s := new(IntegrationOIDCTestSuite)

	s.tailscales = make(map[string]dockertest.Resource)
	s.saveLogs = saveLogs

	suite.Run(t, s)

	// HandleStats, which allows us to check if we passed and save logs
	// is called after TearDown, so we cannot tear down containers before
	// we have potentially saved the logs.
	if s.saveLogs {
		for _, tailscale := range s.tailscales {
			if err := s.pool.Purge(&tailscale); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
		}

		if !s.stats.Passed() {
			err := s.saveLog(&s.headscale, "test_output")
			if err != nil {
				log.Printf("Could not save log: %s\n", err)
			}
		}
		if err := s.pool.Purge(&s.headscale); err != nil {
			t.Logf("Could not purge resource: %s\n", err)
		}

		if err := s.network.Close(); err != nil {
			log.Printf("Could not close network: %s\n", err)
		}
	}
}

func (s *IntegrationOIDCTestSuite) SetupSuite() {
	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		s.FailNow(fmt.Sprintf("Could not connect to docker: %s", err), "")
	}

	if pnetwork, err := s.pool.CreateNetwork("headscale-test"); err == nil {
		s.network = *pnetwork
	} else {
		s.FailNow(fmt.Sprintf("Could not create network: %s", err), "")
	}

	// Create does not give us an updated version of the resource, so we need to
	// get it again.
	networks, err := s.pool.NetworksByName("headscale-test")
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not get network: %s", err), "")
	}
	s.network = networks[0]

	s.Suite.T().Log("Setting up mock OIDC")
	oidc, _ := mockoidc.NewServer(nil)
	ln, _ := net.Listen("tcp", fmt.Sprintf("%s:0", s.network.Network.IPAM.Config[0].Gateway))
	oidc.Start(ln, nil)
	s.oidc = oidc

	// we now parse the Issuer URL and replace the host with the docker internal hostname
	// urlIssuer, _ := url.Parse(s.oidc.Issuer())
	// urlIssuer.Host = fmt.Sprintf("host-gateway:%s", urlIssuer.Port())
	// issuer := urlIssuer.String()

	oidcCfg := fmt.Sprintf(`
oidc:
  issuer: %s
  client_id: %s
  client_secret: %s
  strip_email_domain: true`,
		s.oidc.Issuer(),
		s.oidc.Config().ClientID,
		s.oidc.Config().ClientSecret)

	fmt.Println(oidcCfg)

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: ".",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not determine current path: %s", err), "")
	}

	baseConfig, _ := os.ReadFile("integration_test/etc_oidc/base_config.yaml")
	config := string(baseConfig) + oidcCfg

	configPath := path.Join(currentPath, "integration_test/etc_oidc/config.yaml")
	err = os.WriteFile(configPath, []byte(config), 0644)

	headscaleOptions := &dockertest.RunOptions{
		Name: oidcHeadscaleHostname,
		Mounts: []string{
			fmt.Sprintf(
				"%s/integration_test/etc_oidc:/etc/headscale",
				currentPath,
			),
		},
		Cmd:          []string{"headscale", "serve"},
		ExposedPorts: []string{"8443/tcp", "3478/udp"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8443/tcp": {{HostPort: "8443"}},
			"3478/udp": {{HostPort: "3478"}},
		},
	}

	err = s.pool.RemoveContainerByName(oidcHeadscaleHostname)
	if err != nil {
		s.FailNow(
			fmt.Sprintf(
				"Could not remove existing container before building test: %s",
				err,
			),
			"",
		)
	}

	s.Suite.T().Logf("Creating headscale container for OIDC integration tests")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		s.FailNow(fmt.Sprintf("Could not start headscale container: %s", err), "")
	}
	s.Suite.T().Logf("Created headscale container for embedded OIDC tests")

	s.Suite.T().Logf("Creating tailscale containers for embedded OIDC tests")

	for i := 0; i < totalOidcContainers; i++ {
		version := tailscaleVersions[i%len(tailscaleVersions)]
		hostname, container := s.tailscaleContainer(
			fmt.Sprint(i),
			version,
		)
		s.tailscales[hostname] = *container
	}

	s.Suite.T().Logf("Waiting for headscale to be ready for embedded OIDC tests")
	hostEndpoint := fmt.Sprintf("localhost:%s", s.headscale.GetPort("8443/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("https://%s/health", hostEndpoint)
		insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
		insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{Transport: insecureTransport}
		resp, err := client.Get(url)
		if err != nil {
			fmt.Printf("headscale for embedded OIDC tests is not ready: %s\n", err)
			return err
		}

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("status code not OK")
		}

		return nil
	}); err != nil {
		// TODO(kradalby): If we cannot access headscale, or any other fatal error during
		// test setup, we need to abort and tear down. However, testify does not seem to
		// support that at the moment:
		// https://github.com/stretchr/testify/issues/849
		return // fmt.Errorf("Could not connect to headscale: %s", err)
	}
	s.Suite.T().Log("headscale container is ready for embedded OIDC tests")

	s.Suite.T().Logf("Creating headscale namespace: %s\n", oidcNamespaceName)
	result, err := ExecuteCommand(
		&s.headscale,
		[]string{"headscale", "namespaces", "create", oidcNamespaceName},
		[]string{},
	)
	log.Println("headscale create namespace result: ", result)
	assert.Nil(s.T(), err)

	headscaleEndpoint := fmt.Sprintf(
		"https://headscale:%s",
		s.headscale.GetPort("8443/tcp"),
	)

	log.Printf(
		"Joining tailscale containers to headscale at %s\n",
		headscaleEndpoint,
	)
	for hostname, tailscale := range s.tailscales {
		s.joinWaitGroup.Add(1)
		go s.AuthenticateOIDC(headscaleEndpoint, hostname, tailscale)
	}

	s.joinWaitGroup.Wait()

	// The nodes need a bit of time to get their updated maps from headscale
	// TODO: See if we can have a more deterministic wait here.
	time.Sleep(60 * time.Second)
}

func (s *IntegrationOIDCTestSuite) AuthenticateOIDC(
	endpoint, hostname string,
	tailscale dockertest.Resource,
) {
	defer s.joinWaitGroup.Done()

	loginURL, err := s.joinOIDC(endpoint, hostname, tailscale)
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not join OIDC node: %s", err), "")
	}

	insecureTransport := &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}
	client := &http.Client{Transport: insecureTransport}
	resp, err := client.Get(loginURL.String())
	assert.Nil(s.T(), err)

	body, err := io.ReadAll(resp.Body)
	assert.Nil(s.T(), err)

	if err != nil {
		s.FailNow(fmt.Sprintf("Could not read login page: %s", err), "")
	}

	log.Printf("Login page for %s: %s", hostname, string(body))
}

func (s *IntegrationOIDCTestSuite) joinOIDC(
	endpoint, hostname string,
	tailscale dockertest.Resource,
) (*url.URL, error) {

	command := []string{
		"tailscale",
		"up",
		"-login-server",
		endpoint,
		"--hostname",
		hostname,
	}

	log.Println("Join command:", command)
	log.Printf("Running join command for %s\n", hostname)
	result, _ := ExecuteCommand(
		&tailscale,
		command,
		[]string{},
	)

	// This piece of code just gets the login URL out of the output of the tailscale client.
	// See https://github.com/tailscale/tailscale/blob/main/cmd/tailscale/cli/up.go#L584.
	urlStr := strings.ReplaceAll(result, "\nTo authenticate, visit:\n\n\t", "")
	urlStr = strings.TrimSpace(urlStr)

	// parse URL
	loginUrl, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("Could not parse login URL: %s", err)
		log.Printf("Original join command result: %s", result)
		return nil, err
	}

	return loginUrl, nil
}

func (s *IntegrationOIDCTestSuite) tailscaleContainer(
	identifier, version string,
) (string, *dockertest.Resource) {
	tailscaleBuildOptions := getDockerBuildOptions(version)

	hostname := fmt.Sprintf(
		"tailscale-%s-%s",
		strings.Replace(version, ".", "-", -1),
		identifier,
	)
	tailscaleOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{&s.network},
		Cmd: []string{
			"tailscaled", "--tun=tsdev",
		},

		// expose the host IP address, so we can access it from inside the container
		ExtraHosts: []string{
			"host.docker.internal:host-gateway",
			"headscale:host-gateway",
		},
	}

	pts, err := s.pool.BuildAndRunWithBuildOptions(
		tailscaleBuildOptions,
		tailscaleOptions,
		DockerRestartPolicy,
		DockerAllowLocalIPv6,
		DockerAllowNetworkAdministration,
	)
	if err != nil {
		log.Fatalf("Could not start tailscale container version %s: %s", version, err)
	}
	log.Printf("Created %s container\n", hostname)

	return hostname, pts
}

func (s *IntegrationOIDCTestSuite) TearDownSuite() {
	s.oidc.Shutdown()

	if !s.saveLogs {
		for _, tailscale := range s.tailscales {
			if err := s.pool.Purge(&tailscale); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
		}

		if err := s.pool.Purge(&s.headscale); err != nil {
			log.Printf("Could not purge resource: %s\n", err)
		}

		if err := s.network.Close(); err != nil {
			log.Printf("Could not close network: %s\n", err)
		}
	}
}

func (s *IntegrationOIDCTestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationOIDCTestSuite) saveLog(
	resource *dockertest.Resource,
	basePath string,
) error {
	err := os.MkdirAll(basePath, os.ModePerm)
	if err != nil {
		return err
	}

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	err = s.pool.Client.Logs(
		docker.LogsOptions{
			Context:      context.TODO(),
			Container:    resource.Container.ID,
			OutputStream: &stdout,
			ErrorStream:  &stderr,
			Tail:         "all",
			RawTerminal:  false,
			Stdout:       true,
			Stderr:       true,
			Follow:       false,
			Timestamps:   false,
		},
	)
	if err != nil {
		return err
	}

	log.Printf("Saving logs for %s to %s\n", resource.Container.Name, basePath)

	err = os.WriteFile(
		path.Join(basePath, resource.Container.Name+".stdout.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	err = os.WriteFile(
		path.Join(basePath, resource.Container.Name+".stderr.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *IntegrationOIDCTestSuite) TestPingAllPeersByAddress() {
	for hostname, tailscale := range s.tailscales {
		ips, err := getIPs(s.tailscales)
		assert.Nil(s.T(), err)
		for peername, peerIPs := range ips {
			for i, ip := range peerIPs {
				// We currently cant ping ourselves, so skip that.
				if peername == hostname {
					continue
				}
				s.T().
					Run(fmt.Sprintf("%s-%s-%d", hostname, peername, i), func(t *testing.T) {
						// We are only interested in "direct ping" which means what we
						// might need a couple of more attempts before reaching the node.
						command := []string{
							"tailscale", "ping",
							"--timeout=1s",
							"--c=10",
							"--until-direct=true",
							ip.String(),
						}

						log.Printf(
							"Pinging from %s to %s (%s)\n",
							hostname,
							peername,
							ip,
						)
						result, err := ExecuteCommand(
							&tailscale,
							command,
							[]string{},
						)
						assert.Nil(t, err)
						log.Printf("Result for %s: %s\n", hostname, result)
						assert.Contains(t, result, "pong")
					})
			}
		}
	}
}
