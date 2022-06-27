//go:build integration

package headscale

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/suite"

	"github.com/ccding/go-stun/stun"
)

const (
	headscaleHostname = "headscale-derp"
	namespaceName     = "derpnamespace"
	totalContainers   = 3
)

type IntegrationDERPTestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool      dockertest.Pool
	networks  map[int]dockertest.Network // so we keep the containers isolated
	headscale dockertest.Resource
	saveLogs  bool

	tailscales    map[string]dockertest.Resource
	joinWaitGroup sync.WaitGroup
}

func TestDERPIntegrationTestSuite(t *testing.T) {
	saveLogs, err := GetEnvBool("HEADSCALE_INTEGRATION_SAVE_LOG")
	if err != nil {
		saveLogs = false
	}

	s := new(IntegrationDERPTestSuite)

	s.tailscales = make(map[string]dockertest.Resource)
	s.networks = make(map[int]dockertest.Network)
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
			log.Printf("Could not purge resource: %s\n", err)
		}

		for _, network := range s.networks {
			if err := network.Close(); err != nil {
				log.Printf("Could not close network: %s\n", err)
			}
		}
	}
}

func (s *IntegrationDERPTestSuite) SetupSuite() {
	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		s.FailNow(fmt.Sprintf("Could not connect to docker: %s", err), "")
	}

	for i := 0; i < totalContainers; i++ {
		if pnetwork, err := s.pool.CreateNetwork(fmt.Sprintf("headscale-derp-%d", i)); err == nil {
			s.networks[i] = *pnetwork
		} else {
			s.FailNow(fmt.Sprintf("Could not create network: %s", err), "")
		}
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: ".",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not determine current path: %s", err), "")
	}

	headscaleOptions := &dockertest.RunOptions{
		Name: headscaleHostname,
		Mounts: []string{
			fmt.Sprintf(
				"%s/integration_test/etc_embedded_derp:/etc/headscale",
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

	err = s.pool.RemoveContainerByName(headscaleHostname)
	if err != nil {
		s.FailNow(fmt.Sprintf("Could not remove existing container before building test: %s", err), "")
	}

	log.Println("Creating headscale container")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		s.FailNow(fmt.Sprintf("Could not start headscale container: %s", err), "")
	}
	log.Println("Created headscale container to test DERP")

	log.Println("Creating tailscale containers")

	for i := 0; i < totalContainers; i++ {
		version := tailscaleVersions[i%len(tailscaleVersions)]
		hostname, container := s.tailscaleContainer(
			fmt.Sprint(i),
			version,
			s.networks[i],
		)
		s.tailscales[hostname] = *container
	}

	log.Println("Waiting for headscale to be ready")
	hostEndpoint := fmt.Sprintf("localhost:%s", s.headscale.GetPort("8443/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("https://%s/health", hostEndpoint)
		insecureTransport := http.DefaultTransport.(*http.Transport).Clone()
		insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
		client := &http.Client{Transport: insecureTransport}
		resp, err := client.Get(url)
		if err != nil {
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
	log.Println("headscale container is ready")

	log.Printf("Creating headscale namespace: %s\n", namespaceName)
	result, err := ExecuteCommand(
		&s.headscale,
		[]string{"headscale", "namespaces", "create", namespaceName},
		[]string{},
	)
	log.Println("headscale create namespace result: ", result)
	assert.Nil(s.T(), err)

	log.Printf("Creating pre auth key for %s\n", namespaceName)
	preAuthResult, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"--namespace",
			namespaceName,
			"preauthkeys",
			"create",
			"--reusable",
			"--expiration",
			"24h",
			"--output",
			"json",
		},
		[]string{"LOG_LEVEL=error"},
	)
	assert.Nil(s.T(), err)

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(preAuthResult), &preAuthKey)
	assert.Nil(s.T(), err)
	assert.True(s.T(), preAuthKey.Reusable)

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
		go s.Join(headscaleEndpoint, preAuthKey.Key, hostname, tailscale)
	}

	s.joinWaitGroup.Wait()

	// The nodes need a bit of time to get their updated maps from headscale
	// TODO: See if we can have a more deterministic wait here.
	time.Sleep(60 * time.Second)
}

func (s *IntegrationDERPTestSuite) Join(
	endpoint, key, hostname string,
	tailscale dockertest.Resource,
) {
	defer s.joinWaitGroup.Done()

	command := []string{
		"tailscale",
		"up",
		"-login-server",
		endpoint,
		"--authkey",
		key,
		"--hostname",
		hostname,
	}

	log.Println("Join command:", command)
	log.Printf("Running join command for %s\n", hostname)
	_, err := ExecuteCommand(
		&tailscale,
		command,
		[]string{},
	)
	assert.Nil(s.T(), err)
	log.Printf("%s joined\n", hostname)
}

func (s *IntegrationDERPTestSuite) tailscaleContainer(
	identifier, version string,
	network dockertest.Network,
) (string, *dockertest.Resource) {
	tailscaleBuildOptions := getDockerBuildOptions(version)

	hostname := fmt.Sprintf(
		"tailscale-%s-%s",
		strings.Replace(version, ".", "-", -1),
		identifier,
	)
	tailscaleOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{&network},
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

func (s *IntegrationDERPTestSuite) TearDownSuite() {
	if !s.saveLogs {
		for _, tailscale := range s.tailscales {
			if err := s.pool.Purge(&tailscale); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
		}

		if err := s.pool.Purge(&s.headscale); err != nil {
			log.Printf("Could not purge resource: %s\n", err)
		}

		for _, network := range s.networks {
			if err := network.Close(); err != nil {
				log.Printf("Could not close network: %s\n", err)
			}
		}
	}
}

func (s *IntegrationDERPTestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationDERPTestSuite) saveLog(
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

	err = ioutil.WriteFile(
		path.Join(basePath, resource.Container.Name+".stdout.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	err = ioutil.WriteFile(
		path.Join(basePath, resource.Container.Name+".stderr.log"),
		[]byte(stdout.String()),
		0o644,
	)
	if err != nil {
		return err
	}

	return nil
}

func (s *IntegrationDERPTestSuite) TestPingAllPeersByHostname() {
	hostnames, err := getDNSNames(&s.headscale)
	assert.Nil(s.T(), err)

	log.Printf("Hostnames: %#v\n", hostnames)

	for hostname, tailscale := range s.tailscales {
		for _, peername := range hostnames {
			if strings.Contains(peername, hostname) {
				continue
			}
			s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
				command := []string{
					"tailscale", "ping",
					"--timeout=10s",
					"--c=5",
					"--until-direct=false",
					peername,
				}

				log.Printf(
					"Pinging using hostname from %s to %s\n",
					hostname,
					peername,
				)
				log.Println(command)
				result, err := ExecuteCommand(
					&tailscale,
					command,
					[]string{},
				)
				assert.Nil(t, err)
				log.Printf("Result for %s: %s\n", hostname, result)
				assert.Contains(t, result, "via DERP(headscale)")
			})
		}
	}
}

func (s *IntegrationDERPTestSuite) TestDERPSTUN() {
	headscaleSTUNAddr := fmt.Sprintf("localhost:%s", s.headscale.GetPort("3478/udp"))
	client := stun.NewClient()
	client.SetVerbose(true)
	client.SetVVerbose(true)
	client.SetServerAddr(headscaleSTUNAddr)
	_, _, err := client.Discover()
	assert.Nil(s.T(), err)
}
