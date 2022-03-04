//go:build integration
// +build integration

package headscale

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
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
	"inet.af/netaddr"
	"tailscale.com/client/tailscale/apitype"
	"tailscale.com/ipn/ipnstate"
)

type IntegrationTestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool      dockertest.Pool
	network   dockertest.Network
	headscale dockertest.Resource

	namespaces map[string]TestNamespace

	joinWaitGroup sync.WaitGroup
}

func TestIntegrationTestSuite(t *testing.T) {
	s := new(IntegrationTestSuite)

	s.namespaces = map[string]TestNamespace{
		"thisspace": {
			count:      15,
			tailscales: make(map[string]dockertest.Resource),
		},
		"otherspace": {
			count:      5,
			tailscales: make(map[string]dockertest.Resource),
		},
	}

	suite.Run(t, s)

	// HandleStats, which allows us to check if we passed and save logs
	// is called after TearDown, so we cannot tear down containers before
	// we have potentially saved the logs.
	for _, scales := range s.namespaces {
		for _, tailscale := range scales.tailscales {
			if err := s.pool.Purge(&tailscale); err != nil {
				log.Printf("Could not purge resource: %s\n", err)
			}
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

	if err := s.network.Close(); err != nil {
		log.Printf("Could not close network: %s\n", err)
	}
}

func (s *IntegrationTestSuite) saveLog(
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

func (s *IntegrationTestSuite) Join(
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

func (s *IntegrationTestSuite) tailscaleContainer(
	namespace, identifier, version string,
) (string, *dockertest.Resource) {
	tailscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.tailscale",
		ContextDir: ".",
		BuildArgs: []docker.BuildArg{
			{
				Name:  "TAILSCALE_VERSION",
				Value: version,
			},
		},
	}
	hostname := fmt.Sprintf(
		"%s-tailscale-%s-%s",
		namespace,
		strings.Replace(version, ".", "-", -1),
		identifier,
	)
	tailscaleOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{&s.network},
		Cmd: []string{
			"tailscaled", "--tun=tsdev",
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
		log.Fatalf("Could not start resource: %s", err)
	}
	log.Printf("Created %s container\n", hostname)

	return hostname, pts
}

func (s *IntegrationTestSuite) SetupSuite() {
	var err error
	app = Headscale{
		dbType:   "sqlite3",
		dbString: "integration_test_db.sqlite3",
	}

	if ppool, err := dockertest.NewPool(""); err == nil {
		s.pool = *ppool
	} else {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	if pnetwork, err := s.pool.CreateNetwork("headscale-test"); err == nil {
		s.network = *pnetwork
	} else {
		log.Fatalf("Could not create network: %s", err)
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: ".",
	}

	currentPath, err := os.Getwd()
	if err != nil {
		log.Fatalf("Could not determine current path: %s", err)
	}

	headscaleOptions := &dockertest.RunOptions{
		Name: "headscale",
		Mounts: []string{
			fmt.Sprintf("%s/integration_test/etc:/etc/headscale", currentPath),
		},
		Networks: []*dockertest.Network{&s.network},
		Cmd:      []string{"headscale", "serve"},
	}

	log.Println("Creating headscale container")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		log.Fatalf("Could not start resource: %s", err)
	}
	log.Println("Created headscale container")

	log.Println("Creating tailscale containers")
	for namespace, scales := range s.namespaces {
		for i := 0; i < scales.count; i++ {
			version := tailscaleVersions[i%len(tailscaleVersions)]

			hostname, container := s.tailscaleContainer(
				namespace,
				fmt.Sprint(i),
				version,
			)
			scales.tailscales[hostname] = *container
		}
	}

	log.Println("Waiting for headscale to be ready")
	hostEndpoint := fmt.Sprintf("localhost:%s", s.headscale.GetPort("8080/tcp"))

	if err := s.pool.Retry(func() error {
		url := fmt.Sprintf("http://%s/health", hostEndpoint)

		resp, err := http.Get(url)
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

	for namespace, scales := range s.namespaces {
		log.Printf("Creating headscale namespace: %s\n", namespace)
		result, err := ExecuteCommand(
			&s.headscale,
			[]string{"headscale", "namespaces", "create", namespace},
			[]string{},
		)
		log.Println("headscale create namespace result: ", result)
		assert.Nil(s.T(), err)

		log.Printf("Creating pre auth key for %s\n", namespace)
		preAuthResult, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"--namespace",
				namespace,
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

		headscaleEndpoint := "http://headscale:8080"

		log.Printf(
			"Joining tailscale containers to headscale at %s\n",
			headscaleEndpoint,
		)
		for hostname, tailscale := range scales.tailscales {
			s.joinWaitGroup.Add(1)
			go s.Join(headscaleEndpoint, preAuthKey.Key, hostname, tailscale)
		}

		s.joinWaitGroup.Wait()
	}

	// The nodes need a bit of time to get their updated maps from headscale
	// TODO: See if we can have a more deterministic wait here.
	time.Sleep(60 * time.Second)
}

func (s *IntegrationTestSuite) TearDownSuite() {
}

func (s *IntegrationTestSuite) HandleStats(
	suiteName string,
	stats *suite.SuiteInformation,
) {
	s.stats = stats
}

func (s *IntegrationTestSuite) TestListNodes() {
	for namespace, scales := range s.namespaces {
		log.Println("Listing nodes")
		result, err := ExecuteCommand(
			&s.headscale,
			[]string{"headscale", "--namespace", namespace, "nodes", "list"},
			[]string{},
		)
		assert.Nil(s.T(), err)

		log.Printf("List nodes: \n%s\n", result)

		// Chck that the correct count of host is present in node list
		lines := strings.Split(result, "\n")
		assert.Equal(s.T(), len(scales.tailscales), len(lines)-2)

		for hostname := range scales.tailscales {
			assert.Contains(s.T(), result, hostname)
		}
	}
}

func (s *IntegrationTestSuite) TestGetIpAddresses() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname := range scales.tailscales {
			ips := ips[hostname]
			for _, ip := range ips {
				s.T().Run(hostname, func(t *testing.T) {
					assert.NotNil(t, ip)

					log.Printf("IP for %s: %s\n", hostname, ip)

					// c.Assert(ip.Valid(), check.IsTrue)
					assert.True(t, ip.Is4() || ip.Is6())
					switch {
					case ip.Is4():
						assert.True(t, IpPrefix4.Contains(ip))
					case ip.Is6():
						assert.True(t, IpPrefix6.Contains(ip))
					}
				})
			}
		}
	}
}

// TODO(kradalby): fix this test
// We need some way to import ipnstate.Status from multiple go packages.
// Currently it will only work with 1.18.x since that is the last
// version we have in go.mod
// func (s *IntegrationTestSuite) TestStatus() {
//	for _, scales := range s.namespaces {
//		ips, err := getIPs(scales.tailscales)
//		assert.Nil(s.T(), err)
//
//		for hostname, tailscale := range scales.tailscales {
//			s.T().Run(hostname, func(t *testing.T) {
//				command := []string{"tailscale", "status", "--json"}
//
//				log.Printf("Getting status for %s\n", hostname)
//				result, err := ExecuteCommand(
//					&tailscale,
//					command,
//					[]string{},
//				)
//				assert.Nil(t, err)
//
//				var status ipnstate.Status
//				err = json.Unmarshal([]byte(result), &status)
//				assert.Nil(s.T(), err)
//
//				// TODO(kradalby): Replace this check with peer length of SAME namespace
//				// Check if we have as many nodes in status
//				// as we have IPs/tailscales
//				// lines := strings.Split(result, "\n")
//				// assert.Equal(t, len(ips), len(lines)-1)
//				// assert.Equal(t, len(scales.tailscales), len(lines)-1)
//
//				peerIps := getIPsfromIPNstate(status)
//
//				// Check that all hosts is present in all hosts status
//				for ipHostname, ip := range ips {
//					if hostname != ipHostname {
//						assert.Contains(t, peerIps, ip)
//					}
//				}
//			})
//		}
//	}
// }

func getIPsfromIPNstate(status ipnstate.Status) []netaddr.IP {
	ips := make([]netaddr.IP, 0)

	for _, peer := range status.Peer {
		ips = append(ips, peer.TailscaleIPs...)
	}

	return ips
}

// TODO: Adopt test for cross communication between namespaces
func (s *IntegrationTestSuite) TestPingAllPeersByAddress() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname, tailscale := range scales.tailscales {
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
}

func (s *IntegrationTestSuite) TestTailDrop() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)
		assert.Nil(s.T(), err)

		retry := func(times int, sleepInverval time.Duration, doWork func() error) (err error) {
			for attempts := 0; attempts < times; attempts++ {
				err = doWork()
				if err == nil {
					return
				}
				time.Sleep(sleepInverval)
			}

			return
		}

		for hostname, tailscale := range scales.tailscales {
			command := []string{"touch", fmt.Sprintf("/tmp/file_from_%s", hostname)}
			_, err := ExecuteCommand(
				&tailscale,
				command,
				[]string{},
			)
			assert.Nil(s.T(), err)
			for peername := range ips {
				if peername == hostname {
					continue
				}
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					command := []string{
						"tailscale", "file", "cp",
						fmt.Sprintf("/tmp/file_from_%s", hostname),
						fmt.Sprintf("%s:", peername),
					}
					retry(10, 1*time.Second, func() error {
						log.Printf(
							"Sending file from %s to %s\n",
							hostname,
							peername,
						)
						_, err := ExecuteCommand(
							&tailscale,
							command,
							[]string{},
							ExecuteCommandTimeout(60*time.Second),
						)
						return err
					})
					assert.Nil(t, err)
				})
			}
		}

		for hostname, tailscale := range scales.tailscales {
			command := []string{
				"tailscale", "file",
				"get",
				"/tmp/",
			}
			_, err := ExecuteCommand(
				&tailscale,
				command,
				[]string{},
			)
			assert.Nil(s.T(), err)
			for peername, ip := range ips {
				if peername == hostname {
					continue
				}
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					command := []string{
						"ls",
						fmt.Sprintf("/tmp/file_from_%s", peername),
					}
					log.Printf(
						"Checking file in %s (%s) from %s (%s)\n",
						hostname,
						ips[hostname],
						peername,
						ip,
					)
					result, err := ExecuteCommand(
						&tailscale,
						command,
						[]string{},
					)
					assert.Nil(t, err)
					log.Printf("Result for %s: %s\n", peername, result)
					assert.Equal(
						t,
						fmt.Sprintf("/tmp/file_from_%s\n", peername),
						result,
					)
				})
			}
		}
	}
}

func (s *IntegrationTestSuite) TestPingAllPeersByHostname() {
	for namespace, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)
		for hostname, tailscale := range scales.tailscales {
			for peername := range ips {
				if peername == hostname {
					continue
				}
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					command := []string{
						"tailscale", "ping",
						"--timeout=10s",
						"--c=20",
						"--until-direct=true",
						fmt.Sprintf("%s.%s.headscale.net", peername, namespace),
					}

					log.Printf(
						"Pinging using hostname from %s to %s\n",
						hostname,
						peername,
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

func (s *IntegrationTestSuite) TestMagicDNS() {
	for namespace, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)
		for hostname, tailscale := range scales.tailscales {
			for peername, ips := range ips {
				if peername == hostname {
					continue
				}
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					command := []string{
						"tailscale", "ip",
						fmt.Sprintf("%s.%s.headscale.net", peername, namespace),
					}

					log.Printf(
						"Resolving name %s from %s\n",
						peername,
						hostname,
					)
					result, err := ExecuteCommand(
						&tailscale,
						command,
						[]string{},
					)
					assert.Nil(t, err)
					log.Printf("Result for %s: %s\n", hostname, result)

					for _, ip := range ips {
						assert.Contains(t, result, ip.String())
					}
				})
			}
		}
	}
}

func getAPIURLs(
	tailscales map[string]dockertest.Resource,
) (map[netaddr.IP]string, error) {
	fts := make(map[netaddr.IP]string)
	for _, tailscale := range tailscales {
		command := []string{
			"curl",
			"--unix-socket",
			"/run/tailscale/tailscaled.sock",
			"http://localhost/localapi/v0/file-targets",
		}
		result, err := ExecuteCommand(
			&tailscale,
			command,
			[]string{},
		)
		if err != nil {
			return nil, err
		}

		var pft []apitype.FileTarget
		if err := json.Unmarshal([]byte(result), &pft); err != nil {
			return nil, fmt.Errorf("invalid JSON: %w", err)
		}
		for _, ft := range pft {
			n := ft.Node
			for _, a := range n.Addresses { // just add all the addresses
				if _, ok := fts[a.IP()]; !ok {
					if ft.PeerAPIURL == "" {
						return nil, errors.New("api url is empty")
					}
					fts[a.IP()] = ft.PeerAPIURL
				}
			}
		}
	}

	return fts, nil
}
