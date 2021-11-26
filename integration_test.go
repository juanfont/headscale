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

var tailscaleVersions = []string{"1.16.2", "1.14.3", "1.12.3"}

type TestNamespace struct {
	count      int
	tailscales map[string]dockertest.Resource
}

type IntegrationTestSuite struct {
	suite.Suite
	stats *suite.SuiteInformation

	pool      dockertest.Pool
	network   dockertest.Network
	headscale dockertest.Resource

	namespaces map[string]TestNamespace
}

func TestIntegrationTestSuite(t *testing.T) {
	s := new(IntegrationTestSuite)

	s.namespaces = map[string]TestNamespace{
		"main": {
			count:      20,
			tailscales: make(map[string]dockertest.Resource),
		},
		"shared": {
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

	fmt.Printf("Saving logs for %s to %s\n", resource.Container.Name, basePath)

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
			"tailscaled",
			"--tun=userspace-networking",
			"--socks5-server=localhost:1055",
		},
	}

	pts, err := s.pool.BuildAndRunWithBuildOptions(
		tailscaleBuildOptions,
		tailscaleOptions,
		DockerRestartPolicy,
	)
	if err != nil {
		log.Fatalf("Could not start resource: %s", err)
	}
	fmt.Printf("Created %s container\n", hostname)

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

	fmt.Println("Creating headscale container")
	if pheadscale, err := s.pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, DockerRestartPolicy); err == nil {
		s.headscale = *pheadscale
	} else {
		log.Fatalf("Could not start resource: %s", err)
	}
	fmt.Println("Created headscale container")

	fmt.Println("Creating tailscale containers")
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

	fmt.Println("Waiting for headscale to be ready")
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
	fmt.Println("headscale container is ready")

	for namespace, scales := range s.namespaces {
		fmt.Printf("Creating headscale namespace: %s\n", namespace)
		result, err := ExecuteCommand(
			&s.headscale,
			[]string{"headscale", "namespaces", "create", namespace},
			[]string{},
		)
		fmt.Println("headscale create namespace result: ", result)
		assert.Nil(s.T(), err)

		fmt.Printf("Creating pre auth key for %s\n", namespace)
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

		fmt.Printf(
			"Joining tailscale containers to headscale at %s\n",
			headscaleEndpoint,
		)
		for hostname, tailscale := range scales.tailscales {
			command := []string{
				"tailscale",
				"up",
				"-login-server",
				headscaleEndpoint,
				"--authkey",
				preAuthKey.Key,
				"--hostname",
				hostname,
			}

			fmt.Println("Join command:", command)
			fmt.Printf("Running join command for %s\n", hostname)
			result, err := ExecuteCommand(
				&tailscale,
				command,
				[]string{},
			)
			fmt.Println("tailscale result: ", result)
			assert.Nil(s.T(), err)
			fmt.Printf("%s joined\n", hostname)
		}
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
		fmt.Println("Listing nodes")
		result, err := ExecuteCommand(
			&s.headscale,
			[]string{"headscale", "--namespace", namespace, "nodes", "list"},
			[]string{},
		)
		assert.Nil(s.T(), err)

		fmt.Printf("List nodes: \n%s\n", result)

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
		ipPrefix := netaddr.MustParseIPPrefix("100.64.0.0/10")
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname := range scales.tailscales {
			s.T().Run(hostname, func(t *testing.T) {
				ip, ok := ips[hostname]

				assert.True(t, ok)
				assert.NotNil(t, ip)

				fmt.Printf("IP for %s: %s\n", hostname, ip)

				// c.Assert(ip.Valid(), check.IsTrue)
				assert.True(t, ip.Is4())
				assert.True(t, ipPrefix.Contains(ip))
			})
		}
	}
}

func (s *IntegrationTestSuite) TestStatus() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname, tailscale := range scales.tailscales {
			s.T().Run(hostname, func(t *testing.T) {
				command := []string{"tailscale", "status", "--json"}

				fmt.Printf("Getting status for %s\n", hostname)
				result, err := ExecuteCommand(
					&tailscale,
					command,
					[]string{},
				)
				assert.Nil(t, err)

				var status ipnstate.Status
				err = json.Unmarshal([]byte(result), &status)
				assert.Nil(s.T(), err)

				// TODO(kradalby): Replace this check with peer length of SAME namespace
				// Check if we have as many nodes in status
				// as we have IPs/tailscales
				// lines := strings.Split(result, "\n")
				// assert.Equal(t, len(ips), len(lines)-1)
				// assert.Equal(t, len(scales.tailscales), len(lines)-1)

				peerIps := getIPsfromIPNstate(status)

				// Check that all hosts is present in all hosts status
				for ipHostname, ip := range ips {
					if hostname != ipHostname {
						assert.Contains(t, peerIps, ip)
					}
				}
			})
		}
	}
}

func getIPsfromIPNstate(status ipnstate.Status) []netaddr.IP {
	ips := make([]netaddr.IP, 0)

	for _, peer := range status.Peer {
		ips = append(ips, peer.TailscaleIPs...)
	}

	return ips
}

func (s *IntegrationTestSuite) TestPingAllPeers() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname, tailscale := range scales.tailscales {
			for peername, ip := range ips {
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					// We currently cant ping ourselves, so skip that.
					if peername != hostname {
						// We are only interested in "direct ping" which means what we
						// might need a couple of more attempts before reaching the node.
						command := []string{
							"tailscale", "ping",
							"--timeout=1s",
							"--c=10",
							"--until-direct=true",
							ip.String(),
						}

						fmt.Printf(
							"Pinging from %s (%s) to %s (%s)\n",
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
						fmt.Printf("Result for %s: %s\n", hostname, result)
						assert.Contains(t, result, "pong")
					}
				})
			}
		}
	}
}

func (s *IntegrationTestSuite) TestSharedNodes() {
	main := s.namespaces["main"]
	shared := s.namespaces["shared"]

	result, err := ExecuteCommand(
		&s.headscale,
		[]string{
			"headscale",
			"nodes",
			"list",
			"--output",
			"json",
			"--namespace",
			"shared",
		},
		[]string{},
	)
	assert.Nil(s.T(), err)

	var machineList []v1.Machine
	err = json.Unmarshal([]byte(result), &machineList)
	assert.Nil(s.T(), err)

	for _, machine := range machineList {
		result, err := ExecuteCommand(
			&s.headscale,
			[]string{
				"headscale",
				"nodes",
				"share",
				"--identifier", fmt.Sprint(machine.Id),
				"--namespace", "main",
			},
			[]string{},
		)
		assert.Nil(s.T(), err)

		fmt.Println("Shared node with result: ", result)
	}

	result, err = ExecuteCommand(
		&s.headscale,
		[]string{"headscale", "nodes", "list", "--namespace", "main"},
		[]string{},
	)
	assert.Nil(s.T(), err)
	fmt.Println("Nodelist after sharing", result)

	// Chck that the correct count of host is present in node list
	lines := strings.Split(result, "\n")
	assert.Equal(s.T(), len(main.tailscales)+len(shared.tailscales), len(lines)-2)

	for hostname := range main.tailscales {
		assert.Contains(s.T(), result, hostname)
	}

	for hostname := range shared.tailscales {
		assert.Contains(s.T(), result, hostname)
	}

	// TODO(juanfont): We have to find out why do we need to wait
	time.Sleep(100 * time.Second) // Wait for the nodes to receive updates

	mainIps, err := getIPs(main.tailscales)
	assert.Nil(s.T(), err)

	sharedIps, err := getIPs(shared.tailscales)
	assert.Nil(s.T(), err)

	for hostname, tailscale := range main.tailscales {
		for peername, ip := range sharedIps {
			s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
				// We currently cant ping ourselves, so skip that.
				if peername != hostname {
					// We are only interested in "direct ping" which means what we
					// might need a couple of more attempts before reaching the node.
					command := []string{
						"tailscale", "ping",
						"--timeout=15s",
						"--c=20",
						"--until-direct=true",
						ip.String(),
					}

					fmt.Printf(
						"Pinging from %s (%s) to %s (%s)\n",
						hostname,
						mainIps[hostname],
						peername,
						ip,
					)
					result, err := ExecuteCommand(
						&tailscale,
						command,
						[]string{},
					)
					assert.Nil(t, err)
					fmt.Printf("Result for %s: %s\n", hostname, result)
					assert.Contains(t, result, "pong")
				}
			})
		}
	}
}

func (s *IntegrationTestSuite) TestTailDrop() {
	for _, scales := range s.namespaces {
		ips, err := getIPs(scales.tailscales)
		assert.Nil(s.T(), err)
		apiURLs, err := getAPIURLs(scales.tailscales)
		assert.Nil(s.T(), err)

		for hostname, tailscale := range scales.tailscales {
			command := []string{"touch", fmt.Sprintf("/tmp/file_from_%s", hostname)}
			_, err := ExecuteCommand(
				&tailscale,
				command,
				[]string{},
			)
			assert.Nil(s.T(), err)
			for peername, ip := range ips {
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					if peername != hostname {
						// Under normal circumstances, we should be able to send a file
						// using `tailscale file cp` - but not in userspace networking mode
						// So curl!
						peerAPI, ok := apiURLs[ip]
						assert.True(t, ok)

						// TODO(juanfont): We still have some issues with the test infrastructure, so
						// lets run curl multiple times until it works.
						attempts := 0
						var err error
						for {
							command := []string{
								"curl",
								"--retry-connrefused",
								"--retry-delay",
								"30",
								"--retry",
								"10",
								"--connect-timeout",
								"60",
								"-X",
								"PUT",
								"--upload-file",
								fmt.Sprintf("/tmp/file_from_%s", hostname),
								fmt.Sprintf(
									"%s/v0/put/file_from_%s",
									peerAPI,
									hostname,
								),
							}
							fmt.Printf(
								"Sending file from %s (%s) to %s (%s)\n",
								hostname,
								ips[hostname],
								peername,
								ip,
							)
							_, err = ExecuteCommand(
								&tailscale,
								command,
								[]string{"ALL_PROXY=socks5://localhost:1055"},
							)
							if err == nil {
								break
							} else {
								time.Sleep(10 * time.Second)
								attempts++
								if attempts > 10 {
									break
								}
							}
						}
						assert.Nil(t, err)
					}
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
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					if peername != hostname {
						command := []string{
							"ls",
							fmt.Sprintf("/tmp/file_from_%s", peername),
						}
						fmt.Printf(
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
						fmt.Printf("Result for %s: %s\n", peername, result)
						assert.Equal(
							t,
							result,
							fmt.Sprintf("/tmp/file_from_%s\n", peername),
						)
					}
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
			for peername, ip := range ips {
				s.T().Run(fmt.Sprintf("%s-%s", hostname, peername), func(t *testing.T) {
					if peername != hostname {
						command := []string{
							"tailscale", "ping",
							"--timeout=10s",
							"--c=20",
							"--until-direct=true",
							fmt.Sprintf("%s.%s.headscale.net", peername, namespace),
						}

						fmt.Printf(
							"Pinging using Hostname (magicdns) from %s (%s) to %s (%s)\n",
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
						fmt.Printf("Result for %s: %s\n", hostname, result)
						assert.Contains(t, result, "pong")
					}
				})
			}
		}
	}
}

func getIPs(tailscales map[string]dockertest.Resource) (map[string]netaddr.IP, error) {
	ips := make(map[string]netaddr.IP)
	for hostname, tailscale := range tailscales {
		command := []string{"tailscale", "ip"}

		result, err := ExecuteCommand(
			&tailscale,
			command,
			[]string{},
		)
		if err != nil {
			return nil, err
		}

		ip, err := netaddr.ParseIP(strings.TrimSuffix(result, "\n"))
		if err != nil {
			return nil, err
		}

		ips[hostname] = ip
	}

	return ips, nil
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
