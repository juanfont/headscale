// +build integration

package headscale

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"inet.af/netaddr"

	"gopkg.in/check.v1"
)

var _ = check.Suite(&IntegrationSuite{})

type IntegrationSuite struct{}

var integrationTmpDir string
var ih Headscale

var pool dockertest.Pool
var network dockertest.Network
var headscale dockertest.Resource
var tailscaleCount int = 10
var tailscales map[string]dockertest.Resource

func executeCommand(resource *dockertest.Resource, cmd []string) (string, error) {
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode, err := resource.Exec(
		cmd,
		dockertest.ExecOptions{
			StdOut: &stdout,
			StdErr: &stderr,
		},
	)
	if err != nil {
		return "", err
	}

	if exitCode != 0 {
		fmt.Println("Command: ", cmd)
		fmt.Println("stdout: ", stdout.String())
		fmt.Println("stderr: ", stderr.String())
		return "", fmt.Errorf("command failed with: %s", stderr.String())
	}

	return stdout.String(), nil
}

func dockerRestartPolicy(config *docker.HostConfig) {
	// set AutoRemove to true so that stopped container goes away by itself
	config.AutoRemove = true
	config.RestartPolicy = docker.RestartPolicy{
		Name: "no",
	}
}

func (s *IntegrationSuite) SetUpSuite(c *check.C) {
	var err error
	h = Headscale{
		dbType:   "sqlite3",
		dbString: "integration_test_db.sqlite3",
	}

	if ppool, err := dockertest.NewPool(""); err == nil {
		pool = *ppool
	} else {
		log.Fatalf("Could not connect to docker: %s", err)
	}

	if pnetwork, err := pool.CreateNetwork("headscale-test"); err == nil {
		network = *pnetwork
	} else {
		log.Fatalf("Could not create network: %s", err)
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: ".",
	}

	tailscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.tailscale",
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
			fmt.Sprintf("%s/derp.yaml:/etc/headscale/derp.yaml", currentPath),
		},
		Networks: []*dockertest.Network{&network},
		// Cmd: []string{"sleep", "3600"},
		Cmd: []string{"headscale", "serve"},
		PortBindings: map[docker.Port][]docker.PortBinding{
			"8080/tcp": []docker.PortBinding{{HostPort: "8080"}},
		},
		Env: []string{},
	}

	fmt.Println("Creating headscale container")
	if pheadscale, err := pool.BuildAndRunWithBuildOptions(headscaleBuildOptions, headscaleOptions, dockerRestartPolicy); err == nil {
		headscale = *pheadscale
	} else {
		log.Fatalf("Could not start resource: %s", err)
	}
	fmt.Println("Created headscale container")

	fmt.Println("Creating tailscale containers")
	tailscales = make(map[string]dockertest.Resource)
	for i := 0; i < tailscaleCount; i++ {
		hostname := fmt.Sprintf("tailscale%d", i)
		tailscaleOptions := &dockertest.RunOptions{
			Name:     hostname,
			Networks: []*dockertest.Network{&network},
			// Make the container run until killed
			// Cmd: []string{"sleep", "3600"},
			Cmd: []string{"tailscaled", "--tun=userspace-networking", "--socks5-server=localhost:1055"},
			Env: []string{},
		}

		if pts, err := pool.BuildAndRunWithBuildOptions(tailscaleBuildOptions, tailscaleOptions, dockerRestartPolicy); err == nil {
			tailscales[hostname] = *pts
		} else {
			log.Fatalf("Could not start resource: %s", err)
		}
		fmt.Printf("Created %s container\n", hostname)
	}

	fmt.Println("Waiting for headscale to be ready")
	hostEndpoint := fmt.Sprintf("localhost:%s", headscale.GetPort("8080/tcp"))

	if err := pool.Retry(func() error {
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
		log.Fatalf("Could not connect to docker: %s", err)
	}
	fmt.Println("headscale container is ready")

	fmt.Println("Creating headscale namespace")
	result, err := executeCommand(
		&headscale,
		[]string{"headscale", "namespaces", "create", "test"},
	)
	c.Assert(err, check.IsNil)

	fmt.Println("Creating pre auth key")
	authKey, err := executeCommand(
		&headscale,
		[]string{"headscale", "-n", "test", "preauthkeys", "create", "--reusable", "--expiration", "24h"},
	)
	c.Assert(err, check.IsNil)

	headscaleEndpoint := fmt.Sprintf("http://headscale:%s", headscale.GetPort("8080/tcp"))

	fmt.Printf("Joining tailscale containers to headscale at %s\n", headscaleEndpoint)
	for hostname, tailscale := range tailscales {
		command := []string{"tailscale", "up", "-login-server", headscaleEndpoint, "--authkey", strings.TrimSuffix(authKey, "\n"), "--hostname", hostname}

		fmt.Println("Join command:", command)
		fmt.Printf("Running join command for %s\n", hostname)
		result, err = executeCommand(
			&tailscale,
			command,
		)
		fmt.Println("tailscale result: ", result)
		c.Assert(err, check.IsNil)
		fmt.Printf("%s joined\n", hostname)
	}
}

func (s *IntegrationSuite) TearDownSuite(c *check.C) {
	if err := pool.Purge(&headscale); err != nil {
		log.Printf("Could not purge resource: %s\n", err)
	}

	for _, tailscale := range tailscales {
		if err := pool.Purge(&tailscale); err != nil {
			log.Printf("Could not purge resource: %s\n", err)
		}
	}

	if err := network.Close(); err != nil {
		log.Printf("Could not close network: %s\n", err)
	}
}

func (s *IntegrationSuite) TestListNodes(c *check.C) {
	fmt.Println("Listing nodes")
	result, err := executeCommand(
		&headscale,
		[]string{"headscale", "-n", "test", "nodes", "list"},
	)
	c.Assert(err, check.IsNil)

	for hostname, _ := range tailscales {
		c.Assert(strings.Contains(result, hostname), check.Equals, true)
	}
}

func (s *IntegrationSuite) TestGetIpAddresses(c *check.C) {
	ipPrefix := netaddr.MustParseIPPrefix("100.64.0.0/10")
	ips := make(map[string]netaddr.IP)
	for hostname, tailscale := range tailscales {
		command := []string{"tailscale", "ip"}

		result, err := executeCommand(
			&tailscale,
			command,
		)
		c.Assert(err, check.IsNil)

		ip, err := netaddr.ParseIP(strings.TrimSuffix(result, "\n"))
		c.Assert(err, check.IsNil)

		fmt.Printf("IP for %s: %s", hostname, result)

		// c.Assert(ip.Valid(), check.IsTrue)
		c.Assert(ip.Is4(), check.Equals, true)
		c.Assert(ipPrefix.Contains(ip), check.Equals, true)

		ips[hostname] = ip
	}
}
