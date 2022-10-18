package hsic

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path"

	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
)

const hsicHashLength = 6
const dockerContextPath = "../."

var errHeadscaleStatusCodeNotOk = errors.New("headscale status code not ok")

type HeadscaleInContainer struct {
	hostname string
	port     int

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network
}

func New(
	pool *dockertest.Pool,
	port int,
	network *dockertest.Network) (*HeadscaleInContainer, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(hsicHashLength)
	if err != nil {
		return nil, err
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile",
		ContextDir: dockerContextPath,
	}

	hostname := fmt.Sprintf("hs-%s", hash)
	portProto := fmt.Sprintf("%d/tcp", port)

	currentPath, err := os.Getwd()
	if err != nil {
		return nil, fmt.Errorf("could not determine current path: %w", err)
	}

	integrationConfigPath := path.Join(currentPath, "..", "integration_test", "etc")

	runOptions := &dockertest.RunOptions{
		Name: hostname,
		// TODO(kradalby): Do something clever here, can we ditch the config repo?
		// Always generate the config from code?
		Mounts: []string{
			fmt.Sprintf("%s:/etc/headscale", integrationConfigPath),
		},
		ExposedPorts: []string{portProto},
		// TODO(kradalby): WHY do we need to bind these now that we run fully in docker?
		Networks: []*dockertest.Network{network},
		Cmd:      []string{"headscale", "serve"},
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.BuildAndRunWithBuildOptions(
		headscaleBuildOptions,
		runOptions,
		dockertestutil.DockerRestartPolicy,
		dockertestutil.DockerAllowLocalIPv6,
		dockertestutil.DockerAllowNetworkAdministration,
	)
	if err != nil {
		return nil, fmt.Errorf("could not start headscale container: %w", err)
	}
	log.Printf("Created %s container\n", hostname)

	return &HeadscaleInContainer{
		hostname: hostname,
		port:     port,

		pool:      pool,
		container: container,
		network:   network,
	}, nil
}

func (t *HeadscaleInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
}

func (t *HeadscaleInContainer) GetIP() string {
	return t.container.GetIPInNetwork(t.network)
}

func (t *HeadscaleInContainer) GetPort() string {
	portProto := fmt.Sprintf("%d/tcp", t.port)

	return t.container.GetPort(portProto)
}

func (t *HeadscaleInContainer) GetHealthEndpoint() string {
	hostEndpoint := fmt.Sprintf("%s:%d",
		t.GetIP(),
		t.port)

	return fmt.Sprintf("http://%s/health", hostEndpoint)
}

func (t *HeadscaleInContainer) GetEndpoint() string {
	hostEndpoint := fmt.Sprintf("%s:%d",
		t.GetIP(),
		t.port)

	return fmt.Sprintf("http://%s", hostEndpoint)
}

func (t *HeadscaleInContainer) WaitForReady() error {
	url := t.GetHealthEndpoint()

	log.Printf("waiting for headscale to be ready at %s", url)

	return t.pool.Retry(func() error {
		resp, err := http.Get(url)
		if err != nil {
			return fmt.Errorf("headscale is not ready: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return errHeadscaleStatusCodeNotOk
		}

		return nil
	})
}

func (t *HeadscaleInContainer) CreateNamespace(
	namespace string,
) error {
	command := []string{"headscale", "namespaces", "create", namespace}

	_, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return err
	}

	return nil
}

func (t *HeadscaleInContainer) CreateAuthKey(
	namespace string,
) (*v1.PreAuthKey, error) {
	command := []string{
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
	}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute create auth key command: %w", err)
	}

	var preAuthKey v1.PreAuthKey
	err = json.Unmarshal([]byte(result), &preAuthKey)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth key: %w", err)
	}

	return &preAuthKey, nil
}

func (t *HeadscaleInContainer) ListNodes(
	namespace string,
) ([]*v1.Machine, error) {
	command := []string{"headscale", "--namespace", namespace, "nodes", "list", "--output", "json"}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute list node command: %w", err)
	}

	var nodes []*v1.Machine
	err = json.Unmarshal([]byte(result), &nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes: %w", err)
	}

	return nodes, nil
}
