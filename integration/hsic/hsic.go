package hsic

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
)

const (
	hsicHashLength                = 6
	dockerContextPath             = "../."
	caCertRoot                    = "/usr/local/share/ca-certificates"
	aclPolicyPath                 = "/etc/headscale/acl.hujson"
	tlsCertPath                   = "/etc/headscale/tls.cert"
	tlsKeyPath                    = "/etc/headscale/tls.key"
	headscaleDefaultPort          = 8080
	IntegrationTestDockerFileName = "Dockerfile.integration"
)

var errHeadscaleStatusCodeNotOk = errors.New("headscale status code not ok")

type fileInContainer struct {
	path     string
	contents []byte
}

// HeadscaleInContainer is an implementation of ControlServer which
// sets up a Headscale instance inside a container.
type HeadscaleInContainer struct {
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	pgContainer *dockertest.Resource

	// optional config
	port             int
	extraPorts       []string
	caCerts          [][]byte
	hostPortBindings map[string][]string
	aclPolicy        *policy.ACLPolicy
	env              map[string]string
	tlsCert          []byte
	tlsKey           []byte
	filesInContainer []fileInContainer
	postgres         bool
}

// Option represent optional settings that can be given to a
// Headscale instance.
type Option = func(c *HeadscaleInContainer)

// WithACLPolicy adds a hscontrol.ACLPolicy policy to the
// HeadscaleInContainer instance.
func WithACLPolicy(acl *policy.ACLPolicy) Option {
	return func(hsic *HeadscaleInContainer) {
		if acl == nil {
			return
		}

		// TODO(kradalby): Move somewhere appropriate
		hsic.env["HEADSCALE_POLICY_PATH"] = aclPolicyPath

		hsic.aclPolicy = acl
	}
}

// WithCACert adds it to the trusted surtificate of the container.
func WithCACert(cert []byte) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.caCerts = append(hsic.caCerts, cert)
	}
}

// WithTLS creates certificates and enables HTTPS.
func WithTLS() Option {
	return func(hsic *HeadscaleInContainer) {
		cert, key, err := integrationutil.CreateCertificate(hsic.hostname)
		if err != nil {
			log.Fatalf("failed to create certificates for headscale test: %s", err)
		}

		hsic.tlsCert = cert
		hsic.tlsKey = key
	}
}

// WithCustomTLS uses the given certificates for the Headscale instance.
func WithCustomTLS(cert, key []byte) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.tlsCert = cert
		hsic.tlsKey = key
	}
}

// WithConfigEnv takes a map of environment variables that
// can be used to override Headscale configuration.
func WithConfigEnv(configEnv map[string]string) Option {
	return func(hsic *HeadscaleInContainer) {
		for key, value := range configEnv {
			hsic.env[key] = value
		}
	}
}

// WithPort sets the port on where to run Headscale.
func WithPort(port int) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.port = port
	}
}

// WithExtraPorts exposes additional ports on the container (e.g. 3478/udp for STUN).
func WithExtraPorts(ports []string) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.extraPorts = ports
	}
}

func WithHostPortBindings(bindings map[string][]string) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.hostPortBindings = bindings
	}
}

// WithTestName sets a name for the test, this will be reflected
// in the Docker container name.
func WithTestName(testName string) Option {
	return func(hsic *HeadscaleInContainer) {
		hash, _ := util.GenerateRandomStringDNSSafe(hsicHashLength)

		hostname := fmt.Sprintf("hs-%s-%s", testName, hash)
		hsic.hostname = hostname
	}
}

// WithHostname sets the hostname of the Headscale instance.
func WithHostname(hostname string) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.hostname = hostname
	}
}

// WithFileInContainer adds a file to the container at the given path.
func WithFileInContainer(path string, contents []byte) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.filesInContainer = append(hsic.filesInContainer,
			fileInContainer{
				path:     path,
				contents: contents,
			})
	}
}

// WithPostgres spins up a Postgres container and
// sets it as the main database.
func WithPostgres() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.postgres = true
	}
}

// WithIPAllocationStrategy sets the tests IP Allocation strategy.
func WithIPAllocationStrategy(strategy types.IPAllocationStrategy) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_PREFIXES_ALLOCATION"] = string(strategy)
	}
}

// WithEmbeddedDERPServerOnly configures Headscale to start
// and only use the embedded DERP server.
// It requires WithTLS and WithHostnameAsServerURL to be
// set.
func WithEmbeddedDERPServerOnly() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_DERP_URLS"] = ""
		hsic.env["HEADSCALE_DERP_SERVER_ENABLED"] = "true"
		hsic.env["HEADSCALE_DERP_SERVER_REGION_ID"] = "999"
		hsic.env["HEADSCALE_DERP_SERVER_REGION_CODE"] = "headscale"
		hsic.env["HEADSCALE_DERP_SERVER_REGION_NAME"] = "Headscale Embedded DERP"
		hsic.env["HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR"] = "0.0.0.0:3478"
		hsic.env["HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH"] = "/tmp/derp.key"

		// Envknob for enabling DERP debug logs
		hsic.env["DERP_DEBUG_LOGS"] = "true"
		hsic.env["DERP_PROBER_DEBUG_LOGS"] = "true"
	}
}

// WithDERPConfig configures Headscale use a custom
// DERP server only.
func WithDERPConfig(derpMap tailcfg.DERPMap) Option {
	return func(hsic *HeadscaleInContainer) {
		contents, err := yaml.Marshal(derpMap)
		if err != nil {
			log.Fatalf("failed to marshal DERP map: %s", err)

			return
		}

		hsic.env["HEADSCALE_DERP_PATHS"] = "/etc/headscale/derp.yml"
		hsic.filesInContainer = append(hsic.filesInContainer,
			fileInContainer{
				path:     "/etc/headscale/derp.yml",
				contents: contents,
			})

		// Disable global DERP server and embedded DERP server
		hsic.env["HEADSCALE_DERP_URLS"] = ""
		hsic.env["HEADSCALE_DERP_SERVER_ENABLED"] = "false"

		// Envknob for enabling DERP debug logs
		hsic.env["DERP_DEBUG_LOGS"] = "true"
		hsic.env["DERP_PROBER_DEBUG_LOGS"] = "true"
	}
}

// WithTuning allows changing the tuning settings easily.
func WithTuning(batchTimeout time.Duration, mapSessionChanSize int) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_TUNING_BATCH_CHANGE_DELAY"] = batchTimeout.String()
		hsic.env["HEADSCALE_TUNING_NODE_MAPSESSION_BUFFERED_CHAN_SIZE"] = strconv.Itoa(mapSessionChanSize)
	}
}

func WithTimezone(timezone string) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["TZ"] = timezone
	}
}

// New returns a new HeadscaleInContainer instance.
func New(
	pool *dockertest.Pool,
	network *dockertest.Network,
	opts ...Option,
) (*HeadscaleInContainer, error) {
	hash, err := util.GenerateRandomStringDNSSafe(hsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("hs-%s", hash)

	hsic := &HeadscaleInContainer{
		hostname: hostname,
		port:     headscaleDefaultPort,

		pool:    pool,
		network: network,

		env:              DefaultConfigEnv(),
		filesInContainer: []fileInContainer{},
	}

	for _, opt := range opts {
		opt(hsic)
	}

	log.Println("NAME: ", hsic.hostname)

	portProto := fmt.Sprintf("%d/tcp", hsic.port)

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: IntegrationTestDockerFileName,
		ContextDir: dockerContextPath,
	}

	if hsic.postgres {
		hsic.env["HEADSCALE_DATABASE_TYPE"] = "postgres"
		hsic.env["HEADSCALE_DATABASE_POSTGRES_HOST"] = fmt.Sprintf("postgres-%s", hash)
		hsic.env["HEADSCALE_DATABASE_POSTGRES_USER"] = "headscale"
		hsic.env["HEADSCALE_DATABASE_POSTGRES_PASS"] = "headscale"
		hsic.env["HEADSCALE_DATABASE_POSTGRES_NAME"] = "headscale"
		delete(hsic.env, "HEADSCALE_DATABASE_SQLITE_PATH")

		pg, err := pool.RunWithOptions(
			&dockertest.RunOptions{
				Name:       fmt.Sprintf("postgres-%s", hash),
				Repository: "postgres",
				Tag:        "latest",
				Networks:   []*dockertest.Network{network},
				Env: []string{
					"POSTGRES_USER=headscale",
					"POSTGRES_PASSWORD=headscale",
					"POSTGRES_DB=headscale",
				},
			})
		if err != nil {
			return nil, fmt.Errorf("starting postgres container: %w", err)
		}

		hsic.pgContainer = pg
	}

	env := []string{
		"HEADSCALE_DEBUG_PROFILING_ENABLED=1",
		"HEADSCALE_DEBUG_PROFILING_PATH=/tmp/profile",
		"HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH=/tmp/mapresponses",
		"HEADSCALE_DEBUG_DEADLOCK=1",
		"HEADSCALE_DEBUG_DEADLOCK_TIMEOUT=5s",
		"HEADSCALE_DEBUG_HIGH_CARDINALITY_METRICS=1",
		"HEADSCALE_DEBUG_DUMP_CONFIG=1",
	}
	if hsic.hasTLS() {
		hsic.env["HEADSCALE_TLS_CERT_PATH"] = tlsCertPath
		hsic.env["HEADSCALE_TLS_KEY_PATH"] = tlsKeyPath
	}

	// Server URL and Listen Addr should not be overridable outside of
	// the configuration passed to docker.
	hsic.env["HEADSCALE_SERVER_URL"] = hsic.GetEndpoint()
	hsic.env["HEADSCALE_LISTEN_ADDR"] = fmt.Sprintf("0.0.0.0:%d", hsic.port)

	for key, value := range hsic.env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	log.Printf("ENV: \n%s", spew.Sdump(hsic.env))

	runOptions := &dockertest.RunOptions{
		Name:         hsic.hostname,
		ExposedPorts: append([]string{portProto, "9090/tcp"}, hsic.extraPorts...),
		Networks:     []*dockertest.Network{network},
		// Cmd:          []string{"headscale", "serve"},
		// TODO(kradalby): Get rid of this hack, we currently need to give us some
		// to inject the headscale configuration further down.
		Entrypoint: []string{"/bin/bash", "-c", "/bin/sleep 3 ; update-ca-certificates ; headscale serve ; /bin/sleep 30"},
		Env:        env,
	}

	if len(hsic.hostPortBindings) > 0 {
		runOptions.PortBindings = map[docker.Port][]docker.PortBinding{}
		for port, hostPorts := range hsic.hostPortBindings {
			runOptions.PortBindings[docker.Port(port)] = []docker.PortBinding{}
			for _, hostPort := range hostPorts {
				runOptions.PortBindings[docker.Port(port)] = append(
					runOptions.PortBindings[docker.Port(port)],
					docker.PortBinding{HostPort: hostPort})
			}
		}
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hsic.hostname)
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
	log.Printf("Created %s container\n", hsic.hostname)

	hsic.container = container

	// Write the CA certificates to the container
	for i, cert := range hsic.caCerts {
		err = hsic.WriteFile(fmt.Sprintf("%s/user-%d.crt", caCertRoot, i), cert)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS certificate to container: %w", err)
		}
	}

	err = hsic.WriteFile("/etc/headscale/config.yaml", []byte(MinimumConfigYAML()))
	if err != nil {
		return nil, fmt.Errorf("failed to write headscale config to container: %w", err)
	}

	if hsic.aclPolicy != nil {
		data, err := json.Marshal(hsic.aclPolicy)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ACL Policy to JSON: %w", err)
		}

		err = hsic.WriteFile(aclPolicyPath, data)
		if err != nil {
			return nil, fmt.Errorf("failed to write ACL policy to container: %w", err)
		}
	}

	if hsic.hasTLS() {
		err = hsic.WriteFile(tlsCertPath, hsic.tlsCert)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS certificate to container: %w", err)
		}

		err = hsic.WriteFile(tlsKeyPath, hsic.tlsKey)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS key to container: %w", err)
		}
	}

	for _, f := range hsic.filesInContainer {
		if err := hsic.WriteFile(f.path, f.contents); err != nil {
			return nil, fmt.Errorf("failed to write %q: %w", f.path, err)
		}
	}

	return hsic, nil
}

func (t *HeadscaleInContainer) ConnectToNetwork(network *dockertest.Network) error {
	return t.container.ConnectToNetwork(network)
}

func (t *HeadscaleInContainer) hasTLS() bool {
	return len(t.tlsCert) != 0 && len(t.tlsKey) != 0
}

// Shutdown stops and cleans up the Headscale container.
func (t *HeadscaleInContainer) Shutdown() (string, string, error) {
	stdoutPath, stderrPath, err := t.SaveLog("/tmp/control")
	if err != nil {
		log.Printf(
			"Failed to save log from control: %s",
			fmt.Errorf("failed to save log from control: %w", err),
		)
	}

	err = t.SaveMetrics(fmt.Sprintf("/tmp/control/%s_metrics.txt", t.hostname))
	if err != nil {
		log.Printf(
			"Failed to metrics from control: %s",
			err,
		)
	}

	// Send a interrupt signal to the "headscale" process inside the container
	// allowing it to shut down gracefully and flush the profile to disk.
	// The container will live for a bit longer due to the sleep at the end.
	err = t.SendInterrupt()
	if err != nil {
		log.Printf(
			"Failed to send graceful interrupt to control: %s",
			fmt.Errorf("failed to send graceful interrupt to control: %w", err),
		)
	}

	err = t.SaveProfile("/tmp/control")
	if err != nil {
		log.Printf(
			"Failed to save profile from control: %s",
			fmt.Errorf("failed to save profile from control: %w", err),
		)
	}

	err = t.SaveMapResponses("/tmp/control")
	if err != nil {
		log.Printf(
			"Failed to save mapresponses from control: %s",
			fmt.Errorf("failed to save mapresponses from control: %w", err),
		)
	}

	// We dont have a database to save if we use postgres
	if !t.postgres {
		err = t.SaveDatabase("/tmp/control")
		if err != nil {
			log.Printf(
				"Failed to save database from control: %s",
				fmt.Errorf("failed to save database from control: %w", err),
			)
		}
	}

	// Cleanup postgres container if enabled.
	if t.postgres {
		t.pool.Purge(t.pgContainer)
	}

	return stdoutPath, stderrPath, t.pool.Purge(t.container)
}

// WriteLogs writes the current stdout/stderr log of the container to
// the given io.Writers.
func (t *HeadscaleInContainer) WriteLogs(stdout, stderr io.Writer) error {
	return dockertestutil.WriteLog(t.pool, t.container, stdout, stderr)
}

// SaveLog saves the current stdout log of the container to a path
// on the host system.
func (t *HeadscaleInContainer) SaveLog(path string) (string, string, error) {
	return dockertestutil.SaveLog(t.pool, t.container, path)
}

func (t *HeadscaleInContainer) SaveMetrics(savePath string) error {
	resp, err := http.Get(fmt.Sprintf("http://%s:9090/metrics", t.hostname))
	if err != nil {
		return fmt.Errorf("getting metrics: %w", err)
	}
	defer resp.Body.Close()
	out, err := os.Create(savePath)
	if err != nil {
		return fmt.Errorf("creating file for metrics: %w", err)
	}
	defer out.Close()
	_, err = io.Copy(out, resp.Body)
	if err != nil {
		return fmt.Errorf("copy response to file: %w", err)
	}

	return nil
}

func (t *HeadscaleInContainer) SaveProfile(savePath string) error {
	tarFile, err := t.FetchPath("/tmp/profile")
	if err != nil {
		return err
	}

	err = os.WriteFile(
		path.Join(savePath, t.hostname+".pprof.tar"),
		tarFile,
		os.ModePerm,
	)
	if err != nil {
		return err
	}

	return nil
}

func (t *HeadscaleInContainer) SaveMapResponses(savePath string) error {
	tarFile, err := t.FetchPath("/tmp/mapresponses")
	if err != nil {
		return err
	}

	err = os.WriteFile(
		path.Join(savePath, t.hostname+".maps.tar"),
		tarFile,
		os.ModePerm,
	)
	if err != nil {
		return err
	}

	return nil
}

func (t *HeadscaleInContainer) SaveDatabase(savePath string) error {
	tarFile, err := t.FetchPath("/tmp/integration_test_db.sqlite3")
	if err != nil {
		return err
	}

	err = os.WriteFile(
		path.Join(savePath, t.hostname+".db.tar"),
		tarFile,
		os.ModePerm,
	)
	if err != nil {
		return err
	}

	return nil
}

// Execute runs a command inside the Headscale container and returns the
// result of stdout as a string.
func (t *HeadscaleInContainer) Execute(
	command []string,
) (string, error) {
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		log.Printf("command: %v", command)
		log.Printf("command stderr: %s\n", stderr)

		if stdout != "" {
			log.Printf("command stdout: %s\n", stdout)
		}

		return stdout, fmt.Errorf("executing command in docker: %w, stderr: %s", err, stderr)
	}

	return stdout, nil
}

// GetIP returns the docker container IP as a string.
func (t *HeadscaleInContainer) GetIP() string {
	return t.container.GetIPInNetwork(t.network)
}

// GetPort returns the docker container port as a string.
func (t *HeadscaleInContainer) GetPort() string {
	return fmt.Sprintf("%d", t.port)
}

// GetHealthEndpoint returns a health endpoint for the HeadscaleInContainer
// instance.
func (t *HeadscaleInContainer) GetHealthEndpoint() string {
	return fmt.Sprintf("%s/health", t.GetEndpoint())
}

// GetEndpoint returns the Headscale endpoint for the HeadscaleInContainer.
func (t *HeadscaleInContainer) GetEndpoint() string {
	hostEndpoint := fmt.Sprintf("%s:%d",
		t.GetHostname(),
		t.port)

	if t.hasTLS() {
		return fmt.Sprintf("https://%s", hostEndpoint)
	}

	return fmt.Sprintf("http://%s", hostEndpoint)
}

// GetCert returns the public certificate of the HeadscaleInContainer.
func (t *HeadscaleInContainer) GetCert() []byte {
	return t.tlsCert
}

// GetHostname returns the hostname of the HeadscaleInContainer.
func (t *HeadscaleInContainer) GetHostname() string {
	return t.hostname
}

// WaitForRunning blocks until the Headscale instance is ready to
// serve clients.
func (t *HeadscaleInContainer) WaitForRunning() error {
	url := t.GetHealthEndpoint()

	log.Printf("waiting for headscale to be ready at %s", url)

	client := &http.Client{}

	if t.hasTLS() {
		insecureTransport := http.DefaultTransport.(*http.Transport).Clone()      //nolint
		insecureTransport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint
		client = &http.Client{Transport: insecureTransport}
	}

	return t.pool.Retry(func() error {
		resp, err := client.Get(url) //nolint
		if err != nil {
			return fmt.Errorf("headscale is not ready: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			return errHeadscaleStatusCodeNotOk
		}

		return nil
	})
}

// CreateUser adds a new user to the Headscale instance.
func (t *HeadscaleInContainer) CreateUser(
	user string,
) error {
	command := []string{"headscale", "users", "create", user, fmt.Sprintf("--email=%s@test.no", user)}

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

// CreateAuthKey creates a new "authorisation key" for a User that can be used
// to authorise a TailscaleClient with the Headscale instance.
func (t *HeadscaleInContainer) CreateAuthKey(
	user string,
	reusable bool,
	ephemeral bool,
) (*v1.PreAuthKey, error) {
	command := []string{
		"headscale",
		"--user",
		user,
		"preauthkeys",
		"create",
		"--expiration",
		"24h",
		"--output",
		"json",
	}

	if reusable {
		command = append(command, "--reusable")
	}

	if ephemeral {
		command = append(command, "--ephemeral")
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

// ListNodesInUser list the TailscaleClients (Node, Headscale internal representation)
// associated with a user.
func (t *HeadscaleInContainer) ListNodesInUser(
	user string,
) ([]*v1.Node, error) {
	command := []string{"headscale", "--user", user, "nodes", "list", "--output", "json"}

	result, _, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to execute list node command: %w", err)
	}

	var nodes []*v1.Node
	err = json.Unmarshal([]byte(result), &nodes)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal nodes: %w", err)
	}

	return nodes, nil
}

// WriteFile save file inside the Headscale container.
func (t *HeadscaleInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

// FetchPath gets a path from inside the Headscale container and returns a tar
// file as byte array.
func (t *HeadscaleInContainer) FetchPath(path string) ([]byte, error) {
	return integrationutil.FetchPathFromContainer(t.pool, t.container, path)
}

func (t *HeadscaleInContainer) SendInterrupt() error {
	pid, err := t.Execute([]string{"pidof", "headscale"})
	if err != nil {
		return err
	}

	_, err = t.Execute([]string{"kill", "-2", strings.Trim(pid, "'\n")})
	if err != nil {
		return err
	}

	return nil
}
