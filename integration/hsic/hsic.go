package hsic

import (
	"archive/tar"
	"bytes"
	"cmp"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	clientv2 "github.com/juanfont/headscale/gen/client/v2"
	"github.com/juanfont/headscale/hscontrol"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"gopkg.in/yaml.v3"
	"tailscale.com/tailcfg"
	"tailscale.com/util/mak"
	"tailscale.com/util/rands"
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
	defaultDirPerm                = 0o755
	binHeadscale                  = "headscale"
	flagOutput                    = "--output"
	acceptJSON                    = "Accept: application/json"
)

var (
	errHeadscaleStatusCodeNotOk    = errors.New("headscale status code not ok")
	errInvalidHeadscaleImageFormat = errors.New("invalid HEADSCALE_INTEGRATION_HEADSCALE_IMAGE format, expected repository:tag")
	errHeadscaleImageRequiredInCI  = errors.New("HEADSCALE_INTEGRATION_HEADSCALE_IMAGE must be set in CI")
	errInvalidPostgresImageFormat  = errors.New("invalid HEADSCALE_INTEGRATION_POSTGRES_IMAGE format, expected repository:tag")
)

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
	networks  []*dockertest.Network

	pgContainer *dockertest.Resource

	// optional config
	port             int
	extraPorts       []string
	hostMetricsPort  string // Dynamically assigned host port for metrics/pprof access
	caCerts          [][]byte
	hostPortBindings map[string][]string
	aclPolicy        *policyv2.Policy
	env              map[string]string
	tlsCACert        []byte
	tlsCert          []byte
	tlsKey           []byte
	noTLS            bool
	filesInContainer []fileInContainer
	postgres         bool
	policyMode       types.PolicyMode
}

// Option represent optional settings that can be given to a
// Headscale instance.
type Option = func(c *HeadscaleInContainer)

// WithACLPolicy adds a [policyv2.Policy] to the
// [HeadscaleInContainer] instance.
func WithACLPolicy(acl *policyv2.Policy) Option {
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

// WithoutTLS disables the default TLS configuration.
// Most tests should not need this. Use only for tests that
// explicitly need to test non-TLS behavior.
func WithoutTLS() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.noTLS = true
	}
}

// WithCustomTLS uses the given certificates for the Headscale instance.
// The caCert is installed into the container's trust store and returned
// by [HeadscaleInContainer.GetCert] so that clients can trust this server.
func WithCustomTLS(caCert, cert, key []byte) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.tlsCACert = caCert
		hsic.tlsCert = cert
		hsic.tlsKey = key
		hsic.caCerts = append(hsic.caCerts, caCert)
	}
}

// WithConfigEnv takes a map of environment variables that
// can be used to override Headscale configuration.
func WithConfigEnv(configEnv map[string]string) Option {
	return func(hsic *HeadscaleInContainer) {
		maps.Copy(hsic.env, configEnv)
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
		hash := rands.HexString(hsicHashLength)

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

// WithPolicyMode sets the policy mode for headscale.
func WithPolicyMode(mode types.PolicyMode) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.policyMode = mode
		hsic.env["HEADSCALE_POLICY_MODE"] = string(mode)
	}
}

// WithIPAllocationStrategy sets the tests IP Allocation strategy.
func WithIPAllocationStrategy(strategy types.IPAllocationStrategy) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_PREFIXES_ALLOCATION"] = string(strategy)
	}
}

// WithPublicDERP disables the embedded DERP server and restores
// the default public DERP relay configuration. Use this for tests
// that explicitly need to test public DERP behavior.
func WithPublicDERP() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_DERP_URLS"] = "https://controlplane.tailscale.com/derpmap/default"
		hsic.env["HEADSCALE_DERP_SERVER_ENABLED"] = "false"
		delete(hsic.env, "HEADSCALE_DERP_SERVER_REGION_ID")
		delete(hsic.env, "HEADSCALE_DERP_SERVER_REGION_CODE")
		delete(hsic.env, "HEADSCALE_DERP_SERVER_REGION_NAME")
		delete(hsic.env, "HEADSCALE_DERP_SERVER_STUN_LISTEN_ADDR")
		delete(hsic.env, "HEADSCALE_DERP_SERVER_PRIVATE_KEY_PATH")
		delete(hsic.env, "DERP_DEBUG_LOGS")
		delete(hsic.env, "DERP_PROBER_DEBUG_LOGS")
	}
}

// WithDERPConfig configures Headscale use a custom
// DERP server only.
func WithDERPConfig(derpMap tailcfg.DERPMap) Option {
	return func(hsic *HeadscaleInContainer) {
		contents, err := yaml.Marshal(derpMap)
		if err != nil {
			log.Fatalf("marshalling DERP map: %s", err)

			return
		}

		hsic.env["HEADSCALE_DERP_PATHS"] = "/etc/headscale/derp.yml"
		hsic.filesInContainer = append(hsic.filesInContainer,
			fileInContainer{
				path:     "/etc/headscale/derp.yml",
				contents: contents,
			})

		// Disable global DERP server and embedded DERP server
		hsic.env["HEADSCALE_DERP_URLS"] = "[]"
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
		hsic.env["HEADSCALE_TUNING_NODE_MAPSESSION_BUFFERED_CHAN_SIZE"] = strconv.Itoa(
			mapSessionChanSize,
		)
	}
}

func WithHAProbing(interval, timeout time.Duration) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_NODE_ROUTES_HA_PROBE_INTERVAL"] = interval.String()
		hsic.env["HEADSCALE_NODE_ROUTES_HA_PROBE_TIMEOUT"] = timeout.String()
	}
}

func WithTimezone(timezone string) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["TZ"] = timezone
	}
}

// buildEntrypoint builds the container entrypoint command based on configuration.
// It constructs proper wait conditions instead of fixed sleeps:
// 1. Wait for network to be ready
// 2. Wait for config.yaml (always written after container start)
// 3. Wait for CA certs if configured
// 4. Update CA certificates
// 5. Run headscale serve
// 6. Sleep at end to keep container alive for log collection on shutdown.
func (hsic *HeadscaleInContainer) buildEntrypoint() []string {
	var commands []string

	// Wait for network to be ready
	commands = append(commands, "while ! ip route show default >/dev/null 2>&1; do sleep 0.1; done")

	// Wait for config.yaml to be written (always written after container start)
	commands = append(commands, "while [ ! -f /etc/headscale/config.yaml ]; do sleep 0.1; done")

	// If CA certs are configured, wait for them to be written
	if len(hsic.caCerts) > 0 {
		commands = append(commands,
			fmt.Sprintf("while [ ! -f %s/user-0.crt ]; do sleep 0.1; done", caCertRoot))
	}

	// Update CA certificates
	commands = append(commands, "update-ca-certificates")

	// Run headscale serve
	commands = append(commands, "/usr/local/bin/headscale serve")

	// Keep container alive after headscale exits for log collection
	commands = append(commands, "/bin/sleep 30")

	return []string{"/bin/bash", "-c", strings.Join(commands, " ; ")}
}

// New returns a new [HeadscaleInContainer] instance.
//
//nolint:gocyclo // complex container setup with many options
func New(
	pool *dockertest.Pool,
	networks []*dockertest.Network,
	opts ...Option,
) (*HeadscaleInContainer, error) {
	hash := rands.HexString(hsicHashLength)

	// Include run ID in hostname for easier identification of which test run owns this container
	runID := dockertestutil.GetIntegrationRunID()

	var hostname string

	if runID != "" {
		// Use last 6 chars of run ID (the random hash part) for brevity
		runIDShort := runID[len(runID)-6:]
		hostname = fmt.Sprintf("hs-%s-%s", runIDShort, hash)
	} else {
		hostname = "hs-" + hash
	}

	hsic := &HeadscaleInContainer{
		hostname: hostname,
		port:     headscaleDefaultPort,

		pool:     pool,
		networks: networks,

		env:              DefaultConfigEnv(),
		filesInContainer: []fileInContainer{},
		policyMode:       types.PolicyModeFile,
	}

	for _, opt := range opts {
		opt(hsic)
	}

	// TLS is enabled by default for all integration tests.
	// Generate a self-signed certificate if TLS was not explicitly
	// disabled via [WithoutTLS] and no custom cert was provided
	// via [WithCustomTLS].
	if !hsic.noTLS && len(hsic.tlsCert) == 0 {
		caCert, cert, key, err := integrationutil.CreateCertificate(hsic.hostname)
		if err != nil {
			return nil, fmt.Errorf("creating default TLS certificates: %w", err)
		}

		hsic.tlsCACert = caCert
		hsic.tlsCert = cert
		hsic.tlsKey = key

		// Install the CA cert into the headscale container's trust
		// store so that tools like curl trust the server's own
		// certificate.
		hsic.caCerts = append(hsic.caCerts, caCert)
	}

	log.Println("NAME: ", hsic.hostname)

	portProto := fmt.Sprintf("%d/tcp", hsic.port)

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: IntegrationTestDockerFileName,
		ContextDir: dockerContextPath,
	}

	if hsic.postgres {
		hsic.env["HEADSCALE_DATABASE_TYPE"] = "postgres"
		hsic.env["HEADSCALE_DATABASE_POSTGRES_HOST"] = "postgres-" + hash
		hsic.env["HEADSCALE_DATABASE_POSTGRES_USER"] = binHeadscale
		hsic.env["HEADSCALE_DATABASE_POSTGRES_PASS"] = binHeadscale
		hsic.env["HEADSCALE_DATABASE_POSTGRES_NAME"] = binHeadscale
		delete(hsic.env, "HEADSCALE_DATABASE_SQLITE_PATH")

		// Determine postgres image - use prebuilt if available, otherwise pull from registry
		pgRepo := "postgres"
		pgTag := "latest"

		if prebuiltImage := os.Getenv("HEADSCALE_INTEGRATION_POSTGRES_IMAGE"); prebuiltImage != "" {
			repo, tag, found := strings.Cut(prebuiltImage, ":")
			if !found {
				return nil, errInvalidPostgresImageFormat
			}

			pgRepo = repo
			pgTag = tag
		}

		pgRunOptions := &dockertest.RunOptions{
			Name:       "postgres-" + hash,
			Repository: pgRepo,
			Tag:        pgTag,
			Networks:   networks,
			Env: []string{
				"POSTGRES_USER=headscale",
				"POSTGRES_PASSWORD=headscale",
				"POSTGRES_DB=headscale",
			},
		}

		// Add integration test labels if running under hi tool
		dockertestutil.DockerAddIntegrationLabels(pgRunOptions, "postgres")

		pg, err := pool.RunWithOptions(pgRunOptions)
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
		Networks:     networks,
		// Cmd:          []string{"headscale", "serve"},
		// TODO(kradalby): Get rid of this hack, we currently need to give us some
		// to inject the headscale configuration further down.
		Entrypoint: hsic.buildEntrypoint(),
		Env:        env,
	}

	// Bind metrics port to dynamic host port (kernel assigns free port)
	if runOptions.PortBindings == nil {
		runOptions.PortBindings = map[docker.Port][]docker.PortBinding{}
	}

	runOptions.PortBindings["9090/tcp"] = []docker.PortBinding{
		{HostPort: "0"}, // Let kernel assign a free port
	}

	if len(hsic.hostPortBindings) > 0 {
		for port, hostPorts := range hsic.hostPortBindings {
			runOptions.PortBindings[docker.Port(port)] = []docker.PortBinding{}
			for _, hostPort := range hostPorts {
				runOptions.PortBindings[docker.Port(port)] = append(
					runOptions.PortBindings[docker.Port(port)],
					docker.PortBinding{HostPort: hostPort},
				)
			}
		}
	}

	// dockertest isn't very good at handling containers that has already
	// been created, this is an attempt to make sure this container isn't
	// present.
	err := pool.RemoveContainerByName(hsic.hostname)
	if err != nil {
		return nil, err
	}

	// Add integration test labels if running under hi tool
	dockertestutil.DockerAddIntegrationLabels(runOptions, binHeadscale)

	var container *dockertest.Resource

	// Check if a pre-built image is available via environment variable
	prebuiltImage := os.Getenv("HEADSCALE_INTEGRATION_HEADSCALE_IMAGE")

	if prebuiltImage != "" {
		log.Printf("Using pre-built headscale image: %s", prebuiltImage) //nolint:gosec // G706: integration-only log of trusted env value
		// Parse image into repository and tag
		repo, tag, ok := strings.Cut(prebuiltImage, ":")
		if !ok {
			return nil, errInvalidHeadscaleImageFormat
		}

		runOptions.Repository = repo
		runOptions.Tag = tag

		container, err = pool.RunWithOptions(
			runOptions,
			dockertestutil.DockerRestartPolicy,
			dockertestutil.DockerAllowLocalIPv6,
			dockertestutil.DockerAllowNetworkAdministration,
		)
		if err != nil {
			return nil, fmt.Errorf("running pre-built headscale container %q: %w", prebuiltImage, err)
		}
	} else if util.IsCI() {
		return nil, errHeadscaleImageRequiredInCI
	} else {
		container, err = pool.BuildAndRunWithBuildOptions(
			headscaleBuildOptions,
			runOptions,
			dockertestutil.DockerRestartPolicy,
			dockertestutil.DockerAllowLocalIPv6,
			dockertestutil.DockerAllowNetworkAdministration,
		)
		if err != nil {
			// Try to get more detailed build output
			log.Printf("Docker build/run failed, attempting to get detailed output...")

			buildOutput, buildErr := dockertestutil.RunDockerBuildForDiagnostics(dockerContextPath, IntegrationTestDockerFileName)

			// Show the last 100 lines of build output to avoid overwhelming the logs
			lines := strings.Split(buildOutput, "\n")

			const maxLines = 100

			startLine := 0
			if len(lines) > maxLines {
				startLine = len(lines) - maxLines
			}

			relevantOutput := strings.Join(lines[startLine:], "\n")

			if buildErr != nil {
				// The diagnostic build also failed - this is the real error
				return nil, fmt.Errorf("starting headscale container: %w\n\nDocker build failed. Last %d lines of output:\n%s", err, maxLines, relevantOutput)
			}

			if buildOutput != "" {
				// Build succeeded on retry but container creation still failed
				return nil, fmt.Errorf("starting headscale container: %w\n\nDocker build succeeded on retry, but container creation failed. Last %d lines of build output:\n%s", err, maxLines, relevantOutput)
			}

			// No output at all - diagnostic build command may have failed
			return nil, fmt.Errorf("starting headscale container: %w\n\nUnable to get diagnostic build output (command may have failed silently)", err)
		}
	}

	log.Printf("Created %s container\n", hsic.hostname)

	hsic.container = container

	// Get the dynamically assigned host port for metrics/pprof
	hsic.hostMetricsPort = container.GetHostPort("9090/tcp")

	log.Printf(
		"Headscale %s metrics available at http://localhost:%s/metrics (debug at http://localhost:%s/debug/)\n",
		hsic.hostname,
		hsic.hostMetricsPort,
		hsic.hostMetricsPort,
	)

	// Write the CA certificates to the container
	for i, cert := range hsic.caCerts {
		err = hsic.WriteFile(fmt.Sprintf("%s/user-%d.crt", caCertRoot, i), cert)
		if err != nil {
			return nil, fmt.Errorf("writing TLS certificate to container: %w", err)
		}
	}

	err = hsic.WriteFile("/etc/headscale/config.yaml", []byte(MinimumConfigYAML()))
	if err != nil {
		return nil, fmt.Errorf("writing headscale config to container: %w", err)
	}

	if hsic.aclPolicy != nil {
		err = hsic.writePolicy(hsic.aclPolicy)
		if err != nil {
			return nil, fmt.Errorf("writing policy: %w", err)
		}
	}

	if hsic.hasTLS() {
		err = hsic.WriteFile(tlsCertPath, hsic.tlsCert)
		if err != nil {
			return nil, fmt.Errorf("writing TLS certificate to container: %w", err)
		}

		err = hsic.WriteFile(tlsKeyPath, hsic.tlsKey)
		if err != nil {
			return nil, fmt.Errorf("writing TLS key to container: %w", err)
		}
	}

	for _, f := range hsic.filesInContainer {
		err := hsic.WriteFile(f.path, f.contents)
		if err != nil {
			return nil, fmt.Errorf("writing %q: %w", f.path, err)
		}
	}

	// Load the database from policy file on repeat until it succeeds,
	// this is done as the container sleeps before starting headscale.
	if hsic.aclPolicy != nil && hsic.policyMode == types.PolicyModeDB {
		err := pool.Retry(hsic.reloadDatabasePolicy)
		if err != nil {
			return nil, fmt.Errorf("loading database policy on startup: %w", err)
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
			"saving log from control: %s",
			fmt.Errorf("saving log from control: %w", err),
		)
	}

	err = t.SaveMetrics(fmt.Sprintf("/tmp/control/%s_metrics.txt", t.hostname))
	if err != nil {
		log.Printf(
			"saving metrics from control: %s",
			err,
		)
	}

	// Send a interrupt signal to the "headscale" process inside the container
	// allowing it to shut down gracefully and flush the profile to disk.
	// The container will live for a bit longer due to the sleep at the end.
	err = t.SendInterrupt()
	if err != nil {
		log.Printf(
			"sending graceful interrupt to control: %s",
			fmt.Errorf("sending graceful interrupt to control: %w", err),
		)
	}

	err = t.SaveProfile("/tmp/control")
	if err != nil {
		log.Printf(
			"saving profile from control: %s",
			fmt.Errorf("saving profile from control: %w", err),
		)
	}

	err = t.SaveMapResponses("/tmp/control")
	if err != nil {
		log.Printf(
			"saving mapresponses from control: %s",
			fmt.Errorf("saving mapresponses from control: %w", err),
		)
	}

	// We dont have a database to save if we use postgres
	if !t.postgres {
		err = t.SaveDatabase("/tmp/control")
		if err != nil {
			log.Printf(
				"saving database from control: %s",
				fmt.Errorf("saving database from control: %w", err),
			)
		}
	}

	// Cleanup postgres container if enabled.
	if t.postgres {
		_ = t.pool.Purge(t.pgContainer)
	}

	return stdoutPath, stderrPath, t.pool.Purge(t.container)
}

// WriteLogs writes the current stdout/stderr log of the container to
// the given [io.Writer]s.
func (t *HeadscaleInContainer) WriteLogs(stdout, stderr io.Writer) error {
	return dockertestutil.WriteLog(t.pool, t.container, stdout, stderr)
}

// ReadLog returns the current stdout and stderr logs from the headscale container.
func (t *HeadscaleInContainer) ReadLog() (string, string, error) {
	var stdout, stderr bytes.Buffer

	err := dockertestutil.WriteLog(t.pool, t.container, &stdout, &stderr)
	if err != nil {
		return "", "", fmt.Errorf("reading container logs: %w", err)
	}

	return stdout.String(), stderr.String(), nil
}

// SaveLog saves the current stdout log of the container to a path
// on the host system.
func (t *HeadscaleInContainer) SaveLog(path string) (string, string, error) {
	return dockertestutil.SaveLog(t.pool, t.container, path)
}

func (t *HeadscaleInContainer) SaveMetrics(savePath string) error {
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+net.JoinHostPort(t.hostname, "9090")+"/metrics", nil)
	if err != nil {
		return fmt.Errorf("creating metrics request: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
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

// extractTarToDirectory extracts a tar archive to a directory.
func extractTarToDirectory(tarData []byte, targetDir string) error {
	err := os.MkdirAll(targetDir, defaultDirPerm)
	if err != nil {
		return fmt.Errorf("creating directory %s: %w", targetDir, err)
	}

	// Find the top-level directory to strip
	var topLevelDir string

	firstPass := tar.NewReader(bytes.NewReader(tarData))
	for {
		header, err := firstPass.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		if header.Typeflag == tar.TypeDir && topLevelDir == "" {
			topLevelDir = strings.TrimSuffix(header.Name, "/")
			break
		}
	}

	tarReader := tar.NewReader(bytes.NewReader(tarData))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		// Clean the path to prevent directory traversal
		cleanName := filepath.Clean(header.Name)
		if strings.Contains(cleanName, "..") {
			continue // Skip potentially dangerous paths
		}

		// Strip the top-level directory
		if topLevelDir != "" && strings.HasPrefix(cleanName, topLevelDir+"/") {
			cleanName = strings.TrimPrefix(cleanName, topLevelDir+"/")
		} else if cleanName == topLevelDir {
			// Skip the top-level directory itself
			continue
		}

		// Skip empty paths after stripping
		if cleanName == "" {
			continue
		}

		targetPath := filepath.Join(targetDir, cleanName)

		switch header.Typeflag {
		case tar.TypeDir:
			// Create directory
			//nolint:gosec // G115: header.Mode is trusted from tar archive
			err := os.MkdirAll(targetPath, os.FileMode(header.Mode))
			if err != nil {
				return fmt.Errorf("creating directory %s: %w", targetPath, err)
			}
		case tar.TypeReg:
			// Ensure parent directories exist
			err := os.MkdirAll(filepath.Dir(targetPath), defaultDirPerm)
			if err != nil {
				return fmt.Errorf("creating parent directories for %s: %w", targetPath, err)
			}

			// Create file
			outFile, err := os.Create(targetPath)
			if err != nil {
				return fmt.Errorf("creating file %s: %w", targetPath, err)
			}

			if _, err := io.Copy(outFile, tarReader); err != nil { //nolint:gosec,noinlineerr // trusted tar from test container
				outFile.Close()
				return fmt.Errorf("copying file contents: %w", err)
			}

			outFile.Close()

			// Set file permissions
			if err := os.Chmod(targetPath, os.FileMode(header.Mode)); err != nil { //nolint:gosec,noinlineerr // safe mode from tar header
				return fmt.Errorf("setting file permissions: %w", err)
			}
		}
	}

	return nil
}

func (t *HeadscaleInContainer) SaveProfile(savePath string) error {
	tarFile, err := t.FetchPath("/tmp/profile")
	if err != nil {
		return err
	}

	targetDir := path.Join(savePath, "pprof")

	return extractTarToDirectory(tarFile, targetDir)
}

func (t *HeadscaleInContainer) SaveMapResponses(savePath string) error {
	tarFile, err := t.FetchPath("/tmp/mapresponses")
	if err != nil {
		return err
	}

	targetDir := path.Join(savePath, "mapresponses")

	return extractTarToDirectory(tarFile, targetDir)
}

func (t *HeadscaleInContainer) SaveDatabase(savePath string) error {
	// If using PostgreSQL, skip database file extraction
	if t.postgres {
		return nil
	}

	// Also check for any .sqlite files
	sqliteFiles, err := t.Execute([]string{"find", "/tmp", "-name", "*.sqlite*", "-type", "f"})
	if err != nil {
		log.Printf("Warning: could not find sqlite files: %v", err)
	} else {
		log.Printf("SQLite files found in %s:\n%s", t.hostname, sqliteFiles)
	}

	// Check if the database file exists and has a schema
	dbPath := "/tmp/integration_test_db.sqlite3"

	fileInfo, err := t.Execute([]string{"ls", "-la", dbPath})
	if err != nil {
		return fmt.Errorf("database file does not exist at %s: %w", dbPath, err)
	}

	log.Printf("Database file info: %s", fileInfo)

	// Check if the database has any tables (schema)
	schemaCheck, err := t.Execute([]string{"sqlite3", dbPath, ".schema"})
	if err != nil {
		return fmt.Errorf("checking database schema (sqlite3 command failed): %w", err)
	}

	if strings.TrimSpace(schemaCheck) == "" {
		return errors.New("database file exists but has no schema (empty database)") //nolint:err113
	}

	tarFile, err := t.FetchPath("/tmp/integration_test_db.sqlite3")
	if err != nil {
		return fmt.Errorf("fetching database file: %w", err)
	}

	// For database, extract the first regular file (should be the SQLite file)
	tarReader := tar.NewReader(bytes.NewReader(tarFile))
	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}

		if err != nil {
			return fmt.Errorf("reading tar header: %w", err)
		}

		log.Printf(
			"Found file in tar: %s (type: %d, size: %d)",
			header.Name,
			header.Typeflag,
			header.Size,
		)

		// Extract the first regular file we find
		if header.Typeflag == tar.TypeReg {
			dbPath := path.Join(savePath, t.hostname+".db")

			outFile, err := os.Create(dbPath)
			if err != nil {
				return fmt.Errorf("creating database file: %w", err)
			}

			written, err := io.Copy(outFile, tarReader) //nolint:gosec // trusted tar from test container
			outFile.Close()

			if err != nil {
				return fmt.Errorf("copying database file: %w", err)
			}

			log.Printf(
				"Extracted database file: %s (%d bytes written, header claimed %d bytes)",
				dbPath,
				written,
				header.Size,
			)

			// Check if we actually wrote something
			if written == 0 {
				return fmt.Errorf( //nolint:err113
					"database file is empty (size: %d, header size: %d)",
					written,
					header.Size,
				)
			}

			return nil
		}
	}

	return errors.New("no regular file found in database tar archive") //nolint:err113
}

// Execute runs a command inside the Headscale container and returns the
// result of stdout as a string.
func (t *HeadscaleInContainer) Execute(
	command []string,
) (string, error) {
	return t.executeEnv(command, nil)
}

// executeEnv is Execute with env added to the command's environment, which
// no log line or error names.
func (t *HeadscaleInContainer) executeEnv(command, env []string) (string, error) {
	stdout, stderr, err := dockertestutil.ExecuteCommand(t.container, command, env)
	if err != nil {
		return stdout, execFailure(command, stdout, stderr, err)
	}

	return stdout, nil
}

// execFailure logs a failed command and returns its error, with no secret
// in either.
func execFailure(command []string, stdout, stderr string, err error) error {
	log.Printf("command: %v", dockertestutil.Redact(fmt.Sprint(command)))
	log.Printf("command stderr: %s\n", dockertestutil.Redact(stderr))

	if stdout != "" {
		log.Printf("command stdout: %s\n", dockertestutil.Redact(stdout))
	}

	return dockertestutil.Redactf(err, "executing command in docker: %v, stderr: %s", err, stderr)
}

// GetPort returns the docker container port as a string.
func (t *HeadscaleInContainer) GetPort() string {
	return strconv.Itoa(t.port)
}

// GetHostMetricsPort returns the dynamically assigned host port for metrics/pprof access.
// This port can be used by operators to access metrics at http://localhost:{port}/metrics
// and debug endpoints at http://localhost:{port}/debug/ while tests are running.
func (t *HeadscaleInContainer) GetHostMetricsPort() string {
	return t.hostMetricsPort
}

// GetHealthEndpoint returns a health endpoint for the [HeadscaleInContainer]
// instance.
func (t *HeadscaleInContainer) GetHealthEndpoint() string {
	return t.GetEndpoint() + "/health"
}

// GetEndpoint returns the Headscale endpoint for the [HeadscaleInContainer].
func (t *HeadscaleInContainer) GetEndpoint() string {
	return t.getEndpoint(false)
}

var (
	errOAuthSecretMissing = errors.New(`OAuth client response missing secret in "key" field`)
	errOAuthStatus        = errors.New("the server did not create the OAuth client")
)

// CreateOAuthClient mints an admin API key and uses it to create an OAuth client
// via the v2 keys HTTP API (POST /api/v2/tailnet/-/keys, keyType=client),
// returning the client id and secret. The secret is only returned once, in the
// "key" field. It is a reusable building block for tests that need OAuth client
// credentials (such as the Kubernetes operator).
func (t *HeadscaleInContainer) CreateOAuthClient(
	ctx context.Context,
	scopes, tags []string,
) (string, string, error) {
	apiKey, err := t.Execute([]string{binHeadscale, "api", "keys", "create", "--expiry", "24h"})
	if err != nil {
		return "", "", fmt.Errorf("creating admin api key: %w", err)
	}

	return createOAuthClient(ctx, t.GetEndpoint(), t.httpClient(), strings.TrimSpace(apiKey), scopes, tags)
}

// createOAuthClient creates an OAuth client at endpoint with apiKey. A
// failure names no secret: the generated client's errors quote what it
// could not parse, and an answer of another status may hold a key.
func createOAuthClient(ctx context.Context, endpoint string, hc *http.Client, apiKey string, scopes, tags []string) (string, string, error) {
	client, err := clientv2.NewClientWithResponses(
		endpoint,
		clientv2.WithHTTPClient(hc),
		clientv2.WithRequestEditorFn(func(_ context.Context, req *http.Request) error {
			req.Header.Set("Authorization", "Bearer "+apiKey)

			return nil
		}),
	)
	if err != nil {
		return "", "", dockertestutil.Redactf(err, "building v2 API client: %v", err)
	}

	keyType := "client"

	resp, err := client.CreateKeyWithResponse(ctx, "-", clientv2.CreateKeyRequest{
		KeyType: &keyType,
		Scopes:  &scopes,
		Tags:    &tags,
	})
	if err != nil {
		return "", "", dockertestutil.Redactf(err, "creating OAuth client: %v", err)
	}

	if resp.JSON200 == nil {
		return "", "", dockertestutil.Redactf(errOAuthStatus,
			"creating OAuth client: status %s: %s", resp.Status(), strings.TrimSpace(string(resp.Body)))
	}

	if resp.JSON200.Key == nil || *resp.JSON200.Key == "" {
		return "", "", errOAuthSecretMissing
	}

	// The operator expects clientId and clientSecret as separate values. When the
	// server returns a single opaque credential, the client-credentials grant
	// splits it on "-" (id-secret), matching the Tailscale SaaS shape. Fall back
	// to the whole key as the secret when no id is given.
	clientID, clientSecret := resp.JSON200.Id, *resp.JSON200.Key

	if clientID == "" {
		if id, secret, ok := strings.Cut(*resp.JSON200.Key, "-"); ok {
			clientID, clientSecret = id, secret
		}
	}

	return clientID, clientSecret, nil
}

// httpClient returns an HTTP client that trusts this Headscale's TLS CA when TLS
// is enabled, or a default client when it serves plain HTTP.
func (t *HeadscaleInContainer) httpClient() *http.Client {
	if !t.hasTLS() {
		return &http.Client{Timeout: 30 * time.Second}
	}

	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(t.tlsCACert)

	return &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		},
	}
}

// GetIPEndpoint returns the Headscale endpoint using IP address instead of hostname.
func (t *HeadscaleInContainer) GetIPEndpoint() string {
	return t.getEndpoint(true)
}

// getEndpoint returns the Headscale endpoint, optionally using IP address instead of hostname.
func (t *HeadscaleInContainer) getEndpoint(useIP bool) string {
	var host string
	if useIP && len(t.networks) > 0 {
		// Use IP address from the first network
		host = t.GetIPInNetwork(t.networks[0])
	} else {
		host = t.GetHostname()
	}

	hostEndpoint := fmt.Sprintf("%s:%d", host, t.port)

	if t.hasTLS() {
		return "https://" + hostEndpoint
	}

	return "http://" + hostEndpoint
}

// GetCert returns the CA certificate that clients should trust to
// verify this server's TLS certificate.
func (t *HeadscaleInContainer) GetCert() []byte {
	return t.tlsCACert
}

// GetHostname returns the hostname of the [HeadscaleInContainer].
func (t *HeadscaleInContainer) GetHostname() string {
	return t.hostname
}

// GetIPInNetwork returns the IP address of the [HeadscaleInContainer] in the given network.
func (t *HeadscaleInContainer) GetIPInNetwork(network *dockertest.Network) string {
	return t.container.GetIPInNetwork(network)
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

// cliJSON runs a command of the CLI in the container and decodes what it
// prints with --output json.
func cliJSON[T any](t *HeadscaleInContainer, command []string) (T, error) {
	return cliJSONEnv[T](t, command, nil)
}

// cliJSONEnv is cliJSON with env added to the command's environment.
func cliJSONEnv[T any](t *HeadscaleInContainer, command, env []string) (T, error) {
	var res T

	out, err := t.executeEnv(command, env)
	if err != nil {
		return res, err
	}

	err = json.Unmarshal([]byte(out), &res)
	if err != nil {
		return res, decodeFailure(command, out, err)
	}

	return res, nil
}

// decodeFailure is the error of output that is not the JSON a command
// should print, with no secret in it.
func decodeFailure(command []string, out string, err error) error {
	return dockertestutil.Redactf(err, "decoding the output of %v: %v: %q", command, err, out)
}

// CreateUser adds a new user to the Headscale instance.
func (t *HeadscaleInContainer) CreateUser(
	user string,
) (*clientv0.User, error) {
	return cliJSON[*clientv0.User](t, []string{
		binHeadscale, "users", "create", user,
		fmt.Sprintf("--email=%s@test.no", user),
		flagOutput, "json",
	})
}

// AuthKeyOptions defines options for creating an auth key.
type AuthKeyOptions struct {
	// User is the ID of the user that owns the auth key; with Tags, the
	// user that made it, who may later claim a node that joined with it.
	User *uint64
	// Reusable indicates if the key can be used multiple times
	Reusable bool
	// Ephemeral indicates if nodes registered with this key should be ephemeral
	Ephemeral bool
	// Tags own the key, and the nodes that join with it (tags-as-identity).
	Tags []string
}

var errAuthKeyOwner = errors.New("an auth key needs an owner: a user or tags")

// CreateAuthKeyWithOptions creates a new "authorisation key" owned by a user
// or by tags.
func (t *HeadscaleInContainer) CreateAuthKeyWithOptions(opts AuthKeyOptions) (*clientv0.CreatedAuthKey, error) {
	var owner string

	switch {
	case len(opts.Tags) > 0:
		owner = strings.Join(opts.Tags, ",")
	case opts.User != nil:
		owner = strconv.FormatUint(*opts.User, 10)
	default:
		return nil, errAuthKeyOwner
	}

	command := []string{
		binHeadscale, "auth", "keys", "create", owner,
		"--expiry", "24h",
		flagOutput, "json",
	}

	if opts.Reusable {
		command = append(command, "--reusable")
	}

	if opts.Ephemeral {
		command = append(command, "--ephemeral")
	}

	if len(opts.Tags) > 0 && opts.User != nil {
		// Over the socket the server records no maker of a key; through an
		// API key of the user it records the user.
		env, err := t.cliEnvAs(*opts.User)
		if err != nil {
			return nil, err
		}

		return cliJSONEnv[*clientv0.CreatedAuthKey](t, command, env)
	}

	return cliJSON[*clientv0.CreatedAuthKey](t, command)
}

// cliEnvAs is the environment that points the CLI in the container at the
// server's API, with a new API key of the user.
func (t *HeadscaleInContainer) cliEnvAs(user uint64) ([]string, error) {
	key, err := t.Execute([]string{
		binHeadscale, "api", "keys", "create", "--user", strconv.FormatUint(user, 10), "--expiry", "1h",
	})
	if err != nil {
		return nil, fmt.Errorf("creating an API key of user %d: %w", user, err)
	}

	return []string{
		"HEADSCALE_CLI_ADDRESS=" + t.GetEndpoint(),
		"HEADSCALE_CLI_API_KEY=" + strings.TrimSpace(key),
		"HEADSCALE_CLI_INSECURE=true",
	}, nil
}

// CreateAuthKey creates a new "authorisation key" for a User that can be used
// to authorise a TailscaleClient with the [HeadscaleInContainer] instance.
func (t *HeadscaleInContainer) CreateAuthKey(
	user uint64,
	reusable bool,
	ephemeral bool,
) (*clientv0.CreatedAuthKey, error) {
	return t.CreateAuthKeyWithOptions(AuthKeyOptions{
		User:      &user,
		Reusable:  reusable,
		Ephemeral: ephemeral,
	})
}

// CreateAuthKeyWithTags creates a new "authorisation key" owned by tags and
// made by user, for testing the tags-as-identity model.
func (t *HeadscaleInContainer) CreateAuthKeyWithTags(
	user uint64,
	reusable bool,
	ephemeral bool,
	tags []string,
) (*clientv0.CreatedAuthKey, error) {
	return t.CreateAuthKeyWithOptions(AuthKeyOptions{
		User:      &user,
		Reusable:  reusable,
		Ephemeral: ephemeral,
		Tags:      tags,
	})
}

// DeleteAuthKey revokes an "authorisation key" by ID.
func (t *HeadscaleInContainer) DeleteAuthKey(
	id uint64,
) error {
	_, err := t.Execute([]string{
		binHeadscale, "auth", "keys", "delete", strconv.FormatUint(id, 10), "--force",
	})
	if err != nil {
		return fmt.Errorf("executing delete auth key command: %w", err)
	}

	return nil
}

// ListNodes lists the currently registered Nodes in headscale.
// Optionally a list of usernames can be passed to get users for
// specific users.
func (t *HeadscaleInContainer) ListNodes(
	users ...string,
) ([]*clientv0.Node, error) {
	var ret []*clientv0.Node

	if len(users) == 0 {
		nodes, err := cliJSON[[]*clientv0.Node](t, []string{binHeadscale, "nodes", "list", flagOutput, "json"})
		if err != nil {
			return nil, fmt.Errorf("listing nodes: %w", err)
		}

		ret = nodes
	}

	for _, user := range users {
		nodes, err := cliJSON[[]*clientv0.Node](t, []string{binHeadscale, "nodes", "list", "--filter", "owner=" + user, flagOutput, "json"})
		if err != nil {
			return nil, fmt.Errorf("listing nodes of %s: %w", user, err)
		}

		ret = append(ret, nodes...)
	}

	slices.SortFunc(ret, func(a, b *clientv0.Node) int {
		ai, _ := strconv.ParseUint(a.Id, 10, 64)
		bi, _ := strconv.ParseUint(b.Id, 10, 64)

		return cmp.Compare(ai, bi)
	})

	return ret, nil
}

func (t *HeadscaleInContainer) DeleteNode(nodeID uint64) error {
	_, err := t.Execute([]string{
		binHeadscale, "nodes", "delete", strconv.FormatUint(nodeID, 10), "--force",
	})
	if err != nil {
		return fmt.Errorf("executing delete node command: %w", err)
	}

	return nil
}

// NodesByUser groups the nodes by the name of the user that owns them;
// tagged nodes are under "".
func (t *HeadscaleInContainer) NodesByUser() (map[string][]*clientv0.Node, error) {
	nodes, err := t.ListNodes()
	if err != nil {
		return nil, err
	}

	userMap := make(map[string][]*clientv0.Node)

	for _, node := range nodes {
		name := integrationutil.OwnerUser(node.Owner).Name
		userMap[name] = append(userMap[name], node)
	}

	return userMap, nil
}

func (t *HeadscaleInContainer) NodesByName() (map[string]*clientv0.Node, error) {
	nodes, err := t.ListNodes()
	if err != nil {
		return nil, err
	}

	var nameMap map[string]*clientv0.Node
	for _, node := range nodes {
		mak.Set(&nameMap, node.Hostname, node)
	}

	return nameMap, nil
}

// ListUsers returns a list of users from Headscale.
func (t *HeadscaleInContainer) ListUsers() ([]*clientv0.User, error) {
	return cliJSON[[]*clientv0.User](t, []string{binHeadscale, "users", "list", flagOutput, "json"})
}

// MapUsers returns a map of users from Headscale. It is keyed by the
// user name.
func (t *HeadscaleInContainer) MapUsers() (map[string]*clientv0.User, error) {
	users, err := t.ListUsers()
	if err != nil {
		return nil, err
	}

	var userMap map[string]*clientv0.User
	for _, user := range users {
		mak.Set(&userMap, user.Name, user)
	}

	return userMap, nil
}

// DeleteUser deletes a user from the Headscale instance.
func (t *HeadscaleInContainer) DeleteUser(userID uint64) error {
	_, err := t.Execute([]string{
		binHeadscale, "users", "delete", strconv.FormatUint(userID, 10), "--force",
	})
	if err != nil {
		return fmt.Errorf("executing delete user command: %w", err)
	}

	return nil
}

func (h *HeadscaleInContainer) SetPolicy(pol *policyv2.Policy) error {
	err := h.writePolicy(pol)
	if err != nil {
		return fmt.Errorf("writing policy file: %w", err)
	}

	switch h.policyMode {
	case types.PolicyModeDB:
		err := h.reloadDatabasePolicy()
		if err != nil {
			return fmt.Errorf("reloading database policy: %w", err)
		}
	case types.PolicyModeFile:
		_, err := h.Execute([]string{binHeadscale, "policy", "reload"})
		if err != nil {
			return fmt.Errorf("reloading policy file: %w", err)
		}
	default:
		panic("policy mode is not valid: " + h.policyMode)
	}

	return nil
}

func (h *HeadscaleInContainer) reloadDatabasePolicy() error {
	_, err := h.Execute([]string{binHeadscale, "policy", "set", aclPolicyPath})
	if err != nil {
		return fmt.Errorf("setting policy with db command: %w", err)
	}

	return nil
}

func (h *HeadscaleInContainer) writePolicy(pol *policyv2.Policy) error {
	pBytes, err := json.Marshal(pol)
	if err != nil {
		return fmt.Errorf("marshalling policy: %w", err)
	}

	err = h.WriteFile(aclPolicyPath, pBytes)
	if err != nil {
		return fmt.Errorf("writing policy to headscale container: %w", err)
	}

	return nil
}

func (h *HeadscaleInContainer) PID() (int, error) {
	// Use pidof to find the headscale process, which is more reliable than grep
	// as it only looks for the actual binary name, not processes that contain
	// "headscale" in their command line (like the dlv debugger).
	output, err := h.Execute([]string{"pidof", binHeadscale})
	if err != nil {
		// pidof returns exit code 1 when no process is found
		return 0, os.ErrNotExist
	}

	// pidof returns space-separated PIDs on a single line
	pidStrs := strings.Fields(strings.TrimSpace(output))
	if len(pidStrs) == 0 {
		return 0, os.ErrNotExist
	}

	pids := make([]int, 0, len(pidStrs))
	for _, pidStr := range pidStrs {
		pidInt, err := strconv.Atoi(pidStr)
		if err != nil {
			return 0, fmt.Errorf("parsing PID %q: %w", pidStr, err)
		}
		// We dont care about the root pid for the container
		if pidInt == 1 {
			continue
		}

		pids = append(pids, pidInt)
	}

	switch len(pids) {
	case 0:
		return 0, os.ErrNotExist
	case 1:
		return pids[0], nil
	default:
		// If we still have multiple PIDs, return the first one as a fallback
		// This can happen in edge cases during startup/shutdown
		return pids[0], nil
	}
}

// Reload sends a SIGHUP to the headscale process to reload internals,
// for example Policy from file.
func (h *HeadscaleInContainer) Reload() error {
	pid, err := h.PID()
	if err != nil {
		return fmt.Errorf("getting headscale PID: %w", err)
	}

	_, err = h.Execute([]string{"kill", "-HUP", strconv.Itoa(pid)})
	if err != nil {
		return fmt.Errorf("reloading headscale with HUP: %w", err)
	}

	return nil
}

// Restart restarts the headscale container. The on-disk database and keys
// persist across the restart, but all in-memory state is dropped — including
// the bounded cache of pending authentication sessions. This reproduces a
// control-plane restart, one of the real-world cases where a pending SSH-check
// auth session is lost.
func (h *HeadscaleInContainer) Restart() error {
	err := h.pool.Client.RestartContainer(h.container.Container.ID, 30)
	if err != nil {
		return fmt.Errorf("restarting headscale container %s: %w", h.hostname, err)
	}

	return h.WaitForRunning()
}

// ApproveRoutes sets the approved routes of a node; none clears them.
func (t *HeadscaleInContainer) ApproveRoutes(id uint64, routes []netip.Prefix) (*clientv0.Node, error) {
	command := []string{binHeadscale, "nodes", "routes", "clear", strconv.FormatUint(id, 10), flagOutput, "json"}
	if len(routes) > 0 {
		command = []string{
			binHeadscale, "nodes", "routes", "set", strconv.FormatUint(id, 10),
			strings.Join(util.PrefixesToString(routes), ","),
			flagOutput, "json",
		}
	}

	node, err := cliJSON[*clientv0.Node](t, command)
	if err != nil {
		return nil, fmt.Errorf("approving routes (node %d, routes %v): %w", id, routes, err)
	}

	return node, nil
}

// SetNodeTags sets tags on a node via the headscale CLI, as the Tailscale
// admin console does through the API. --force answers the question that
// tagging a user-owned node asks.
func (t *HeadscaleInContainer) SetNodeTags(nodeID uint64, tags []string) error {
	_, err := t.Execute([]string{
		binHeadscale, "nodes", "tags", "set", strconv.FormatUint(nodeID, 10), strings.Join(tags, ","), "--force",
	})
	if err != nil {
		return fmt.Errorf("executing set tags command (node %d, tags %v): %w", nodeID, tags, err)
	}

	return nil
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
	pid, err := t.Execute([]string{"pidof", binHeadscale})
	if err != nil {
		return err
	}

	_, err = t.Execute([]string{"kill", "-2", strings.Trim(pid, "'\n")})
	if err != nil {
		return err
	}

	return nil
}

func (t *HeadscaleInContainer) GetAllMapReponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	return t.debugJSON[map[types.NodeID][]tailcfg.MapResponse]("mapresponses")
}

// PrimaryRoutes fetches the primary routes from the debug endpoint.
func (t *HeadscaleInContainer) PrimaryRoutes() (*types.DebugRoutes, error) {
	return t.debugJSON[*types.DebugRoutes]("routes")
}

// DebugBatcher fetches the batcher debug information from the debug endpoint.
func (t *HeadscaleInContainer) DebugBatcher() (*hscontrol.DebugBatcherInfo, error) {
	return t.debugJSON[*hscontrol.DebugBatcherInfo]("batcher")
}

// DebugNodeStore fetches the [state.NodeStore] data from the debug endpoint.
func (t *HeadscaleInContainer) DebugNodeStore() (map[types.NodeID]types.Node, error) {
	return t.debugJSON[map[types.NodeID]types.Node]("nodestore")
}

// DebugFilter fetches the current filter rules from the debug endpoint.
func (t *HeadscaleInContainer) DebugFilter() ([]tailcfg.FilterRule, error) {
	return t.debugJSON[[]tailcfg.FilterRule]("filter")
}

// debugJSON fetches and decodes a JSON-returning debug endpoint by name.
func (t *HeadscaleInContainer) debugJSON[T any](endpoint string) (T, error) {
	var res T

	// Execute curl inside the container to access the debug endpoint locally
	command := []string{
		"curl", "-s", "-H", acceptJSON, "http://localhost:9090/debug/" + endpoint,
	}

	result, err := t.Execute(command)
	if err != nil {
		return res, fmt.Errorf("fetching %s from debug endpoint: %w", endpoint, err)
	}

	if err := json.Unmarshal([]byte(result), &res); err != nil { //nolint:noinlineerr
		return res, fmt.Errorf("decoding %s response: %w", endpoint, err)
	}

	return res, nil
}

// DebugPolicy fetches the current policy from the debug endpoint.
func (t *HeadscaleInContainer) DebugPolicy() (string, error) {
	// Execute curl inside the container to access the debug endpoint locally
	command := []string{
		"curl", "-s", "http://localhost:9090/debug/policy",
	}

	result, err := t.Execute(command)
	if err != nil {
		return "", fmt.Errorf("fetching policy from debug endpoint: %w", err)
	}

	return result, nil
}
