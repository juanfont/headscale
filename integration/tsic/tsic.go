package tsic

import (
	"archive/tar"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/netip"
	"net/url"
	"os"
	"reflect"
	"runtime/debug"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/ipn"
	"tailscale.com/ipn/ipnstate"
	"tailscale.com/ipn/store/mem"
	"tailscale.com/net/netcheck"
	"tailscale.com/paths"
	"tailscale.com/types/key"
	"tailscale.com/types/netmap"
	"tailscale.com/util/multierr"
	"tailscale.com/wgengine/filter"
)

const (
	tsicHashLength       = 6
	defaultPingTimeout   = 200 * time.Millisecond
	defaultPingCount     = 5
	dockerContextPath    = "../."
	caCertRoot           = "/usr/local/share/ca-certificates"
	dockerExecuteTimeout = 60 * time.Second
)

var (
	errTailscalePingFailed             = errors.New("ping failed")
	errTailscalePingNotDERP            = errors.New("ping not via DERP")
	errTailscaleNotLoggedIn            = errors.New("tailscale not logged in")
	errTailscaleWrongPeerCount         = errors.New("wrong peer count")
	errTailscaleCannotUpWithoutAuthkey = errors.New("cannot up without authkey")
	errTailscaleNotConnected           = errors.New("tailscale not connected")
	errTailscaledNotReadyForLogin      = errors.New("tailscaled not ready for login")
	errInvalidClientConfig             = errors.New("verifiably invalid client config requested")
	errInvalidTailscaleImageFormat     = errors.New("invalid HEADSCALE_INTEGRATION_TAILSCALE_IMAGE format, expected repository:tag")
	errTailscaleImageRequiredInCI      = errors.New("HEADSCALE_INTEGRATION_TAILSCALE_IMAGE must be set in CI for HEAD version")
	errContainerNotInitialized         = errors.New("container not initialized")
	errFQDNNotYetAvailable             = errors.New("FQDN not yet available")
)

const (
	VersionHead = "head"
)

func errTailscaleStatus(hostname string, err error) error {
	return fmt.Errorf("%s failed to fetch tailscale status: %w", hostname, err)
}

// TailscaleInContainer is an implementation of TailscaleClient which
// sets up a Tailscale instance inside a container.
type TailscaleInContainer struct {
	version  string
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	// "cache"
	ips  []netip.Addr
	fqdn string

	// optional config
	caCerts           [][]byte
	headscaleHostname string
	withWebsocketDERP bool
	withSSH           bool
	withTags          []string
	withEntrypoint    []string
	withExtraHosts    []string
	workdir           string
	netfilter         string
	extraLoginArgs    []string
	withAcceptRoutes  bool
	withPackages      []string // Alpine packages to install at container start
	withWebserverPort int      // Port for built-in HTTP server (0 = disabled)
	withExtraCommands []string // Extra shell commands to run before tailscaled

	// build options, solely for HEAD
	buildConfig TailscaleInContainerBuildConfig
}

type TailscaleInContainerBuildConfig struct {
	tags []string
}

// Option represent optional settings that can be given to a
// Tailscale instance.
type Option = func(c *TailscaleInContainer)

// WithCACert adds it to the trusted surtificate of the Tailscale container.
func WithCACert(cert []byte) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.caCerts = append(tsic.caCerts, cert)
	}
}

// WithNetwork sets the Docker container network to use with
// the Tailscale instance.
func WithNetwork(network *dockertest.Network) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.network = network
	}
}

// WithHeadscaleName set the name of the headscale instance,
// mostly useful in combination with TLS and WithCACert.
func WithHeadscaleName(hsName string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.headscaleHostname = hsName
	}
}

// WithTags associates the given tags to the Tailscale instance.
func WithTags(tags []string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withTags = tags
	}
}

// WithWebsocketDERP toggles a development knob to
// force enable DERP connection through the new websocket protocol.
func WithWebsocketDERP(enabled bool) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withWebsocketDERP = enabled
	}
}

// WithSSH enables SSH for the Tailscale instance.
func WithSSH() Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withSSH = true
	}
}

// WithDockerWorkdir allows the docker working directory to be set.
func WithDockerWorkdir(dir string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.workdir = dir
	}
}

func WithExtraHosts(hosts []string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withExtraHosts = hosts
	}
}

// WithDockerEntrypoint allows the docker entrypoint of the container
// to be overridden. This is a dangerous option which can make
// the container not work as intended as a typo might prevent
// tailscaled and other processes from starting.
// Use with caution.
func WithDockerEntrypoint(args []string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withEntrypoint = args
	}
}

// WithNetfilter configures Tailscales parameter --netfilter-mode
// allowing us to turn of modifying ip[6]tables/nftables.
// It takes: "on", "off", "nodivert".
func WithNetfilter(state string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.netfilter = state
	}
}

// WithBuildTag adds an additional value to the `-tags=` parameter
// of the Go compiler, allowing callers to customize the Tailscale client build.
// This option is only meaningful when invoked on **HEAD** versions of the client.
// Attempts to use it with any other version is a bug in the calling code.
func WithBuildTag(tag string) Option {
	return func(tsic *TailscaleInContainer) {
		if tsic.version != VersionHead {
			panic(errInvalidClientConfig)
		}

		tsic.buildConfig.tags = append(
			tsic.buildConfig.tags, tag,
		)
	}
}

// WithExtraLoginArgs adds additional arguments to the `tailscale up` command
// as part of the Login function.
func WithExtraLoginArgs(args []string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.extraLoginArgs = append(tsic.extraLoginArgs, args...)
	}
}

// WithAcceptRoutes tells the node to accept incoming routes.
func WithAcceptRoutes() Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withAcceptRoutes = true
	}
}

// WithPackages specifies Alpine packages to install when the container starts.
// This requires internet access and uses `apk add`. Common packages:
// - "python3" for HTTP server
// - "curl" for HTTP client
// - "bind-tools" for dig command
// - "iptables", "ip6tables" for firewall rules
// Note: Tests using this option require internet access and cannot use
// the built-in DERP server in offline mode.
func WithPackages(packages ...string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withPackages = append(tsic.withPackages, packages...)
	}
}

// WithWebserver starts a Python HTTP server on the specified port
// alongside tailscaled. This is useful for testing subnet routing
// and ACL connectivity. Automatically adds "python3" to packages if needed.
// The server serves files from the root directory (/).
func WithWebserver(port int) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withWebserverPort = port
	}
}

// WithExtraCommands adds extra shell commands to run before tailscaled starts.
// Commands are run after package installation and CA certificate updates.
func WithExtraCommands(commands ...string) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.withExtraCommands = append(tsic.withExtraCommands, commands...)
	}
}

// buildEntrypoint constructs the container entrypoint command based on
// configured options (packages, webserver, etc.).
func (t *TailscaleInContainer) buildEntrypoint() []string {
	var commands []string

	// Wait for network to be ready
	commands = append(commands, "while ! ip route show default >/dev/null 2>&1; do sleep 0.1; done")

	// If CA certs are configured, wait for them to be written by the Go code
	// (certs are written after container start via tsic.WriteFile)
	if len(t.caCerts) > 0 {
		commands = append(commands,
			fmt.Sprintf("while [ ! -f %s/user-0.crt ]; do sleep 0.1; done", caCertRoot))
	}

	// Install packages if requested (requires internet access)
	packages := t.withPackages
	if t.withWebserverPort > 0 && !slices.Contains(packages, "python3") {
		packages = append(packages, "python3")
	}

	if len(packages) > 0 {
		commands = append(commands, "apk add --no-cache "+strings.Join(packages, " "))
	}

	// Update CA certificates
	commands = append(commands, "update-ca-certificates")

	// Run extra commands if any
	commands = append(commands, t.withExtraCommands...)

	// Start webserver in background if requested
	// Use subshell to avoid & interfering with command joining
	if t.withWebserverPort > 0 {
		commands = append(commands,
			fmt.Sprintf("(python3 -m http.server --bind :: %d &)", t.withWebserverPort))
	}

	// Start tailscaled (must be last as it's the foreground process)
	commands = append(commands, "tailscaled --tun=tsdev --verbose=10")

	return []string{"/bin/sh", "-c", strings.Join(commands, " ; ")}
}

// New returns a new TailscaleInContainer instance.
func New(
	pool *dockertest.Pool,
	version string,
	opts ...Option,
) (*TailscaleInContainer, error) {
	hash, err := util.GenerateRandomStringDNSSafe(tsicHashLength)
	if err != nil {
		return nil, err
	}

	// Include run ID in hostname for easier identification of which test run owns this container
	runID := dockertestutil.GetIntegrationRunID()

	var hostname string

	if runID != "" {
		// Use last 6 chars of run ID (the random hash part) for brevity
		runIDShort := runID[len(runID)-6:]
		hostname = fmt.Sprintf("ts-%s-%s-%s", runIDShort, strings.ReplaceAll(version, ".", "-"), hash)
	} else {
		hostname = fmt.Sprintf("ts-%s-%s", strings.ReplaceAll(version, ".", "-"), hash)
	}

	tsic := &TailscaleInContainer{
		version:  version,
		hostname: hostname,

		pool: pool,
	}

	for _, opt := range opts {
		opt(tsic)
	}

	// Build the entrypoint command dynamically based on options.
	// Only build if no custom entrypoint was provided via WithDockerEntrypoint.
	if len(tsic.withEntrypoint) == 0 {
		tsic.withEntrypoint = tsic.buildEntrypoint()
	}

	if tsic.network == nil {
		return nil, fmt.Errorf("no network set, called from: \n%s", string(debug.Stack()))
	}

	tailscaleOptions := &dockertest.RunOptions{
		Name:       hostname,
		Networks:   []*dockertest.Network{tsic.network},
		Entrypoint: tsic.withEntrypoint,
		ExtraHosts: tsic.withExtraHosts,
		Env:        []string{},
	}

	if tsic.withWebsocketDERP {
		if version != VersionHead {
			return tsic, errInvalidClientConfig
		}

		WithBuildTag("ts_debug_websockets")(tsic)

		tailscaleOptions.Env = append(
			tailscaleOptions.Env,
			fmt.Sprintf("TS_DEBUG_DERP_WS_CLIENT=%t", tsic.withWebsocketDERP),
		)
	}

	tailscaleOptions.ExtraHosts = append(tailscaleOptions.ExtraHosts,
		"host.docker.internal:host-gateway")

	if tsic.workdir != "" {
		tailscaleOptions.WorkingDir = tsic.workdir
	}

	// dockertest isn't very good at handling containers that has already
	// been created, this is an attempt to make sure this container isn't
	// present.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	// Add integration test labels if running under hi tool
	dockertestutil.DockerAddIntegrationLabels(tailscaleOptions, "tailscale")

	var container *dockertest.Resource

	if version != VersionHead {
		// build options are not meaningful with pre-existing images,
		// let's not lead anyone astray by pretending otherwise.
		defaultBuildConfig := TailscaleInContainerBuildConfig{}

		hasBuildConfig := !reflect.DeepEqual(defaultBuildConfig, tsic.buildConfig)
		if hasBuildConfig {
			return tsic, errInvalidClientConfig
		}
	}

	switch version {
	case VersionHead:
		// Check if a pre-built image is available via environment variable
		prebuiltImage := os.Getenv("HEADSCALE_INTEGRATION_TAILSCALE_IMAGE")

		// If custom build tags are required (e.g., for websocket DERP), we cannot use
		// the pre-built image as it won't have the necessary code compiled in.
		hasBuildTags := len(tsic.buildConfig.tags) > 0
		if hasBuildTags && prebuiltImage != "" {
			log.Printf("Ignoring pre-built image %s because custom build tags are required: %v",
				prebuiltImage, tsic.buildConfig.tags)
			prebuiltImage = ""
		}

		if prebuiltImage != "" {
			log.Printf("Using pre-built tailscale image: %s", prebuiltImage)

			// Parse image into repository and tag
			repo, tag, ok := strings.Cut(prebuiltImage, ":")
			if !ok {
				return nil, errInvalidTailscaleImageFormat
			}

			tailscaleOptions.Repository = repo
			tailscaleOptions.Tag = tag

			container, err = pool.RunWithOptions(
				tailscaleOptions,
				dockertestutil.DockerRestartPolicy,
				dockertestutil.DockerAllowLocalIPv6,
				dockertestutil.DockerAllowNetworkAdministration,
				dockertestutil.DockerMemoryLimit,
			)
			if err != nil {
				return nil, fmt.Errorf("could not run pre-built tailscale container %q: %w", prebuiltImage, err)
			}
		} else if util.IsCI() && !hasBuildTags {
			// In CI, we require a pre-built image unless custom build tags are needed
			return nil, errTailscaleImageRequiredInCI
		} else {
			buildOptions := &dockertest.BuildOptions{
				Dockerfile: "Dockerfile.tailscale-HEAD",
				ContextDir: dockerContextPath,
				BuildArgs:  []docker.BuildArg{},
			}

			buildTags := strings.Join(tsic.buildConfig.tags, ",")
			if len(buildTags) > 0 {
				buildOptions.BuildArgs = append(
					buildOptions.BuildArgs,
					docker.BuildArg{
						Name:  "BUILD_TAGS",
						Value: buildTags,
					},
				)
			}

			container, err = pool.BuildAndRunWithBuildOptions(
				buildOptions,
				tailscaleOptions,
				dockertestutil.DockerRestartPolicy,
				dockertestutil.DockerAllowLocalIPv6,
				dockertestutil.DockerAllowNetworkAdministration,
				dockertestutil.DockerMemoryLimit,
			)
			if err != nil {
				// Try to get more detailed build output
				log.Printf("Docker build failed for %s, attempting to get detailed output...", hostname)

				buildOutput, buildErr := dockertestutil.RunDockerBuildForDiagnostics(dockerContextPath, "Dockerfile.tailscale-HEAD")

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
					return nil, fmt.Errorf(
						"%s could not start tailscale container (version: %s): %w\n\nDocker build failed. Last %d lines of output:\n%s",
						hostname,
						version,
						err,
						maxLines,
						relevantOutput,
					)
				}

				if buildOutput != "" {
					// Build succeeded on retry but container creation still failed
					return nil, fmt.Errorf(
						"%s could not start tailscale container (version: %s): %w\n\nDocker build succeeded on retry, but container creation failed. Last %d lines of build output:\n%s",
						hostname,
						version,
						err,
						maxLines,
						relevantOutput,
					)
				}

				// No output at all - diagnostic build command may have failed
				return nil, fmt.Errorf(
					"%s could not start tailscale container (version: %s): %w\n\nUnable to get diagnostic build output (command may have failed silently)",
					hostname,
					version,
					err,
				)
			}
		}
	case "unstable":
		tailscaleOptions.Repository = "tailscale/tailscale"
		tailscaleOptions.Tag = version

		container, err = pool.RunWithOptions(
			tailscaleOptions,
			dockertestutil.DockerRestartPolicy,
			dockertestutil.DockerAllowLocalIPv6,
			dockertestutil.DockerAllowNetworkAdministration,
			dockertestutil.DockerMemoryLimit,
		)
		if err != nil {
			log.Printf("Docker run failed for %s (unstable), error: %v", hostname, err)
		}
	default:
		tailscaleOptions.Repository = "tailscale/tailscale"
		tailscaleOptions.Tag = "v" + version

		container, err = pool.RunWithOptions(
			tailscaleOptions,
			dockertestutil.DockerRestartPolicy,
			dockertestutil.DockerAllowLocalIPv6,
			dockertestutil.DockerAllowNetworkAdministration,
			dockertestutil.DockerMemoryLimit,
		)
		if err != nil {
			log.Printf("Docker run failed for %s (version: v%s), error: %v", hostname, version, err)
		}
	}

	if err != nil {
		return nil, fmt.Errorf(
			"%s could not start tailscale container (version: %s): %w",
			hostname,
			version,
			err,
		)
	}

	log.Printf("Created %s container\n", hostname)

	tsic.container = container

	for i, cert := range tsic.caCerts {
		err = tsic.WriteFile(fmt.Sprintf("%s/user-%d.crt", caCertRoot, i), cert)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS certificate to container: %w", err)
		}
	}

	return tsic, nil
}

// Shutdown stops and cleans up the Tailscale container.
func (t *TailscaleInContainer) Shutdown() (string, string, error) {
	stdoutPath, stderrPath, err := t.SaveLog("/tmp/control")
	if err != nil {
		log.Printf(
			"Failed to save log from %s: %s",
			t.hostname,
			fmt.Errorf("failed to save log: %w", err),
		)
	}

	return stdoutPath, stderrPath, t.pool.Purge(t.container)
}

// Hostname returns the hostname of the Tailscale instance.
func (t *TailscaleInContainer) Hostname() string {
	return t.hostname
}

// Version returns the running Tailscale version of the instance.
func (t *TailscaleInContainer) Version() string {
	return t.version
}

// ID returns the Docker container ID of the TailscaleInContainer
// instance.
func (t *TailscaleInContainer) ContainerID() string {
	return t.container.Container.ID
}

// Execute runs a command inside the Tailscale container and returns the
// result of stdout as a string.
func (t *TailscaleInContainer) Execute(
	command []string,
	options ...dockertestutil.ExecuteCommandOption,
) (string, string, error) {
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		t.container,
		command,
		[]string{},
		options...,
	)
	if err != nil {
		// log.Printf("command issued: %s", strings.Join(command, " "))
		// log.Printf("command stderr: %s\n", stderr)
		if stdout != "" {
			log.Printf("command stdout: %s\n", stdout)
		}

		if strings.Contains(stderr, "NeedsLogin") {
			return stdout, stderr, errTailscaleNotLoggedIn
		}

		return stdout, stderr, err
	}

	return stdout, stderr, nil
}

// Retrieve container logs.
func (t *TailscaleInContainer) Logs(stdout, stderr io.Writer) error {
	return dockertestutil.WriteLog(
		t.pool,
		t.container,
		stdout, stderr,
	)
}

func (t *TailscaleInContainer) buildLoginCommand(
	loginServer, authKey string,
) []string {
	command := []string{
		"tailscale",
		"up",
		"--login-server=" + loginServer,
		"--hostname=" + t.hostname,
		fmt.Sprintf("--accept-routes=%t", t.withAcceptRoutes),
	}

	if authKey != "" {
		command = append(command, "--authkey="+authKey)
	}

	if t.extraLoginArgs != nil {
		command = append(command, t.extraLoginArgs...)
	}

	if t.withSSH {
		command = append(command, "--ssh")
	}

	if t.netfilter != "" {
		command = append(command, "--netfilter-mode="+t.netfilter)
	}

	if len(t.withTags) > 0 {
		command = append(command,
			"--advertise-tags="+strings.Join(t.withTags, ","),
		)
	}

	return command
}

// Login runs the login routine on the given Tailscale instance.
// This login mechanism uses the authorised key for authentication.
func (t *TailscaleInContainer) Login(
	loginServer, authKey string,
) error {
	command := t.buildLoginCommand(loginServer, authKey)

	if _, _, err := t.Execute(command, dockertestutil.ExecuteCommandTimeout(dockerExecuteTimeout)); err != nil {
		return fmt.Errorf(
			"%s failed to join tailscale client (%s): %w",
			t.hostname,
			strings.Join(command, " "),
			err,
		)
	}

	return nil
}

// Up runs the login routine on the given Tailscale instance.
// This login mechanism uses web + command line flow for authentication.
func (t *TailscaleInContainer) LoginWithURL(
	loginServer string,
) (loginURL *url.URL, err error) {
	command := t.buildLoginCommand(loginServer, "")

	stdout, stderr, err := t.Execute(command)
	if errors.Is(err, errTailscaleNotLoggedIn) {
		return nil, errTailscaleCannotUpWithoutAuthkey
	}

	defer func() {
		if err != nil {
			log.Printf("join command: %q", strings.Join(command, " "))
		}
	}()

	loginURL, err = util.ParseLoginURLFromCLILogin(stdout + stderr)
	if err != nil {
		return nil, err
	}

	return loginURL, nil
}

// Logout runs the logout routine on the given Tailscale instance.
func (t *TailscaleInContainer) Logout() error {
	stdout, stderr, err := t.Execute([]string{"tailscale", "logout"})
	if err != nil {
		return err
	}

	stdout, stderr, _ = t.Execute([]string{"tailscale", "status"})
	if !strings.Contains(stdout+stderr, "Logged out.") {
		return fmt.Errorf("failed to logout, stdout: %s, stderr: %s", stdout, stderr)
	}

	return t.waitForBackendState("NeedsLogin", integrationutil.PeerSyncTimeout())
}

// Restart restarts the Tailscale container using Docker API.
// This simulates a container restart (e.g., docker restart or Kubernetes pod restart).
// The container's entrypoint will re-execute, which typically includes running
// "tailscale up" with any auth keys stored in environment variables.
func (t *TailscaleInContainer) Restart() error {
	if t.container == nil {
		return errContainerNotInitialized
	}

	// Use Docker API to restart the container
	err := t.pool.Client.RestartContainer(t.container.Container.ID, 30)
	if err != nil {
		return fmt.Errorf("failed to restart container %s: %w", t.hostname, err)
	}

	// Wait for the container to be back up and tailscaled to be ready
	// We use exponential backoff to poll until we can successfully execute a command
	_, err = backoff.Retry(context.Background(), func() (struct{}, error) {
		// Try to execute a simple command to verify the container is responsive
		_, _, err := t.Execute([]string{"tailscale", "version"}, dockertestutil.ExecuteCommandTimeout(5*time.Second))
		if err != nil {
			return struct{}{}, fmt.Errorf("container not ready: %w", err)
		}

		return struct{}{}, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxElapsedTime(30*time.Second))
	if err != nil {
		return fmt.Errorf("timeout waiting for container %s to restart and become ready: %w", t.hostname, err)
	}

	return nil
}

// Helper that runs `tailscale up` with no arguments.
func (t *TailscaleInContainer) Up() error {
	command := []string{
		"tailscale",
		"up",
	}

	if _, _, err := t.Execute(command, dockertestutil.ExecuteCommandTimeout(dockerExecuteTimeout)); err != nil {
		return fmt.Errorf(
			"%s failed to bring tailscale client up (%s): %w",
			t.hostname,
			strings.Join(command, " "),
			err,
		)
	}

	return nil
}

// Helper that runs `tailscale down` with no arguments.
func (t *TailscaleInContainer) Down() error {
	command := []string{
		"tailscale",
		"down",
	}

	if _, _, err := t.Execute(command, dockertestutil.ExecuteCommandTimeout(dockerExecuteTimeout)); err != nil {
		return fmt.Errorf(
			"%s failed to bring tailscale client down (%s): %w",
			t.hostname,
			strings.Join(command, " "),
			err,
		)
	}

	return nil
}

// IPs returns the netip.Addr of the Tailscale instance.
func (t *TailscaleInContainer) IPs() ([]netip.Addr, error) {
	if len(t.ips) != 0 {
		return t.ips, nil
	}

	// Retry with exponential backoff to handle eventual consistency
	ips, err := backoff.Retry(context.Background(), func() ([]netip.Addr, error) {
		command := []string{
			"tailscale",
			"ip",
		}

		result, _, err := t.Execute(command)
		if err != nil {
			return nil, fmt.Errorf("%s failed to get IPs: %w", t.hostname, err)
		}

		ips := make([]netip.Addr, 0)

		for address := range strings.SplitSeq(result, "\n") {
			address = strings.TrimSuffix(address, "\n")
			if len(address) < 1 {
				continue
			}

			ip, err := netip.ParseAddr(address)
			if err != nil {
				return nil, fmt.Errorf("failed to parse IP %s: %w", address, err)
			}

			ips = append(ips, ip)
		}

		if len(ips) == 0 {
			return nil, fmt.Errorf("no IPs returned yet for %s", t.hostname)
		}

		return ips, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxElapsedTime(10*time.Second))
	if err != nil {
		return nil, fmt.Errorf("failed to get IPs for %s after retries: %w", t.hostname, err)
	}

	return ips, nil
}

func (t *TailscaleInContainer) MustIPs() []netip.Addr {
	ips, err := t.IPs()
	if err != nil {
		panic(err)
	}

	return ips
}

// IPv4 returns the IPv4 address of the Tailscale instance.
func (t *TailscaleInContainer) IPv4() (netip.Addr, error) {
	ips, err := t.IPs()
	if err != nil {
		return netip.Addr{}, err
	}

	for _, ip := range ips {
		if ip.Is4() {
			return ip, nil
		}
	}

	return netip.Addr{}, fmt.Errorf("no IPv4 address found for %s", t.hostname)
}

func (t *TailscaleInContainer) MustIPv4() netip.Addr {
	ip, err := t.IPv4()
	if err != nil {
		panic(err)
	}

	return ip
}

func (t *TailscaleInContainer) MustIPv6() netip.Addr {
	for _, ip := range t.MustIPs() {
		if ip.Is6() {
			return ip
		}
	}

	panic("no ipv6 found")
}

// Status returns the ipnstate.Status of the Tailscale instance.
func (t *TailscaleInContainer) Status(save ...bool) (*ipnstate.Status, error) {
	command := []string{
		"tailscale",
		"status",
		"--json",
	}

	result, _, err := t.Execute(command)
	if err != nil {
		return nil, fmt.Errorf("failed to execute tailscale status command: %w", err)
	}

	var status ipnstate.Status

	err = json.Unmarshal([]byte(result), &status)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tailscale status: %w", err)
	}

	err = os.WriteFile(fmt.Sprintf("/tmp/control/%s_status.json", t.hostname), []byte(result), 0o755)
	if err != nil {
		return nil, fmt.Errorf("status netmap to /tmp/control: %w", err)
	}

	return &status, err
}

// MustStatus returns the ipnstate.Status of the Tailscale instance.
func (t *TailscaleInContainer) MustStatus() *ipnstate.Status {
	status, err := t.Status()
	if err != nil {
		panic(err)
	}

	return status
}

// MustID returns the ID of the Tailscale instance.
func (t *TailscaleInContainer) MustID() types.NodeID {
	status, err := t.Status()
	if err != nil {
		panic(err)
	}

	id, err := strconv.ParseUint(string(status.Self.ID), 10, 64)
	if err != nil {
		panic(fmt.Sprintf("failed to parse ID: %s", err))
	}

	return types.NodeID(id)
}

// Netmap returns the current Netmap (netmap.NetworkMap) of the Tailscale instance.
// Only works with Tailscale 1.56 and newer.
// Panics if version is lower then minimum.
func (t *TailscaleInContainer) Netmap() (*netmap.NetworkMap, error) {
	if !util.TailscaleVersionNewerOrEqual("1.56", t.version) {
		panic("tsic.Netmap() called with unsupported version: " + t.version)
	}

	command := []string{
		"tailscale",
		"debug",
		"netmap",
	}

	result, stderr, err := t.Execute(command)
	if err != nil {
		fmt.Printf("stderr: %s\n", stderr)
		return nil, fmt.Errorf("failed to execute tailscale debug netmap command: %w", err)
	}

	var nm netmap.NetworkMap

	err = json.Unmarshal([]byte(result), &nm)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tailscale netmap: %w", err)
	}

	err = os.WriteFile(fmt.Sprintf("/tmp/control/%s_netmap.json", t.hostname), []byte(result), 0o755)
	if err != nil {
		return nil, fmt.Errorf("saving netmap to /tmp/control: %w", err)
	}

	return &nm, err
}

// Netmap returns the current Netmap (netmap.NetworkMap) of the Tailscale instance.
// This implementation is based on getting the netmap from `tailscale debug watch-ipn`
// as there seem to be some weirdness omitting endpoint and DERP info if we use
// Patch updates.
// This implementation works on all supported versions.
// func (t *TailscaleInContainer) Netmap() (*netmap.NetworkMap, error) {
// 	// watch-ipn will only give an update if something is happening,
// 	// since we send keep alives, the worst case for this should be
// 	// 1 minute, but set a slightly more conservative time.
// 	ctx, _ := context.WithTimeout(context.Background(), 3*time.Minute)

// 	notify, err := t.watchIPN(ctx)
// 	if err != nil {
// 		return nil, err
// 	}

// 	if notify.NetMap == nil {
// 		return nil, fmt.Errorf("no netmap present in ipn.Notify")
// 	}

// 	return notify.NetMap, nil
// }

// watchIPN watches `tailscale debug watch-ipn` for a ipn.Notify object until
// it gets one that has a netmap.NetworkMap.
func (t *TailscaleInContainer) watchIPN(ctx context.Context) (*ipn.Notify, error) {
	pr, pw := io.Pipe()

	type result struct {
		notify *ipn.Notify
		err    error
	}

	resultChan := make(chan result, 1)

	// There is no good way to kill the goroutine with watch-ipn,
	// so make a nice func to send a kill command to issue when
	// we are done.
	killWatcher := func() {
		stdout, stderr, err := t.Execute([]string{
			"/bin/sh", "-c", `kill $(ps aux | grep "tailscale debug watch-ipn" | grep -v grep | awk '{print $1}') || true`,
		})
		if err != nil {
			log.Printf("failed to kill tailscale watcher, \nstdout: %s\nstderr: %s\nerr: %s", stdout, stderr, err)
		}
	}

	go func() {
		_, _ = t.container.Exec(
			// Prior to 1.56, the initial "Connected." message was printed to stdout,
			// filter out with grep.
			[]string{"/bin/sh", "-c", `tailscale debug watch-ipn | grep -v "Connected."`},
			dockertest.ExecOptions{
				// The interesting output is sent to stdout, so ignore stderr.
				StdOut: pw,
				// StdErr: pw,
			},
		)
	}()

	go func() {
		decoder := json.NewDecoder(pr)
		for decoder.More() {
			var notify ipn.Notify

			err := decoder.Decode(&notify)
			if err != nil {
				resultChan <- result{nil, fmt.Errorf("parse notify: %w", err)}
			}

			if notify.NetMap != nil {
				resultChan <- result{&notify, nil}
			}
		}
	}()

	select {
	case <-ctx.Done():
		killWatcher()

		return nil, ctx.Err()

	case result := <-resultChan:
		killWatcher()

		if result.err != nil {
			return nil, result.err
		}

		return result.notify, nil
	}
}

func (t *TailscaleInContainer) DebugDERPRegion(region string) (*ipnstate.DebugDERPRegionReport, error) {
	if !util.TailscaleVersionNewerOrEqual("1.34", t.version) {
		panic("tsic.DebugDERPRegion() called with unsupported version: " + t.version)
	}

	command := []string{
		"tailscale",
		"debug",
		"derp",
		region,
	}

	result, stderr, err := t.Execute(command)
	if err != nil {
		fmt.Printf("stderr: %s\n", stderr) // nolint

		return nil, fmt.Errorf("failed to execute tailscale debug derp command: %w", err)
	}

	var report ipnstate.DebugDERPRegionReport

	err = json.Unmarshal([]byte(result), &report)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tailscale derp region report: %w", err)
	}

	return &report, err
}

// Netcheck returns the current Netcheck Report (netcheck.Report) of the Tailscale instance.
func (t *TailscaleInContainer) Netcheck() (*netcheck.Report, error) {
	command := []string{
		"tailscale",
		"netcheck",
		"--format=json",
	}

	result, stderr, err := t.Execute(command)
	if err != nil {
		fmt.Printf("stderr: %s\n", stderr)
		return nil, fmt.Errorf("failed to execute tailscale debug netcheck command: %w", err)
	}

	var nm netcheck.Report

	err = json.Unmarshal([]byte(result), &nm)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal tailscale netcheck: %w", err)
	}

	return &nm, err
}

// FQDN returns the FQDN as a string of the Tailscale instance.
func (t *TailscaleInContainer) FQDN() (string, error) {
	if t.fqdn != "" {
		return t.fqdn, nil
	}

	// Retry with exponential backoff to handle eventual consistency
	fqdn, err := backoff.Retry(context.Background(), func() (string, error) {
		status, err := t.Status()
		if err != nil {
			return "", fmt.Errorf("failed to get status: %w", err)
		}

		if status.Self.DNSName == "" {
			return "", errFQDNNotYetAvailable
		}

		return status.Self.DNSName, nil
	}, backoff.WithBackOff(backoff.NewExponentialBackOff()), backoff.WithMaxElapsedTime(10*time.Second))
	if err != nil {
		return "", fmt.Errorf("failed to get FQDN for %s after retries: %w", t.hostname, err)
	}

	return fqdn, nil
}

// MustFQDN returns the FQDN as a string of the Tailscale instance, panicking on error.
func (t *TailscaleInContainer) MustFQDN() string {
	fqdn, err := t.FQDN()
	if err != nil {
		panic(err)
	}

	return fqdn
}

// FailingPeersAsString returns a formatted-ish multi-line-string of peers in the client
// and a bool indicating if the clients online count and peer count is equal.
func (t *TailscaleInContainer) FailingPeersAsString() (string, bool, error) {
	status, err := t.Status()
	if err != nil {
		return "", false, fmt.Errorf("failed to get FQDN: %w", err)
	}

	var b strings.Builder

	fmt.Fprintf(&b, "Peers of %s\n", t.hostname)
	fmt.Fprint(&b, "Hostname\tOnline\tLastSeen\n")

	peerCount := len(status.Peers())
	onlineCount := 0

	for _, peerKey := range status.Peers() {
		peer := status.Peer[peerKey]

		if peer.Online {
			onlineCount++
		}

		fmt.Fprintf(&b, "%s\t%t\t%s\n", peer.HostName, peer.Online, peer.LastSeen)
	}

	fmt.Fprintf(&b, "Peer Count: %d, Online Count: %d\n\n", peerCount, onlineCount)

	return b.String(), peerCount == onlineCount, nil
}

// WaitForNeedsLogin blocks until the Tailscale (tailscaled) instance has
// started and needs to be logged into.
func (t *TailscaleInContainer) WaitForNeedsLogin(timeout time.Duration) error {
	return t.waitForBackendState("NeedsLogin", timeout)
}

// WaitForRunning blocks until the Tailscale (tailscaled) instance is logged in
// and ready to be used.
func (t *TailscaleInContainer) WaitForRunning(timeout time.Duration) error {
	return t.waitForBackendState("Running", timeout)
}

func (t *TailscaleInContainer) waitForBackendState(state string, timeout time.Duration) error {
	ticker := time.NewTicker(integrationutil.PeerSyncRetryInterval())
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for backend state %s on %s after %v", state, t.hostname, timeout)
		case <-ticker.C:
			status, err := t.Status()
			if err != nil {
				continue // Keep retrying on status errors
			}

			// ipnstate.Status.CurrentTailnet was added in Tailscale 1.22.0
			// https://github.com/tailscale/tailscale/pull/3865
			//
			// Before that, we can check the BackendState to see if the
			// tailscaled daemon is connected to the control system.
			if status.BackendState == state {
				return nil
			}
		}
	}
}

// WaitForPeers blocks until N number of peers is present in the
// Peer list of the Tailscale instance and is reporting Online.
//
// The method verifies that each peer:
// - Has the expected peer count
// - All peers are Online
// - All peers have a hostname
// - All peers have a DERP relay assigned
//
// Uses multierr to collect all validation errors.
func (t *TailscaleInContainer) WaitForPeers(expected int, timeout, retryInterval time.Duration) error {
	ticker := time.NewTicker(retryInterval)
	defer ticker.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var lastErrs []error

	for {
		select {
		case <-ctx.Done():
			if len(lastErrs) > 0 {
				return fmt.Errorf("timeout waiting for %d peers on %s after %v, errors: %w", expected, t.hostname, timeout, multierr.New(lastErrs...))
			}

			return fmt.Errorf("timeout waiting for %d peers on %s after %v", expected, t.hostname, timeout)
		case <-ticker.C:
			status, err := t.Status()
			if err != nil {
				lastErrs = []error{errTailscaleStatus(t.hostname, err)}
				continue // Keep retrying on status errors
			}

			if peers := status.Peers(); len(peers) != expected {
				lastErrs = []error{fmt.Errorf(
					"%s err: %w expected %d, got %d",
					t.hostname,
					errTailscaleWrongPeerCount,
					expected,
					len(peers),
				)}

				continue
			}

			// Verify that the peers of a given node is Online
			// has a hostname and a DERP relay.
			var peerErrors []error

			for _, peerKey := range status.Peers() {
				peer := status.Peer[peerKey]

				if !peer.Online {
					peerErrors = append(peerErrors, fmt.Errorf("[%s] peer count correct, but %s is not online", t.hostname, peer.HostName))
				}

				if peer.HostName == "" {
					peerErrors = append(peerErrors, fmt.Errorf("[%s] peer count correct, but %s does not have a Hostname", t.hostname, peer.HostName))
				}

				if peer.Relay == "" {
					peerErrors = append(peerErrors, fmt.Errorf("[%s] peer count correct, but %s does not have a DERP", t.hostname, peer.HostName))
				}
			}

			if len(peerErrors) > 0 {
				lastErrs = peerErrors
				continue
			}

			return nil
		}
	}
}

type (
	// PingOption represent optional settings that can be given
	// to ping another host.
	PingOption = func(args *pingArgs)

	pingArgs struct {
		timeout time.Duration
		count   int
		direct  bool
	}
)

// WithPingTimeout sets the timeout for the ping command.
func WithPingTimeout(timeout time.Duration) PingOption {
	return func(args *pingArgs) {
		args.timeout = timeout
	}
}

// WithPingCount sets the count of pings to attempt.
func WithPingCount(count int) PingOption {
	return func(args *pingArgs) {
		args.count = count
	}
}

// WithPingUntilDirect decides if the ping should only succeed
// if a direct connection is established or if successful
// DERP ping is sufficient.
func WithPingUntilDirect(direct bool) PingOption {
	return func(args *pingArgs) {
		args.direct = direct
	}
}

// Ping executes the Tailscale ping command and pings a hostname
// or IP. It accepts a series of PingOption.
// TODO(kradalby): Make multiping, go routine magic.
func (t *TailscaleInContainer) Ping(hostnameOrIP string, opts ...PingOption) error {
	args := pingArgs{
		timeout: defaultPingTimeout,
		count:   defaultPingCount,
		direct:  true,
	}

	for _, opt := range opts {
		opt(&args)
	}

	command := []string{
		"tailscale", "ping",
		fmt.Sprintf("--timeout=%s", args.timeout),
		fmt.Sprintf("--c=%d", args.count),
		"--until-direct=" + strconv.FormatBool(args.direct),
	}

	command = append(command, hostnameOrIP)

	result, _, err := t.Execute(
		command,
		dockertestutil.ExecuteCommandTimeout(
			time.Duration(int64(args.timeout)*int64(args.count)),
		),
	)
	if err != nil {
		log.Printf("command: %v", command)
		log.Printf(
			"failed to run ping command from %s to %s, err: %s",
			t.Hostname(),
			hostnameOrIP,
			err,
		)

		return err
	}

	if strings.Contains(result, "is local") {
		return nil
	}

	if !strings.Contains(result, "pong") {
		return errTailscalePingFailed
	}

	if !args.direct {
		if strings.Contains(result, "via DERP") {
			return nil
		} else {
			return errTailscalePingNotDERP
		}
	}

	return nil
}

type (
	// CurlOption repreent optional settings that can be given
	// to curl another host.
	CurlOption = func(args *curlArgs)

	curlArgs struct {
		connectionTimeout time.Duration
		maxTime           time.Duration
		retry             int
		retryDelay        time.Duration
		retryMaxTime      time.Duration
	}
)

// WithCurlConnectionTimeout sets the timeout for each connection started
// by curl.
func WithCurlConnectionTimeout(timeout time.Duration) CurlOption {
	return func(args *curlArgs) {
		args.connectionTimeout = timeout
	}
}

// WithCurlMaxTime sets the max time for a transfer for each connection started
// by curl.
func WithCurlMaxTime(t time.Duration) CurlOption {
	return func(args *curlArgs) {
		args.maxTime = t
	}
}

// WithCurlRetry sets the number of retries a connection is attempted by curl.
func WithCurlRetry(ret int) CurlOption {
	return func(args *curlArgs) {
		args.retry = ret
	}
}

const (
	defaultConnectionTimeout = 1 * time.Second
	defaultMaxTime           = 3 * time.Second
	defaultRetry             = 3
	defaultRetryDelay        = 200 * time.Millisecond
	defaultRetryMaxTime      = 5 * time.Second
)

// Curl executes the Tailscale curl command and curls a hostname
// or IP. It accepts a series of CurlOption.
func (t *TailscaleInContainer) Curl(url string, opts ...CurlOption) (string, error) {
	args := curlArgs{
		connectionTimeout: defaultConnectionTimeout,
		maxTime:           defaultMaxTime,
		retry:             defaultRetry,
		retryDelay:        defaultRetryDelay,
		retryMaxTime:      defaultRetryMaxTime,
	}

	for _, opt := range opts {
		opt(&args)
	}

	command := []string{
		"curl",
		"--silent",
		"--connect-timeout", strconv.Itoa(int(args.connectionTimeout.Seconds())),
		"--max-time", strconv.Itoa(int(args.maxTime.Seconds())),
		"--retry", strconv.Itoa(args.retry),
		"--retry-delay", strconv.Itoa(int(args.retryDelay.Seconds())),
		"--retry-max-time", strconv.Itoa(int(args.retryMaxTime.Seconds())),
		url,
	}

	var result string

	result, _, err := t.Execute(command)
	if err != nil {
		log.Printf(
			"failed to run curl command from %s to %s, err: %s",
			t.Hostname(),
			url,
			err,
		)

		return result, err
	}

	return result, nil
}

// CurlFailFast executes the Tailscale curl command with aggressive timeouts
// optimized for testing expected connection failures. It uses minimal timeouts
// to quickly detect blocked connections without waiting for multiple retries.
func (t *TailscaleInContainer) CurlFailFast(url string) (string, error) {
	// Use aggressive timeouts for fast failure detection
	return t.Curl(url,
		WithCurlConnectionTimeout(1*time.Second),
		WithCurlMaxTime(2*time.Second),
		WithCurlRetry(1))
}

func (t *TailscaleInContainer) Traceroute(ip netip.Addr) (util.Traceroute, error) {
	command := []string{
		"traceroute",
		ip.String(),
	}

	var result util.Traceroute

	stdout, stderr, err := t.Execute(command)
	if err != nil {
		return result, err
	}

	result, err = util.ParseTraceroute(stdout + stderr)
	if err != nil {
		return result, err
	}

	return result, nil
}

// WriteFile save file inside the Tailscale container.
func (t *TailscaleInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

// SaveLog saves the current stdout log of the container to a path
// on the host system.
func (t *TailscaleInContainer) SaveLog(path string) (string, string, error) {
	// TODO(kradalby): Assert if tailscale logs contains panics.
	// NOTE(enoperm): `t.WriteLog | countMatchingLines`
	// is probably most of what is for that,
	// but I'd rather not change the behaviour here,
	// as it may affect all the other tests
	// I have not otherwise touched.
	return dockertestutil.SaveLog(t.pool, t.container, path)
}

// WriteLogs writes the current stdout/stderr log of the container to
// the given io.Writers.
func (t *TailscaleInContainer) WriteLogs(stdout, stderr io.Writer) error {
	return dockertestutil.WriteLog(t.pool, t.container, stdout, stderr)
}

// ReadFile reads a file from the Tailscale container.
// It returns the content of the file as a byte slice.
func (t *TailscaleInContainer) ReadFile(path string) ([]byte, error) {
	tarBytes, err := integrationutil.FetchPathFromContainer(t.pool, t.container, path)
	if err != nil {
		return nil, fmt.Errorf("reading file from container: %w", err)
	}

	var out bytes.Buffer

	tr := tar.NewReader(bytes.NewReader(tarBytes))
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break // End of archive
		}

		if err != nil {
			return nil, fmt.Errorf("reading tar header: %w", err)
		}

		if !strings.Contains(path, hdr.Name) {
			return nil, fmt.Errorf("file not found in tar archive, looking for: %s, header was: %s", path, hdr.Name)
		}

		if _, err := io.Copy(&out, tr); err != nil {
			return nil, fmt.Errorf("copying file to buffer: %w", err)
		}

		// Only support reading the first tile
		break
	}

	if out.Len() == 0 {
		return nil, errors.New("file is empty")
	}

	return out.Bytes(), nil
}

func (t *TailscaleInContainer) GetNodePrivateKey() (*key.NodePrivate, error) {
	state, err := t.ReadFile(paths.DefaultTailscaledStateFile())
	if err != nil {
		return nil, fmt.Errorf("failed to read state file: %w", err)
	}

	store := &mem.Store{}
	if err = store.LoadFromJSON(state); err != nil {
		return nil, fmt.Errorf("failed to unmarshal state file: %w", err)
	}

	currentProfileKey, err := store.ReadState(ipn.CurrentProfileStateKey)
	if err != nil {
		return nil, fmt.Errorf("failed to read current profile state key: %w", err)
	}

	currentProfile, err := store.ReadState(ipn.StateKey(currentProfileKey))
	if err != nil {
		return nil, fmt.Errorf("failed to read current profile state: %w", err)
	}

	p := &ipn.Prefs{}
	if err = json.Unmarshal(currentProfile, &p); err != nil {
		return nil, fmt.Errorf("failed to unmarshal current profile state: %w", err)
	}

	return &p.Persist.PrivateNodeKey, nil
}

// PacketFilter returns the current packet filter rules from the client's network map.
// This is useful for verifying that policy changes have propagated to the client.
func (t *TailscaleInContainer) PacketFilter() ([]filter.Match, error) {
	if !util.TailscaleVersionNewerOrEqual("1.56", t.version) {
		return nil, fmt.Errorf("tsic.PacketFilter() requires Tailscale 1.56+, current version: %s", t.version)
	}

	nm, err := t.Netmap()
	if err != nil {
		return nil, fmt.Errorf("failed to get netmap: %w", err)
	}

	return nm.PacketFilter, nil
}
