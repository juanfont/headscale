package tsic

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/juanfont/headscale"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/ipn/ipnstate"
)

const (
	tsicHashLength    = 6
	defaultPingCount  = 10
	dockerContextPath = "../."
	headscaleCertPath = "/usr/local/share/ca-certificates/headscale.crt"
)

var (
	errTailscalePingFailed             = errors.New("ping failed")
	errTailscalePingNotDERP            = errors.New("ping not via DERP")
	errTailscaleNotLoggedIn            = errors.New("tailscale not logged in")
	errTailscaleWrongPeerCount         = errors.New("wrong peer count")
	errTailscaleCannotUpWithoutAuthkey = errors.New("cannot up without authkey")
	errTailscaleNotConnected           = errors.New("tailscale not connected")
	errTailscaleNotLoggedOut           = errors.New("tailscale not logged out")
)

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
	headscaleCert     []byte
	headscaleHostname string
	withSSH           bool
	withTags          []string
	withEntrypoint    []string
	withExtraHosts    []string
	workdir           string
}

// Option represent optional settings that can be given to a
// Tailscale instance.
type Option = func(c *TailscaleInContainer)

// WithHeadscaleTLS takes the certificate of the Headscale instance
// and adds it to the trusted surtificate of the Tailscale container.
func WithHeadscaleTLS(cert []byte) Option {
	return func(tsic *TailscaleInContainer) {
		tsic.headscaleCert = cert
	}
}

// WithOrCreateNetwork sets the Docker container network to use with
// the Tailscale instance, if the parameter is nil, a new network,
// isolating the TailscaleClient, will be created. If a network is
// passed, the Tailscale instance will join the given network.
func WithOrCreateNetwork(network *dockertest.Network) Option {
	return func(tsic *TailscaleInContainer) {
		if network != nil {
			tsic.network = network

			return
		}

		network, err := dockertestutil.GetFirstOrCreateNetwork(
			tsic.pool,
			fmt.Sprintf("%s-network", tsic.hostname),
		)
		if err != nil {
			log.Fatalf("failed to create network: %s", err)
		}

		tsic.network = network
	}
}

// WithHeadscaleName set the name of the headscale instance,
// mostly useful in combination with TLS and WithHeadscaleTLS.
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

// New returns a new TailscaleInContainer instance.
func New(
	pool *dockertest.Pool,
	version string,
	network *dockertest.Network,
	opts ...Option,
) (*TailscaleInContainer, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(tsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("ts-%s-%s", strings.ReplaceAll(version, ".", "-"), hash)

	tsic := &TailscaleInContainer{
		version:  version,
		hostname: hostname,

		pool:    pool,
		network: network,

		withEntrypoint: []string{
			"/bin/bash",
			"-c",
			"/bin/sleep 3 ; update-ca-certificates ; tailscaled --tun=tsdev",
		},
	}

	for _, opt := range opts {
		opt(tsic)
	}

	tailscaleOptions := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{tsic.network},
		// Cmd: []string{
		// 	"tailscaled", "--tun=tsdev",
		// },
		Entrypoint: tsic.withEntrypoint,
		ExtraHosts: tsic.withExtraHosts,
	}

	if tsic.headscaleHostname != "" {
		tailscaleOptions.ExtraHosts = []string{
			"host.docker.internal:host-gateway",
			fmt.Sprintf("%s:host-gateway", tsic.headscaleHostname),
		}
	}

	if tsic.workdir != "" {
		tailscaleOptions.WorkingDir = tsic.workdir
	}

	// dockertest isnt very good at handling containers that has already
	// been created, this is an attempt to make sure this container isnt
	// present.
	err = pool.RemoveContainerByName(hostname)
	if err != nil {
		return nil, err
	}

	container, err := pool.BuildAndRunWithBuildOptions(
		createTailscaleBuildOptions(version),
		tailscaleOptions,
		dockertestutil.DockerRestartPolicy,
		dockertestutil.DockerAllowLocalIPv6,
		dockertestutil.DockerAllowNetworkAdministration,
	)
	if err != nil {
		return nil, fmt.Errorf("could not start tailscale container: %w", err)
	}
	log.Printf("Created %s container\n", hostname)

	tsic.container = container

	if tsic.hasTLS() {
		err = tsic.WriteFile(headscaleCertPath, tsic.headscaleCert)
		if err != nil {
			return nil, fmt.Errorf("failed to write TLS certificate to container: %w", err)
		}
	}

	return tsic, nil
}

func (t *TailscaleInContainer) hasTLS() bool {
	return len(t.headscaleCert) != 0
}

// Shutdown stops and cleans up the Tailscale container.
func (t *TailscaleInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
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
func (t *TailscaleInContainer) ID() string {
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
		log.Printf("command stderr: %s\n", stderr)

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

// Up runs the login routine on the given Tailscale instance.
// This login mechanism uses the authorised key for authentication.
func (t *TailscaleInContainer) Up(
	loginServer, authKey string,
) error {
	command := []string{
		"tailscale",
		"up",
		"-login-server",
		loginServer,
		"--authkey",
		authKey,
		"--hostname",
		t.hostname,
	}

	if t.withSSH {
		command = append(command, "--ssh")
	}

	if len(t.withTags) > 0 {
		command = append(command,
			fmt.Sprintf(`--advertise-tags=%s`, strings.Join(t.withTags, ",")),
		)
	}

	if _, _, err := t.Execute(command); err != nil {
		return fmt.Errorf("failed to join tailscale client: %w", err)
	}

	return nil
}

// Up runs the login routine on the given Tailscale instance.
// This login mechanism uses web + command line flow for authentication.
func (t *TailscaleInContainer) UpWithLoginURL(
	loginServer string,
) (*url.URL, error) {
	command := []string{
		"tailscale",
		"up",
		"-login-server",
		loginServer,
		"--hostname",
		t.hostname,
	}

	_, stderr, err := t.Execute(command)
	if errors.Is(err, errTailscaleNotLoggedIn) {
		return nil, errTailscaleCannotUpWithoutAuthkey
	}

	urlStr := strings.ReplaceAll(stderr, "\nTo authenticate, visit:\n\n\t", "")
	urlStr = strings.TrimSpace(urlStr)

	// parse URL
	loginURL, err := url.Parse(urlStr)
	if err != nil {
		log.Printf("Could not parse login URL: %s", err)
		log.Printf("Original join command result: %s", stderr)

		return nil, err
	}

	return loginURL, nil
}

// Logout runs the logout routine on the given Tailscale instance.
func (t *TailscaleInContainer) Logout() error {
	_, _, err := t.Execute([]string{"tailscale", "logout"})
	if err != nil {
		return err
	}

	return nil
}

// IPs returns the netip.Addr of the Tailscale instance.
func (t *TailscaleInContainer) IPs() ([]netip.Addr, error) {
	if t.ips != nil && len(t.ips) != 0 {
		return t.ips, nil
	}

	ips := make([]netip.Addr, 0)

	command := []string{
		"tailscale",
		"ip",
	}

	result, _, err := t.Execute(command)
	if err != nil {
		return []netip.Addr{}, fmt.Errorf("failed to join tailscale client: %w", err)
	}

	for _, address := range strings.Split(result, "\n") {
		address = strings.TrimSuffix(address, "\n")
		if len(address) < 1 {
			continue
		}
		ip, err := netip.ParseAddr(address)
		if err != nil {
			return nil, err
		}
		ips = append(ips, ip)
	}

	return ips, nil
}

// Status returns the ipnstate.Status of the Tailscale instance.
func (t *TailscaleInContainer) Status() (*ipnstate.Status, error) {
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

	return &status, err
}

// FQDN returns the FQDN as a string of the Tailscale instance.
func (t *TailscaleInContainer) FQDN() (string, error) {
	if t.fqdn != "" {
		return t.fqdn, nil
	}

	status, err := t.Status()
	if err != nil {
		return "", fmt.Errorf("failed to get FQDN: %w", err)
	}

	return status.Self.DNSName, nil
}

// WaitForReady blocks until the Tailscale (tailscaled) instance is ready
// to login or be used.
func (t *TailscaleInContainer) WaitForReady() error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch tailscale status: %w", err)
		}

		if status.CurrentTailnet != nil {
			return nil
		}

		// ipnstate.Status.CurrentTailnet was added in Tailscale 1.22.0
		// https://github.com/tailscale/tailscale/pull/3865
		//
		// Before that, we can check the BackendState to see if the
		// tailscaled daemon is connected to the control system.
		if status.BackendState == "Running" {
			return nil
		}

		return errTailscaleNotConnected
	})
}

// WaitForLogout blocks until the Tailscale instance has logged out.
func (t *TailscaleInContainer) WaitForLogout() error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch tailscale status: %w", err)
		}

		if status.CurrentTailnet == nil {
			return nil
		}

		return errTailscaleNotLoggedOut
	})
}

// WaitForPeers blocks until N number of peers is present in the
// Peer list of the Tailscale instance.
func (t *TailscaleInContainer) WaitForPeers(expected int) error {
	return t.pool.Retry(func() error {
		status, err := t.Status()
		if err != nil {
			return fmt.Errorf("failed to fetch tailscale status: %w", err)
		}

		if peers := status.Peers(); len(peers) != expected {
			return errTailscaleWrongPeerCount
		}

		return nil
	})
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
		timeout: time.Second,
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
		fmt.Sprintf("--until-direct=%s", strconv.FormatBool(args.direct)),
	}

	command = append(command, hostnameOrIP)

	return t.pool.Retry(func() error {
		result, _, err := t.Execute(command)
		if err != nil {
			log.Printf(
				"failed to run ping command from %s to %s, err: %s",
				t.Hostname(),
				hostnameOrIP,
				err,
			)

			return err
		}

		if !strings.Contains(result, "pong") && !strings.Contains(result, "is local") {
			return backoff.Permanent(errTailscalePingFailed)
		}

		return nil
	})
}

// PingViaDERP executes the Tailscale ping command and pings a hostname
// or IP via the DERP network (i.e., not a direct connection). It accepts a series of DERPPingOption.
// TODO(kradalby): Make multiping, go routine magic.
func (t *TailscaleInContainer) PingViaDERP(hostnameOrIP string, opts ...PingOption) error {
	args := pingArgs{
		timeout: time.Second,
		count:   defaultPingCount,
	}

	for _, opt := range opts {
		opt(&args)
	}

	command := []string{
		"tailscale", "ping",
		fmt.Sprintf("--timeout=%s", args.timeout),
		fmt.Sprintf("--c=%d", args.count),
		"--until-direct=false",
	}

	command = append(command, hostnameOrIP)

	return t.pool.Retry(func() error {
		result, _, err := t.Execute(
			command,
			dockertestutil.ExecuteCommandTimeout(
				time.Duration(int64(args.timeout)*int64(args.count)),
			),
		)
		if err != nil {
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
			return backoff.Permanent(errTailscalePingFailed)
		}

		if !strings.Contains(result, "via DERP") {
			return backoff.Permanent(errTailscalePingNotDERP)
		}

		return nil
	})
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
	defaultConnectionTimeout = 3 * time.Second
	defaultMaxTime           = 10 * time.Second
	defaultRetry             = 5
	defaultRetryDelay        = 0 * time.Second
	defaultRetryMaxTime      = 50 * time.Second
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
		"--connect-timeout", fmt.Sprintf("%d", int(args.connectionTimeout.Seconds())),
		"--max-time", fmt.Sprintf("%d", int(args.maxTime.Seconds())),
		"--retry", fmt.Sprintf("%d", args.retry),
		"--retry-delay", fmt.Sprintf("%d", int(args.retryDelay.Seconds())),
		"--retry-max-time", fmt.Sprintf("%d", int(args.retryMaxTime.Seconds())),
		url,
	}

	var result string
	err := t.pool.Retry(func() error {
		var err error
		result, _, err = t.Execute(command)
		if err != nil {
			log.Printf(
				"failed to run curl command from %s to %s, err: %s",
				t.Hostname(),
				url,
				err,
			)

			return err
		}

		return nil
	})

	return result, err
}

// WriteFile save file inside the Tailscale container.
func (t *TailscaleInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

func createTailscaleBuildOptions(version string) *dockertest.BuildOptions {
	var tailscaleBuildOptions *dockertest.BuildOptions
	switch version {
	case "head":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale-HEAD",
			ContextDir: dockerContextPath,
			BuildArgs:  []docker.BuildArg{},
		}
	case "unstable":
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "TAILSCALE_VERSION",
					Value: "*", // Installs the latest version https://askubuntu.com/a/824926
				},
				{
					Name:  "TAILSCALE_CHANNEL",
					Value: "unstable",
				},
			},
		}
	default:
		tailscaleBuildOptions = &dockertest.BuildOptions{
			Dockerfile: "Dockerfile.tailscale",
			ContextDir: dockerContextPath,
			BuildArgs: []docker.BuildArg{
				{
					Name:  "TAILSCALE_VERSION",
					Value: version,
				},
				{
					Name:  "TAILSCALE_CHANNEL",
					Value: "stable",
				},
			},
		}
	}

	return tailscaleBuildOptions
}
