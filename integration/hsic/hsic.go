package hsic

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
)

const (
	hsicHashLength       = 6
	dockerContextPath    = "../."
	aclPolicyPath        = "/etc/headscale/acl.hujson"
	tlsCertPath          = "/etc/headscale/tls.cert"
	tlsKeyPath           = "/etc/headscale/tls.key"
	headscaleDefaultPort = 8080
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

	// optional config
	port             int
	extraPorts       []string
	hostPortBindings map[string][]string
	aclPolicy        *policy.ACLPolicy
	env              map[string]string
	tlsCert          []byte
	tlsKey           []byte
	filesInContainer []fileInContainer
}

// Option represent optional settings that can be given to a
// Headscale instance.
type Option = func(c *HeadscaleInContainer)

// WithACLPolicy adds a hscontrol.ACLPolicy policy to the
// HeadscaleInContainer instance.
func WithACLPolicy(acl *policy.ACLPolicy) Option {
	return func(hsic *HeadscaleInContainer) {
		// TODO(kradalby): Move somewhere appropriate
		hsic.env["HEADSCALE_ACL_POLICY_PATH"] = aclPolicyPath

		hsic.aclPolicy = acl
	}
}

// WithTLS creates certificates and enables HTTPS.
func WithTLS() Option {
	return func(hsic *HeadscaleInContainer) {
		cert, key, err := createCertificate(hsic.hostname)
		if err != nil {
			log.Fatalf("failed to create certificates for headscale test: %s", err)
		}

		// TODO(kradalby): Move somewhere appropriate
		hsic.env["HEADSCALE_TLS_CERT_PATH"] = tlsCertPath
		hsic.env["HEADSCALE_TLS_KEY_PATH"] = tlsKeyPath

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

// WithHostnameAsServerURL sets the Headscale ServerURL based on
// the Hostname.
func WithHostnameAsServerURL() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env["HEADSCALE_SERVER_URL"] = fmt.Sprintf("http://%s",
			net.JoinHostPort(hsic.GetHostname(),
				fmt.Sprintf("%d", hsic.port)),
		)
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

	serverURL, err := url.Parse(hsic.env["HEADSCALE_SERVER_URL"])
	if err != nil {
		return nil, err
	}

	if len(hsic.tlsCert) != 0 && len(hsic.tlsKey) != 0 {
		serverURL.Scheme = "https"
		hsic.env["HEADSCALE_SERVER_URL"] = serverURL.String()
	}

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: dockerContextPath,
	}

	env := []string{
		"HEADSCALE_PROFILING_ENABLED=1",
		"HEADSCALE_PROFILING_PATH=/tmp/profile",
		"HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH=/tmp/mapresponses",
	}
	for key, value := range hsic.env {
		env = append(env, fmt.Sprintf("%s=%s", key, value))
	}

	log.Printf("ENV: \n%s", spew.Sdump(hsic.env))

	runOptions := &dockertest.RunOptions{
		Name:         hsic.hostname,
		ExposedPorts: append([]string{portProto}, hsic.extraPorts...),
		Networks:     []*dockertest.Network{network},
		// Cmd:          []string{"headscale", "serve"},
		// TODO(kradalby): Get rid of this hack, we currently need to give us some
		// to inject the headscale configuration further down.
		Entrypoint: []string{"/bin/bash", "-c", "/bin/sleep 3 ; headscale serve ; /bin/sleep 30"},
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
func (t *HeadscaleInContainer) Shutdown() error {
	err := t.SaveLog("/tmp/control")
	if err != nil {
		log.Printf(
			"Failed to save log from control: %s",
			fmt.Errorf("failed to save log from control: %w", err),
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

	return t.pool.Purge(t.container)
}

// SaveLog saves the current stdout log of the container to a path
// on the host system.
func (t *HeadscaleInContainer) SaveLog(path string) error {
	return dockertestutil.SaveLog(t.pool, t.container, path)
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
		log.Printf("command stderr: %s\n", stderr)

		if stdout != "" {
			log.Printf("command stdout: %s\n", stdout)
		}

		return "", err
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
		t.GetIP(),
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
	command := []string{"headscale", "users", "create", user}

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

// nolint
func createCertificate(hostname string) ([]byte, []byte, error) {
	// From:
	// https://shaneutt.com/blog/golang-ca-and-signed-cert-go/

	ca := &x509.Certificate{
		SerialNumber: big.NewInt(2019),
		Subject: pkix.Name{
			Organization: []string{"Headscale testing INC"},
			Country:      []string{"NL"},
			Locality:     []string{"Leiden"},
		},
		NotBefore: time.Now(),
		NotAfter:  time.Now().Add(60 * time.Minute),
		IsCA:      true,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	cert := &x509.Certificate{
		SerialNumber: big.NewInt(1658),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Headscale testing INC"},
			Country:      []string{"NL"},
			Locality:     []string{"Leiden"},
		},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(60 * time.Minute),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
		DNSNames:     []string{hostname},
	}

	certPrivKey, err := rsa.GenerateKey(rand.Reader, 4096)
	if err != nil {
		return nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		ca,
		&certPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return nil, nil, err
	}

	certPEM := new(bytes.Buffer)

	err = pem.Encode(certPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)

	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, nil, err
	}

	return certPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}
