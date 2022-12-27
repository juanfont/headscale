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
	"time"

	"github.com/juanfont/headscale"
	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/ory/dockertest/v3"
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

type HeadscaleInContainer struct {
	hostname string

	pool      *dockertest.Pool
	container *dockertest.Resource
	network   *dockertest.Network

	// optional config
	port      int
	aclPolicy *headscale.ACLPolicy
	env       []string
	tlsCert   []byte
	tlsKey    []byte
}

type Option = func(c *HeadscaleInContainer)

func WithACLPolicy(acl *headscale.ACLPolicy) Option {
	return func(hsic *HeadscaleInContainer) {
		// TODO(kradalby): Move somewhere appropriate
		hsic.env = append(hsic.env, fmt.Sprintf("HEADSCALE_ACL_POLICY_PATH=%s", aclPolicyPath))

		hsic.aclPolicy = acl
	}
}

func WithTLS() Option {
	return func(hsic *HeadscaleInContainer) {
		cert, key, err := createCertificate()
		if err != nil {
			log.Fatalf("failed to create certificates for headscale test: %s", err)
		}

		// TODO(kradalby): Move somewhere appropriate
		hsic.env = append(hsic.env, fmt.Sprintf("HEADSCALE_TLS_CERT_PATH=%s", tlsCertPath))
		hsic.env = append(hsic.env, fmt.Sprintf("HEADSCALE_TLS_KEY_PATH=%s", tlsKeyPath))

		hsic.tlsCert = cert
		hsic.tlsKey = key
	}
}

func WithConfigEnv(configEnv map[string]string) Option {
	return func(hsic *HeadscaleInContainer) {
		for key, value := range configEnv {
			hsic.env = append(hsic.env, fmt.Sprintf("%s=%s", key, value))
		}
	}
}

func WithPort(port int) Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.port = port
	}
}

func WithTestName(testName string) Option {
	return func(hsic *HeadscaleInContainer) {
		hash, _ := headscale.GenerateRandomStringDNSSafe(hsicHashLength)

		hostname := fmt.Sprintf("hs-%s-%s", testName, hash)
		hsic.hostname = hostname
	}
}

func WithHostnameAsServerURL() Option {
	return func(hsic *HeadscaleInContainer) {
		hsic.env = append(
			hsic.env,
			fmt.Sprintf("HEADSCALE_SERVER_URL=http://%s:%d",
				hsic.GetHostname(),
				hsic.port,
			))
	}
}

func New(
	pool *dockertest.Pool,
	network *dockertest.Network,
	opts ...Option,
) (*HeadscaleInContainer, error) {
	hash, err := headscale.GenerateRandomStringDNSSafe(hsicHashLength)
	if err != nil {
		return nil, err
	}

	hostname := fmt.Sprintf("hs-%s", hash)

	hsic := &HeadscaleInContainer{
		hostname: hostname,
		port:     headscaleDefaultPort,

		pool:    pool,
		network: network,
	}

	for _, opt := range opts {
		opt(hsic)
	}

	log.Println("NAME: ", hsic.hostname)

	portProto := fmt.Sprintf("%d/tcp", hsic.port)

	headscaleBuildOptions := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.debug",
		ContextDir: dockerContextPath,
	}

	runOptions := &dockertest.RunOptions{
		Name:         hsic.hostname,
		ExposedPorts: []string{portProto},
		Networks:     []*dockertest.Network{network},
		// Cmd:          []string{"headscale", "serve"},
		// TODO(kradalby): Get rid of this hack, we currently need to give us some
		// to inject the headscale configuration further down.
		Entrypoint: []string{"/bin/bash", "-c", "/bin/sleep 3 ; headscale serve"},
		Env:        hsic.env,
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

	err = hsic.WriteFile("/etc/headscale/config.yaml", []byte(DefaultConfigYAML()))
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

	return hsic, nil
}

func (t *HeadscaleInContainer) hasTLS() bool {
	return len(t.tlsCert) != 0 && len(t.tlsKey) != 0
}

func (t *HeadscaleInContainer) Shutdown() error {
	return t.pool.Purge(t.container)
}

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

func (t *HeadscaleInContainer) GetIP() string {
	return t.container.GetIPInNetwork(t.network)
}

func (t *HeadscaleInContainer) GetPort() string {
	return fmt.Sprintf("%d", t.port)
}

func (t *HeadscaleInContainer) GetHealthEndpoint() string {
	return fmt.Sprintf("%s/health", t.GetEndpoint())
}

func (t *HeadscaleInContainer) GetEndpoint() string {
	hostEndpoint := fmt.Sprintf("%s:%d",
		t.GetIP(),
		t.port)

	if t.hasTLS() {
		return fmt.Sprintf("https://%s", hostEndpoint)
	}

	return fmt.Sprintf("http://%s", hostEndpoint)
}

func (t *HeadscaleInContainer) GetCert() []byte {
	return t.tlsCert
}

func (t *HeadscaleInContainer) GetHostname() string {
	return t.hostname
}

func (t *HeadscaleInContainer) WaitForReady() error {
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
	reusable bool,
	ephemeral bool,
) (*v1.PreAuthKey, error) {
	command := []string{
		"headscale",
		"--namespace",
		namespace,
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

func (t *HeadscaleInContainer) ListMachinesInNamespace(
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

func (t *HeadscaleInContainer) WriteFile(path string, data []byte) error {
	return integrationutil.WriteFileToContainer(t.pool, t.container, path, data)
}

// nolint
func createCertificate() ([]byte, []byte, error) {
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
		NotAfter:  time.Now().Add(30 * time.Minute),
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
			Organization: []string{"Headscale testing INC"},
			Country:      []string{"NL"},
			Locality:     []string{"Leiden"},
		},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
		NotBefore:    time.Now(),
		NotAfter:     time.Now().Add(30 * time.Minute),
		SubjectKeyId: []byte{1, 2, 3, 4, 6},
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth},
		KeyUsage:     x509.KeyUsageDigitalSignature,
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
