package integrationutil

import (
	"archive/tar"
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"path/filepath"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/ory/dockertest/v3"
	"github.com/ory/dockertest/v3/docker"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
)

var errInvalidImageFormat = errors.New("integration image env must be in repository:tag format")

// PrebuiltImage reads a HEADSCALE_INTEGRATION_*_IMAGE knob (the full var name,
// e.g. "HEADSCALE_INTEGRATION_HEADSCALE_IMAGE") and splits it into repository
// and tag. The bool is false when the knob is unset — the suite then builds the
// image itself; it errors when the value is set but is not "repository:tag".
// This is the one place the prebuilt-image knobs (used by the CI / nix-check
// path) are read, via tailscale's envknob.
func PrebuiltImage(envVar string) (string, string, bool, error) {
	image := envknob.String(envVar)
	if image == "" {
		return "", "", false, nil
	}

	repo, tag, err := ParseImageRef(image)
	if err != nil {
		return "", "", false, fmt.Errorf("%s=%w", envVar, err)
	}

	return repo, tag, true, nil
}

// ParseImageRef splits an already-resolved "repository:tag" image string into
// its parts. Use it where the image comes from somewhere other than a single
// knob (e.g. a websocket-tagged override chosen at runtime); for the common
// read-a-knob case use [PrebuiltImage].
func ParseImageRef(image string) (string, string, error) {
	repo, tag, found := strings.Cut(image, ":")
	if !found {
		return "", "", fmt.Errorf("%q: %w", image, errInvalidImageFormat)
	}

	return repo, tag, nil
}

// PeerSyncTimeout returns the timeout for peer synchronization: 60s for dev,
// scaled for CI / the slow nix VM.
func PeerSyncTimeout() time.Duration {
	return dockertestutil.ScaleTimeout(60 * time.Second)
}

// PeerSyncRetryInterval returns the retry interval for peer synchronization checks.
func PeerSyncRetryInterval() time.Duration {
	return 100 * time.Millisecond
}

// ScaledTimeout returns the given convergence budget, scaled for the running
// environment via [dockertestutil.ScaleTimeout].
func ScaledTimeout(d time.Duration) time.Duration {
	return dockertestutil.ScaleTimeout(d)
}

func WriteFileToContainer(
	pool *dockertest.Pool,
	container *dockertest.Resource,
	path string,
	data []byte,
) error {
	dirPath, fileName := filepath.Split(path)

	file := bytes.NewReader(data)

	buf := bytes.NewBuffer([]byte{})

	tarWriter := tar.NewWriter(buf)

	header := &tar.Header{
		Name: fileName,
		Size: file.Size(),
		// Mode:    int64(stat.Mode()),
		// ModTime: stat.ModTime(),
	}

	err := tarWriter.WriteHeader(header)
	if err != nil {
		return fmt.Errorf("writing file header to tar: %w", err)
	}

	_, err = io.Copy(tarWriter, file)
	if err != nil {
		return fmt.Errorf("copying file to tar: %w", err)
	}

	err = tarWriter.Close()
	if err != nil {
		return fmt.Errorf("closing tar: %w", err)
	}

	// Ensure the directory is present inside the container
	_, _, err = dockertestutil.ExecuteCommand(
		container,
		[]string{"mkdir", "-p", dirPath},
		[]string{},
	)
	if err != nil {
		return fmt.Errorf("ensuring directory: %w", err)
	}

	err = pool.Client.UploadToContainer(
		container.Container.ID,
		docker.UploadToContainerOptions{
			NoOverwriteDirNonDir: false,
			Path:                 dirPath,
			InputStream:          bytes.NewReader(buf.Bytes()),
		},
	)
	if err != nil {
		return err
	}

	return nil
}

func FetchPathFromContainer(
	pool *dockertest.Pool,
	container *dockertest.Resource,
	path string,
) ([]byte, error) {
	buf := bytes.NewBuffer([]byte{})

	err := pool.Client.DownloadFromContainer(
		container.Container.ID,
		docker.DownloadFromContainerOptions{
			OutputStream: buf,
			Path:         path,
		},
	)
	if err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// nolint
// CreateCertificate generates a CA certificate and a server certificate
// signed by that CA for the given hostname. It returns the CA certificate
// PEM (for trust stores), server certificate PEM, and server private key
// PEM.
func CreateCertificate(hostname string) (caCertPEM, certPEM, keyPEM []byte, err error) {
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
		NotAfter:  time.Now().Add(60 * time.Hour),
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
		return nil, nil, nil, err
	}

	caBytes, err := x509.CreateCertificate(
		rand.Reader,
		ca,
		ca,
		&caPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	caPEM := new(bytes.Buffer)
	err = pem.Encode(caPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: caBytes,
	})
	if err != nil {
		return nil, nil, nil, err
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
		return nil, nil, nil, err
	}

	certBytes, err := x509.CreateCertificate(
		rand.Reader,
		cert,
		ca,
		&certPrivKey.PublicKey,
		caPrivKey,
	)
	if err != nil {
		return nil, nil, nil, err
	}

	serverCertPEM := new(bytes.Buffer)
	err = pem.Encode(serverCertPEM, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	})
	if err != nil {
		return nil, nil, nil, err
	}

	certPrivKeyPEM := new(bytes.Buffer)
	err = pem.Encode(certPrivKeyPEM, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(certPrivKey),
	})
	if err != nil {
		return nil, nil, nil, err
	}

	return caPEM.Bytes(), serverCertPEM.Bytes(), certPrivKeyPEM.Bytes(), nil
}

func BuildExpectedOnlineMap(all map[types.NodeID][]tailcfg.MapResponse) map[types.NodeID]map[types.NodeID]bool {
	res := make(map[types.NodeID]map[types.NodeID]bool)
	for nid, mrs := range all {
		res[nid] = make(map[types.NodeID]bool)

		set := func(id tailcfg.NodeID, online *bool) {
			if online != nil {
				res[nid][types.NodeID(id)] = *online //nolint:gosec // safe conversion for peer ID
			}
		}

		for _, mr := range mrs {
			for _, peer := range mr.Peers {
				set(peer.ID, peer.Online)
			}

			for _, peer := range mr.PeersChanged {
				set(peer.ID, peer.Online)
			}

			for _, peer := range mr.PeersChangedPatch {
				set(peer.NodeID, peer.Online)
			}
		}
	}

	return res
}
