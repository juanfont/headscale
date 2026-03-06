package hscontrol

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTestCertificate generates a self-signed certificate and private key for testing.
// Returns cert PEM bytes, key PEM bytes, and any error.
func createTestCertificate(hostname string) ([]byte, []byte, error) {
	// Generate a private key
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	// Create certificate template
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName:   hostname,
			Organization: []string{"Headscale Test"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(1 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	// Self-sign the certificate
	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the certificate
	certPEM := new(bytes.Buffer)
	err = pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err != nil {
		return nil, nil, err
	}

	// PEM encode the private key
	keyPEM := new(bytes.Buffer)
	err = pem.Encode(keyPEM, &pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(privKey)})
	if err != nil {
		return nil, nil, err
	}

	return certPEM.Bytes(), keyPEM.Bytes(), nil
}

// writeCertFiles writes certificate and key PEM data to files in the given directory.
func writeCertFiles(t *testing.T, dir string, certPEM, keyPEM []byte) (certPath, keyPath string) {
	t.Helper()

	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")

	err := os.WriteFile(certPath, certPEM, 0o600)
	require.NoError(t, err)

	err = os.WriteFile(keyPath, keyPEM, 0o600)
	require.NoError(t, err)

	return certPath, keyPath
}

func TestReloadTLSCertificate_InitialLoad(t *testing.T) {
	tmpDir := t.TempDir()

	// Create test certificate
	certPEM, keyPEM, err := createTestCertificate("test.example.com")
	require.NoError(t, err)

	certPath, keyPath := writeCertFiles(t, tmpDir, certPEM, keyPEM)

	// Create minimal Headscale instance with TLS config
	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	// Test initial certificate load
	err = h.reloadTLSCertificate()
	require.NoError(t, err)

	// Verify certificate was loaded
	cert, err := h.getTLSCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)

	// Verify certificate content matches what we wrote
	expectedCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedCert.Certificate, cert.Certificate)
}

func TestReloadTLSCertificate_ReloadUpdatedCert(t *testing.T) {
	tmpDir := t.TempDir()

	// Create initial certificate
	certPEM1, keyPEM1, err := createTestCertificate("initial.example.com")
	require.NoError(t, err)

	certPath, keyPath := writeCertFiles(t, tmpDir, certPEM1, keyPEM1)

	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	// Load initial certificate
	err = h.reloadTLSCertificate()
	require.NoError(t, err)

	// Get initial certificate
	initialCert, err := h.getTLSCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, initialCert)

	// Create and write a NEW certificate (simulating cert renewal)
	certPEM2, keyPEM2, err := createTestCertificate("renewed.example.com")
	require.NoError(t, err)

	err = os.WriteFile(certPath, certPEM2, 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, keyPEM2, 0o600)
	require.NoError(t, err)

	// Reload the certificate (simulates SIGHUP handler)
	err = h.reloadTLSCertificate()
	require.NoError(t, err)

	// Get reloaded certificate
	reloadedCert, err := h.getTLSCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, reloadedCert)

	// Verify certificates are different (reload worked)
	assert.NotEqual(t, initialCert.Certificate, reloadedCert.Certificate,
		"reloaded certificate should be different from initial certificate")

	// Verify reloaded cert matches the new file
	expectedCert, err := tls.LoadX509KeyPair(certPath, keyPath)
	require.NoError(t, err)
	assert.Equal(t, expectedCert.Certificate, reloadedCert.Certificate)
}

func TestReloadTLSCertificate_InvalidPath(t *testing.T) {
	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: "/nonexistent/path/cert.pem",
				KeyPath:  "/nonexistent/path/key.pem",
			},
		},
	}

	err := h.reloadTLSCertificate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading TLS certificate")
}

func TestReloadTLSCertificate_InvalidCertContent(t *testing.T) {
	tmpDir := t.TempDir()

	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	// Write invalid certificate content
	err := os.WriteFile(certPath, []byte("not a valid certificate"), 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, []byte("not a valid key"), 0o600)
	require.NoError(t, err)

	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	err = h.reloadTLSCertificate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading TLS certificate")
}

func TestReloadTLSCertificate_MismatchedCertAndKey(t *testing.T) {
	tmpDir := t.TempDir()

	// Create two different certificates
	certPEM1, _, err := createTestCertificate("cert1.example.com")
	require.NoError(t, err)

	_, keyPEM2, err := createTestCertificate("cert2.example.com")
	require.NoError(t, err)

	// Write cert from first pair and key from second pair (mismatched)
	certPath := filepath.Join(tmpDir, "cert.pem")
	keyPath := filepath.Join(tmpDir, "key.pem")

	err = os.WriteFile(certPath, certPEM1, 0o600)
	require.NoError(t, err)
	err = os.WriteFile(keyPath, keyPEM2, 0o600)
	require.NoError(t, err)

	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	err = h.reloadTLSCertificate()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "loading TLS certificate")
}

func TestGetTLSCertificate_BeforeLoad(t *testing.T) {
	h := &Headscale{
		cfg: &types.Config{},
	}

	// Before any certificate is loaded, getTLSCertificate should return nil
	cert, err := h.getTLSCertificate(nil)
	require.NoError(t, err)
	assert.Nil(t, cert)
}

func TestReloadTLSCertificate_ConcurrentAccess(t *testing.T) {
	tmpDir := t.TempDir()

	certPEM, keyPEM, err := createTestCertificate("concurrent.example.com")
	require.NoError(t, err)

	certPath, keyPath := writeCertFiles(t, tmpDir, certPEM, keyPEM)

	h := &Headscale{
		cfg: &types.Config{
			TLS: types.TLSConfig{
				CertPath: certPath,
				KeyPath:  keyPath,
			},
		},
	}

	// Initial load
	err = h.reloadTLSCertificate()
	require.NoError(t, err)

	// Run concurrent readers and writers
	var wg sync.WaitGroup
	const numReaders = 100
	const numReloads = 10

	// Start readers
	for range numReaders {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 100 {
				cert, err := h.getTLSCertificate(nil)
				assert.NoError(t, err)
				assert.NotNil(t, cert)
			}
		}()
	}

	// Start writers (reloaders)
	for range numReloads {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range 10 {
				err := h.reloadTLSCertificate()
				assert.NoError(t, err)
			}
		}()
	}

	wg.Wait()

	// Final verification that certificate is still accessible
	cert, err := h.getTLSCertificate(nil)
	require.NoError(t, err)
	require.NotNil(t, cert)
}
