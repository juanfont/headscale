package integration

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	tlsCertPath = "/etc/headscale/tls.cert"
	tlsKeyPath  = "/etc/headscale/tls.key"
)

// getTLSCertificate connects to the given HTTPS endpoint and returns
// the server's TLS certificate.
func getTLSCertificate(endpoint string) (*x509.Certificate, error) {
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				InsecureSkipVerify: true, //nolint:gosec
			},
		},
		Timeout: 5 * time.Second,
	}

	resp, err := client.Get(endpoint + "/health")
	if err != nil {
		return nil, fmt.Errorf("connecting to endpoint: %w", err)
	}
	defer resp.Body.Close()

	if resp.TLS == nil || len(resp.TLS.PeerCertificates) == 0 {
		return nil, fmt.Errorf("no TLS certificates received")
	}

	return resp.TLS.PeerCertificates[0], nil
}

// TestTLSCertificateReloadOnSIGHUP tests that headscale reloads TLS certificates
// when it receives a SIGHUP signal.
func TestTLSCertificateReloadOnSIGHUP(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create headscale with TLS enabled
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tls-reload"),
		hsic.WithTLS(),
		hsic.WithEmbeddedDERPServerOnly(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	// Wait for headscale to be ready and get the endpoint
	endpoint := headscale.GetEndpoint()
	require.Contains(t, endpoint, "https://", "endpoint should be HTTPS when TLS is enabled")

	// Get the initial certificate
	var initialCert *x509.Certificate
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		cert, err := getTLSCertificate(endpoint)
		assert.NoError(c, err)
		assert.NotNil(c, cert)
		initialCert = cert
	}, 10*time.Second, 500*time.Millisecond, "should be able to get initial TLS certificate")

	t.Logf("Initial certificate NotBefore: %s", initialCert.NotBefore.Format(time.RFC3339Nano))

	// Wait a bit to ensure the new certificate will have a different NotBefore time
	time.Sleep(1 * time.Second)

	// Generate a new certificate (will have a different NotBefore time)
	newCert, newKey, err := integrationutil.CreateCertificate(headscale.GetHostname())
	require.NoError(t, err)

	// Write the new certificate files to the container
	err = headscale.WriteFile(tlsCertPath, newCert)
	require.NoError(t, err, "failed to write new certificate")

	err = headscale.WriteFile(tlsKeyPath, newKey)
	require.NoError(t, err, "failed to write new key")

	t.Log("New certificate written to container, sending SIGHUP...")

	// Send SIGHUP to trigger certificate reload
	err = headscale.Reload()
	require.NoError(t, err, "failed to send SIGHUP")

	// Wait a moment for the reload to take effect
	time.Sleep(500 * time.Millisecond)

	// Verify the new certificate is being served by checking NotBefore time changed
	var newCertFromServer *x509.Certificate
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		cert, err := getTLSCertificate(endpoint)
		assert.NoError(c, err)
		assert.NotNil(c, cert)
		newCertFromServer = cert

		// The NotBefore time should be different (later) than the initial one
		assert.True(c, cert.NotBefore.After(initialCert.NotBefore),
			"new certificate NotBefore (%s) should be after initial (%s)",
			cert.NotBefore.Format(time.RFC3339Nano),
			initialCert.NotBefore.Format(time.RFC3339Nano))
	}, 10*time.Second, 500*time.Millisecond, "certificate should be reloaded after SIGHUP")

	t.Logf("New certificate NotBefore: %s", newCertFromServer.NotBefore.Format(time.RFC3339Nano))
	t.Log("TLS certificate reload verified successfully")
}

// TestTLSCertificateReloadClientConnectivity tests that clients remain
// connected and functional after a TLS certificate reload.
func TestTLSCertificateReloadClientConnectivity(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create headscale with TLS enabled
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tls-reload-conn"),
		hsic.WithTLS(),
		hsic.WithEmbeddedDERPServerOnly(),
	)
	requireNoErrHeadscaleEnv(t, err)

	// Wait for clients to sync
	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 2, "should have 2 clients")

	// Verify clients can ping each other before certificate reload
	allIPs, err := scenario.ListTailscaleClientsIPs()
	require.NoError(t, err)

	t.Log("Verifying initial connectivity...")
	for _, client := range allClients {
		for _, ip := range allIPs {
			err := client.Ping(ip.String())
			require.NoError(t, err, "initial ping failed")
		}
	}

	// Get endpoint and initial certificate
	endpoint := headscale.GetEndpoint()
	initialCert, err := getTLSCertificate(endpoint)
	require.NoError(t, err)

	t.Logf("Initial certificate NotBefore: %s", initialCert.NotBefore.Format(time.RFC3339Nano))

	// Wait to ensure new certificate will have different NotBefore
	time.Sleep(1 * time.Second)

	// Generate and write new certificate
	newCert, newKey, err := integrationutil.CreateCertificate(headscale.GetHostname())
	require.NoError(t, err)

	err = headscale.WriteFile(tlsCertPath, newCert)
	require.NoError(t, err)

	err = headscale.WriteFile(tlsKeyPath, newKey)
	require.NoError(t, err)

	t.Log("Sending SIGHUP to reload certificate...")
	err = headscale.Reload()
	require.NoError(t, err)

	// Wait for reload to take effect
	time.Sleep(1 * time.Second)

	// Verify certificate changed
	var newCertFromServer *x509.Certificate
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		cert, err := getTLSCertificate(endpoint)
		assert.NoError(c, err)
		newCertFromServer = cert
		assert.True(c, cert.NotBefore.After(initialCert.NotBefore),
			"certificate should have changed")
	}, 10*time.Second, 500*time.Millisecond, "certificate should be reloaded")

	t.Logf("New certificate NotBefore: %s", newCertFromServer.NotBefore.Format(time.RFC3339Nano))

	// Verify clients can still ping each other after certificate reload
	t.Log("Verifying connectivity after certificate reload...")
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		for _, client := range allClients {
			for _, ip := range allIPs {
				err := client.Ping(ip.String())
				assert.NoError(c, err, "ping after certificate reload failed")
			}
		}
	}, 30*time.Second, 1*time.Second, "clients should remain connected after certificate reload")

	t.Log("Client connectivity verified after TLS certificate reload")
}
