package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/juanfont/headscale/integration/tsric"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTailscaleRustAxum tests that the tailscale-rs axum example can join a
// headscale network and serve HTTP to other peers on the tailnet.
//
// Architecture:
//
//	headscale (control) <--- tsic (probe client) --curl--> tsric (axum server)
//
// The test:
//  1. Creates a headscale environment with one regular Tailscale client (tsic)
//  2. Creates a tailscale-rs container running the axum example (tsric)
//  3. Verifies the tsric node registers with headscale
//  4. Uses the tsic client to curl the axum web server through the tailnet
func TestTailscaleRustAxum(t *testing.T) {
	IntegrationSkip(t)

	// Set up a scenario with one user and one regular Tailscale client.
	// The regular client acts as a "probe" to verify the tsric node
	// is reachable on the tailnet.
	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"}, //nolint:goconst // consistent with other integration tests
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tailscalers"),
		// The embedded DERP server uses a self-signed cert that
		// tailscale-rs cannot validate without a custom CA bundle, so
		// we route DERP through Tailscale's public relays.
		hsic.WithPublicDERP(),
		// TODO: drop WithoutTLS once tailscale-rs lets us inject the
		// headscale CA into its trust chain; until then the control
		// plane has to be plain HTTP for the Rust client to register.
		hsic.WithoutTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	// Get the headscale instance and probe client
	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1, "expected exactly 1 probe client")

	probeClient := allClients[0]

	// Create auth key for the tailscale-rs node
	users, err := headscale.ListUsers()
	require.NoError(t, err)
	require.NotEmpty(t, users, "expected at least one user")

	var userID uint64

	for _, u := range users {
		if u.GetName() == "user1" { //nolint:goconst
			userID = u.GetId()

			break
		}
	}

	require.NotZero(t, userID, "user1 not found")

	pak, err := headscale.CreateAuthKey(userID, false, true)
	require.NoError(t, err)

	// Determine the network and headscale connection details
	networks := scenario.Networks()
	require.NotEmpty(t, networks)

	network := networks[0]
	headscaleIP := headscale.GetIPInNetwork(network)
	headscaleHostname := headscale.GetHostname()
	headscaleEndpoint := headscale.GetEndpoint()

	t.Logf("Headscale endpoint: %s (hostname: %s, IP: %s)",
		headscaleEndpoint, headscaleHostname, headscaleIP)

	// Create the tailscale-rs container
	tsrsOpts := []tsric.Option{
		tsric.WithNetwork(network),
		tsric.WithHeadscaleURL(headscaleEndpoint),
		tsric.WithAuthKey(pak.GetKey()),
		tsric.WithExtraHosts([]string{headscaleHostname + ":" + headscaleIP}),
	}

	cert := headscale.GetCert()
	if len(cert) > 0 {
		tsrsOpts = append(tsrsOpts, tsric.WithCACert(cert))
	}

	t.Log("Creating tailscale-rs container (first build may take several minutes)...")

	tsrs, err := tsric.New(scenario.Pool(), tsrsOpts...)
	require.NoError(t, err, "failed to create tailscale-rs container")

	defer func() {
		_, _, err := tsrs.Shutdown()
		if err != nil {
			t.Logf("error shutting down tailscale-rs container: %s", err)
		}
	}()

	// Wait for the tailscale-rs node to appear in headscale's node list.
	// Verify it gets both IPv4 and IPv6 addresses and has the expected hostname.
	var (
		rustNodeIPv4 string
		rustNodeIPv6 string
		rustNodeName string
	)

	t.Log("Waiting for tailscale-rs node to register with headscale...")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(c, err)

		// Expect 2 nodes: 1 tsic probe + 1 tsric
		assert.GreaterOrEqual(c, len(nodes), 2,
			"expected at least 2 nodes (1 probe + 1 tailscale-rs)")

		// Find the tailscale-rs node by hostname prefix
		for _, n := range nodes {
			if strings.HasPrefix(n.GetGivenName(), "tsrs-") {
				addrs := n.GetIpAddresses()
				if len(addrs) > 0 {
					rustNodeIPv4 = addrs[0]
				}

				if len(addrs) > 1 {
					rustNodeIPv6 = addrs[1]
				}

				rustNodeName = n.GetGivenName()
			}
		}

		assert.NotEmpty(c, rustNodeIPv4, "tailscale-rs node should have an IPv4 address")
	}, 120*time.Second, 2*time.Second, "tailscale-rs node should register with headscale")

	require.NotEmpty(t, rustNodeIPv4, "failed to find tailscale-rs node IP")

	t.Logf("tailscale-rs node %q registered with IPv4=%s IPv6=%s",
		rustNodeName, rustNodeIPv4, rustNodeIPv6)

	// Verify IPv6 was allocated. The axum example only listens on IPv4,
	// so we can't curl via IPv6, but headscale should still assign both.
	assert.NotEmpty(t, rustNodeIPv6,
		"headscale should assign both IPv4 and IPv6 to the tailscale-rs node")

	// Verify the hostname propagated correctly from the config
	assert.True(t, strings.HasPrefix(rustNodeName, "tsrs-"),
		"tailscale-rs node name should start with tsrs- prefix")

	// Verify the probe client sees the tailscale-rs node as a peer
	t.Log("Verifying probe client sees tailscale-rs as a peer...")

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		status, err := probeClient.Status()
		assert.NoError(c, err)

		found := false

		for _, peerKey := range status.Peers() {
			peer := status.Peer[peerKey]
			if strings.HasPrefix(peer.HostName, "tsrs-") {
				found = true
			}
		}

		assert.True(c, found, "probe client should see tsrs node as a peer")
	}, 30*time.Second, 2*time.Second, "probe should see tailscale-rs peer in status")

	// Test 1: GET /index.html — verify the axum web server serves content
	axumURL := fmt.Sprintf("http://%s/index.html", rustNodeIPv4)

	t.Logf("Verifying axum web server is reachable at %s via probe client...", axumURL)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := probeClient.Curl(axumURL)
		assert.NoError(c, err, "curl to axum server failed")
		assert.Contains(c, result, "tailscale-rs",
			"expected index.html to contain 'tailscale-rs'")
	}, 120*time.Second, 2*time.Second, "axum /index.html should be reachable from probe client")

	t.Log("axum web server is serving content through the tailnet")

	// Test 2: GET /assets/index.css — verify static asset serving works
	cssURL := fmt.Sprintf("http://%s/assets/index.css", rustNodeIPv4)

	t.Logf("Verifying static asset at %s...", cssURL)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		result, err := probeClient.Curl(cssURL)
		assert.NoError(c, err, "curl to CSS asset failed")
		assert.Contains(c, result, "font-family",
			"expected CSS file to contain 'font-family'")
	}, 10*time.Second, 1*time.Second, "axum should serve static CSS assets")

	// Test 3: Sequential POST /count — verify the counter increments correctly.
	// This exercises multiple TCP connections and proves the netstack maintains
	// state across requests.
	countURL := fmt.Sprintf("http://%s/count", rustNodeIPv4)

	t.Logf("Verifying /count POST endpoint increments at %s...", countURL)

	// First POST establishes connectivity and gets the initial counter value
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		stdout, _, err := probeClient.Execute([]string{
			"curl", "--silent",
			"--connect-timeout", "3",
			"--max-time", "5",
			"-X", "POST",
			countURL,
		})
		assert.NoError(c, err, "curl POST to /count failed")
		assert.Contains(c, stdout, `"count"`,
			"expected /count response to contain 'count'")
	}, 30*time.Second, 2*time.Second, "axum /count POST should work")

	// Fire several more POSTs and verify the counter advances.
	// The axum handler returns {"count": N} where N is the pre-increment value.
	// After the initial EventuallyWithT loop we don't know the exact counter,
	// but two back-to-back POSTs should return consecutive values.
	t.Log("Verifying counter increments across multiple requests...")

	var firstCount, secondCount string

	stdout1, _, err := probeClient.Execute([]string{
		"curl", "--silent", "--max-time", "5", "-X", "POST", countURL,
	})
	require.NoError(t, err, "first sequential POST failed")

	firstCount = stdout1

	stdout2, _, err := probeClient.Execute([]string{
		"curl", "--silent", "--max-time", "5", "-X", "POST", countURL,
	})
	require.NoError(t, err, "second sequential POST failed")

	secondCount = stdout2

	t.Logf("Counter responses: first=%s second=%s", firstCount, secondCount)

	// Verify they're different (counter is incrementing)
	require.NotEqual(t, firstCount, secondCount,
		"counter should increment between sequential POST requests")

	t.Log("TestTailscaleRustAxum: all checks passed")
}
