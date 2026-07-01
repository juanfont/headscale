package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/ory/dockertest/v3"
	"github.com/samber/lo"
	"github.com/stretchr/testify/require"
	"tailscale.com/control/controlbase"
	"tailscale.com/control/controlhttp/controlhttpcommon"
	"tailscale.com/net/wsconn"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
	"tailscale.com/util/rands"
)

// Tailscale's JS/WASM control client opens /ts2021 as a browser WebSocket — an
// HTTP GET upgrade — rather than the native client's HTTP POST upgrade. A router
// that registers /ts2021 for POST only rejects that GET with 405 before the
// Noise handshake starts, which breaks every WASM client (issue #3357).
//
// These two tests guard that path against real headscale:
//
//   - TestTS2021WebSocketGET dials the WebSocket GET directly from the test
//     process using the same coder/websocket + controlbase primitives the WASM
//     client uses. It is fast and always on.
//   - TestTS2021WASMClientUnderNode runs the *actual* tailscale.com js/wasm
//     control dial (integration/wasmic/wasmclient, built for GOOS=js) inside a
//     Node container, alongside normal Tailscale clients, and asserts it
//     completes the Noise handshake with headscale over the WebSocket.
//
// The server cannot tell the two apart: both send GET /ts2021 with
// Sec-WebSocket-Protocol: tailscale-control-protocol. Before the fix both fail
// with 405; after it, both complete the handshake.

// TestTS2021WebSocketGET connects to /ts2021 over a WebSocket GET from the test
// process and completes the Noise handshake, exactly as a browser/WASM client
// would.
func TestTS2021WebSocketGET(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)

	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("ts2021ws"))
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	conn, err := dialTS2021WebSocket(t, headscale.GetEndpoint(), headscale.GetCert())
	require.NoError(t, err,
		"WebSocket GET to /ts2021 must reach NoiseUpgradeHandler, not be rejected by the router with 405")
	require.NotNil(t, conn)
	t.Cleanup(func() { _ = conn.Close() })

	t.Logf("noise established over websocket, protocol version %d", conn.ProtocolVersion())
}

// TestTS2021WASMClientUnderNode runs the real tailscale.com js/wasm control dial
// inside a Node container against real headscale, next to normal Tailscale
// clients, and asserts the WASM client completes the /ts2021 handshake.
func TestTS2021WASMClientUnderNode(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		NodesPerUser: 2,
		Users:        []string{"user1"},
		Networks: map[string]NetworkSpec{
			"wasmnet": {Users: []string{"user1"}},
		},
		ExtraService: map[string][]extraServiceFunc{
			"wasmnet": {wasmClientService},
		},
		// The wasm client image builds from this module; pair it with the
		// head Tailscale clients so the whole environment is current.
		Versions: []string{"head"},
	}

	scenario, err := NewScenario(spec)

	require.NoErrorf(t, err, "failed to create scenario: %s", err)
	defer scenario.ShutdownAssertNoPanics(t)

	// The Tailscale JS/WASM client dials the control server as a WebSocket.
	// client_js.go only honours a custom port for ws:// (plain HTTP); over
	// wss:// it always targets :443, so it cannot reach a TLS control server on
	// :8080. Run headscale without TLS, matching the http:// setup in the issue.
	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("ts2021wasm"),
		hsic.WithoutTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIPs, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	// Normal Tailscale clients come up and form a working tailnet alongside the
	// WASM control client.
	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Sanity-check the tailnet the WASM client is joining: the normal clients
	// must be able to reach each other.
	allAddrs := lo.Map(allIPs, func(x netip.Addr, _ int) string { return x.String() })
	assertPingAll(t, allClients, allAddrs)

	services, err := scenario.Services("wasmnet")
	require.NoError(t, err)
	require.Len(t, services, 1, "expected the wasm client container")

	wasm := services[0]
	controlURL := headscale.GetEndpoint()

	// Fetch the server's Noise key here and pass it to the WASM client: Go's
	// net/http DNS resolver is unavailable under GOOS=js, so the client can only
	// use the JS WebSocket transport, not an HTTP GET to /key.
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	controlKey, err := fetchServerNoiseKey(ctx, &http.Client{Timeout: 15 * time.Second}, controlURL)
	require.NoError(t, err)
	controlKeyText, err := controlKey.MarshalText()
	require.NoError(t, err)

	// Run the real js/wasm control client under Node: it dials /ts2021 as a
	// WebSocket GET; success means the Noise handshake completed.
	stdout, stderr, err := dockertestutil.ExecuteCommand(
		wasm,
		[]string{"node", "/app/wasm_exec_node.js", "/app/client.wasm", controlURL, string(controlKeyText)},
		[]string{},
		dockertestutil.ExecuteCommandTimeout(60*time.Second),
	)
	t.Logf("wasm client stdout:\n%s", stdout)
	t.Logf("wasm client stderr:\n%s", stderr)

	require.NoError(t, err,
		"wasm control client must connect to /ts2021 over websocket (405 means the router rejected the GET)")
	require.Contains(t, stdout, "WASM_TS2021_OK",
		"wasm control client should report a completed Noise handshake")
}

// wasmClientService builds and starts the Node + js/wasm control-client
// container (Dockerfile.wasmclient) on the given network so it can reach
// headscale by hostname. It idles; the test execs the client on demand.
func wasmClientService(s *Scenario, networkName string) (*dockertest.Resource, error) {
	hash := rands.HexString(hsicOIDCMockHashLength)
	hostname := "hs-wasmclient-" + hash

	network, ok := s.networks[s.prefixedNetworkName(networkName)]
	if !ok {
		return nil, fmt.Errorf("network does not exist: %s", networkName) //nolint:err113
	}

	runOpts := &dockertest.RunOptions{
		Name:     hostname,
		Networks: []*dockertest.Network{network},
		Env:      []string{},
	}
	dockertestutil.DockerAddIntegrationLabels(runOpts, "wasmclient")

	buildOpts := &dockertest.BuildOptions{
		Dockerfile: "Dockerfile.wasmclient",
		ContextDir: dockerContextPath,
	}

	resource, err := s.pool.BuildAndRunWithBuildOptions(
		buildOpts,
		runOpts,
		dockertestutil.DockerRestartPolicy,
	)
	if err != nil {
		return nil, fmt.Errorf("building wasm client container: %w", err)
	}

	return resource, nil
}

// dialTS2021WebSocket opens /ts2021 as a WebSocket GET (subprotocol
// tailscale-control-protocol) and completes the Noise handshake, mirroring what
// tailscale.com/control/controlhttp/client_js.go does in a browser. It returns
// the established Noise connection, or an error (a router that only allows POST
// returns 405 here).
func dialTS2021WebSocket(t *testing.T, endpoint string, caCert []byte) (*controlbase.Conn, error) {
	t.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	u, err := url.Parse(endpoint)
	require.NoError(t, err)

	httpClient := &http.Client{Timeout: 15 * time.Second}

	if u.Scheme == "https" {
		pool := x509.NewCertPool()
		pool.AppendCertsFromPEM(caCert)
		httpClient.Transport = &http.Transport{
			TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12},
		}
	}

	controlKey, err := fetchServerNoiseKey(ctx, httpClient, endpoint)
	require.NoError(t, err)

	init, cont, err := controlbase.ClientDeferred(
		key.NewMachine(),
		controlKey,
		uint16(tailcfg.CurrentCapabilityVersion),
	)
	require.NoError(t, err)

	wsScheme := "ws"
	if u.Scheme == "https" {
		wsScheme = "wss"
	}

	wsURL := &url.URL{
		Scheme: wsScheme,
		Host:   u.Host,
		Path:   "/ts2021",
		RawQuery: url.Values{
			controlhttpcommon.HandshakeHeaderName: []string{base64.StdEncoding.EncodeToString(init)},
		}.Encode(),
	}

	wsConn, resp, err := websocket.Dial(ctx, wsURL.String(), &websocket.DialOptions{
		Subprotocols: []string{controlhttpcommon.UpgradeHeaderValue},
		HTTPClient:   httpClient,
	})
	if resp != nil && resp.Body != nil {
		_ = resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	netConn := wsconn.NetConn(ctx, wsConn, websocket.MessageBinary, wsURL.String())

	cbConn, err := cont(ctx, netConn)
	if err != nil {
		_ = netConn.Close()
		return nil, fmt.Errorf("noise handshake over websocket: %w", err)
	}

	return cbConn, nil
}

// fetchServerNoiseKey retrieves headscale's Noise public key from /key, the same
// endpoint a real client consults before dialing /ts2021.
func fetchServerNoiseKey(
	ctx context.Context,
	client *http.Client,
	endpoint string,
) (key.MachinePublic, error) {
	var zero key.MachinePublic

	keyURL := fmt.Sprintf("%s/key?v=%d", endpoint, tailcfg.CurrentCapabilityVersion)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, keyURL, nil)
	if err != nil {
		return zero, err
	}

	resp, err := client.Do(req)
	if err != nil {
		return zero, err
	}
	defer resp.Body.Close()

	var k tailcfg.OverTLSPublicKeyResponse

	err = json.NewDecoder(resp.Body).Decode(&k)
	if err != nil {
		return zero, fmt.Errorf("decoding /key response: %w", err)
	}

	if k.PublicKey.IsZero() {
		return zero, errors.New("server returned zero Noise public key") //nolint:err113
	}

	return k.PublicKey, nil
}
