package integration

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/funnel"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/tsnet"
)

// TestTailscaleFunnel runs the real `tailscale funnel` behind the funnel
// relay. Headscale gives the client the funnel attribute from the policy
// and the relay, a tsnet node tagged tag:relay running in this test
// process, the ingress capability towards it. A container outside the
// tailnet then fetches the client's name through the relay: the client
// terminates TLS with the certificate Pebble issued it, and its backend
// sees a funnel request. A port the client only serves to the tailnet,
// and a port after `funnel off`, are not reachable through the relay.
//
// Not parallel: Pebble reads its knobs from the environment.
func TestTailscaleFunnel(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)

	defer scenario.ShutdownAssertNoPanics(t)

	suiteIP, err := suiteAddrIn(scenario.Networks()[0])
	require.NoError(t, err)

	tsigKey := base64.StdEncoding.EncodeToString([]byte("headscale-integration-tsig-key"))
	zone := startUpdateDNS(t, "headscale.", tsigKey)
	directoryURL, pebbleCA, issuerRoot := startPebble(t, zone, suiteIP)

	pol := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:relay"): policyv2.Owners{usernameOwner("user1@")},
		},
		ACLs: []policyv2.ACL{{
			Action:       "accept",
			Sources:      []policyv2.Alias{policyv2.Wildcard},
			Destinations: []policyv2.AliasWithPorts{{Alias: policyv2.Wildcard, Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}}},
		}},
		NodeAttrs: []policyv2.NodeAttrGrant{{
			Targets: policyv2.Aliases{new(policyv2.Username("user1@"))},
			Attrs:   []nodecap.Cap{nodecap.Funnel},
		}},
	}

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithCACert(pebbleCA),
			tsic.WithPackages("curl"),
			tsic.WithWebserver(webserverPort),
			tsic.WithExtraCommands("export TS_DEBUG_ACME_DIRECTORY_URL=" + directoryURL),
		},
		hsic.WithTestName("funnel"),
		hsic.WithACLPolicy(pol),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_CERTIFICATES_ENABLED":          "true",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":       "rfc2136",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_SERVER":     net.JoinHostPort(suiteIP, zone.port),
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_NAME":   "headscale.",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_ALG":    dns.HmacSHA256,
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY":        tsigKey,
			"HEADSCALE_DNS_CHALLENGE_PROPAGATION_TIMEOUT": "0s",
			"HEADSCALE_FUNNEL_ENABLED":                    "true",
			"HEADSCALE_FUNNEL_RELAY_TAGS":                 "tag:relay",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1)

	client := allClients[0]

	fqdn, err := client.FQDN()
	require.NoError(t, err)

	fqdn = strings.TrimSuffix(fqdn, ".")

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	users, err := headscale.MapUsers()
	require.NoError(t, err)

	key, err := scenario.CreatePreAuthKeyWithTags(mustParseID(users["user1"].Id), false, false, []string{"tag:relay"})
	require.NoError(t, err)

	// The relay: a tagged tsnet node in this process, listening on the
	// suite address. Its listeners stand for public ports 443 and 8443.
	// It reaches headscale over TLS, so it must trust the test CA; the
	// system roots are read from SSL_CERT_FILE on first use.
	caFile := filepath.Join(t.TempDir(), "headscale-ca.pem")
	require.NoError(t, os.WriteFile(caFile, headscale.GetCert(), 0o600))
	t.Setenv("SSL_CERT_FILE", caFile)

	srv := &tsnet.Server{
		Hostname:   "relay",
		Dir:        t.TempDir(),
		ControlURL: headscale.GetEndpoint(),
		AuthKey:    key.Key,
		Logf:       func(string, ...any) {},
	}

	t.Cleanup(func() { srv.Close() })

	upCtx, cancelUp := context.WithTimeout(t.Context(), 2*time.Minute)
	defer cancelUp()

	_, err = srv.Up(upCtx)
	require.NoError(t, err, "relay should join the tailnet")

	backend, err := funnel.NewTSNetBackend(srv)
	require.NoError(t, err)

	relay := &funnel.Relay{Backend: backend}
	ctx, cancel := context.WithCancel(t.Context())
	t.Cleanup(cancel)

	relayAddr := map[uint16]string{}

	for _, port := range []uint16{443, 8443} {
		ln, err := net.Listen("tcp", net.JoinHostPort(suiteIP, "0")) //nolint:noctx // containers must reach it
		require.NoError(t, err)

		relayAddr[port] = ln.Addr().String()

		go func() { _ = relay.Serve(ctx, ln, port) }()
	}

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		st, err := backend.Status(t.Context())
		assert.NoError(c, err)

		var found bool

		for _, p := range st.Peer {
			found = found || strings.TrimSuffix(p.DNSName, ".") == fqdn
		}

		assert.True(c, found, "relay should have %s as a peer", fqdn)
	}, 30*time.Second, 500*time.Millisecond, "relay should see the funnel node")

	// Funnel public 443 to the headers echo, so the request the backend
	// gets shows it came through funnel; serve 8443 to the tailnet only.
	require.NoError(t, client.WriteFile("/tmp/headers.py", []byte(headersEcho)))
	_, stderr, err := client.Execute([]string{
		"sh", "-c", fmt.Sprintf("python3 /tmp/headers.py %d >/dev/null 2>&1 &", headersPort),
	})
	require.NoError(t, err, "starting headers echo: %s", stderr)

	_, stderr, err = client.Execute([]string{
		"tailscale", "funnel", "--bg", "--yes", fmt.Sprintf("http://127.0.0.1:%d", headersPort),
	})
	require.NoError(t, err, "tailscale funnel: %s", stderr)

	_, stderr, err = client.Execute([]string{
		"tailscale", "serve", "--bg", "--yes", "--https=8443", fmt.Sprintf("http://127.0.0.1:%d", webserverPort),
	})
	require.NoError(t, err, "tailscale serve: %s", stderr)

	// The fetcher is outside the tailnet: never logged in.
	fetcher, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(scenario.Networks()[0]),
		tsic.WithCACert(issuerRoot),
		tsic.WithPackages("curl"),
	)
	require.NoError(t, err)

	// fetchVia fetches https://fqdn:port/ from the fetcher, connecting to
	// addr instead of resolving fqdn.
	fetchVia := func(addr string, port uint16, extra ...string) (string, error) {
		host, addrPort, err := net.SplitHostPort(addr)
		if err != nil {
			return "", err
		}

		args := append([]string{
			"curl", "--silent", "--fail", "--max-time", "10",
			"--connect-to", fmt.Sprintf("%s:%d:%s:%s", fqdn, port, host, addrPort),
		}, extra...)

		body, _, err := fetcher.Execute(
			append(args, "https://"+net.JoinHostPort(fqdn, strconv.Itoa(int(port)))+"/"),
			dockertestutil.ExecuteCommandTimeout(20*time.Second),
		)

		return body, err
	}

	fetch := func(port uint16) (string, error) { return fetchVia(relayAddr[port], port) }

	// The first request also waits for the node's certificate from Pebble.
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		body, err := fetch(443)
		assert.NoError(c, err)
		assert.Contains(c, body, "Tailscale-Funnel-Request")
	}, 90*time.Second, time.Second, "https://%s should be funnelled", fqdn)

	_, err = fetch(8443)
	require.Error(t, err, "a port served to the tailnet only must not be reachable through the relay")

	// Behind a reverse proxy that terminates TLS, as Nginx Proxy Manager
	// does: it opens a new TLS connection to the relay named after the
	// requested host, which the node terminates with its own certificate.
	nodeRoots := x509.NewCertPool()
	require.True(t, nodeRoots.AppendCertsFromPEM(issuerRoot))

	proxyAddr := startTerminatingProxy(t, suiteIP, relayAddr[443], nodeRoots)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		// The proxy's own certificate is self-signed.
		body, err := fetchVia(proxyAddr, 443, "--insecure")
		assert.NoError(c, err)
		assert.Contains(c, body, "Tailscale-Funnel-Request")
	}, 30*time.Second, time.Second, "https://%s should be funnelled behind a TLS-terminating proxy", fqdn)

	_, stderr, err = client.Execute([]string{"tailscale", "funnel", "--https=443", "off"})
	require.NoError(t, err, "tailscale funnel off: %s", stderr)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		_, err := fetch(443)
		assert.Error(c, err)
	}, 30*time.Second, time.Second, "https://%s should no longer be funnelled", fqdn)
}

// startTerminatingProxy plays a reverse proxy that terminates TLS in front
// of the relay at relayAddr, such as Nginx Proxy Manager with
// `proxy_ssl_server_name on; proxy_ssl_name $host;`: it serves its own
// certificate, then opens a new TLS connection to the relay with the
// requested host as server name, verifying the node's certificate against
// nodeRoots. It returns the address the proxy listens on.
func startTerminatingProxy(t *testing.T, suiteIP, relayAddr string, nodeRoots *x509.CertPool) string {
	t.Helper()

	cert, _ := selfSignedCert(t, suiteIP)

	transport := &http.Transport{
		// Every request goes to the relay; the URL host only names the node.
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer

			return d.DialContext(ctx, network, relayAddr)
		},
		TLSClientConfig: &tls.Config{RootCAs: nodeRoots, MinVersion: tls.VersionTLS12},
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.SetURL(&url.URL{Scheme: "https", Host: pr.In.Host})
			pr.Out.Host = pr.In.Host
			pr.SetXForwarded()
		},
		Transport: transport,
	}

	ln, err := (&net.ListenConfig{}).Listen(t.Context(), "tcp", net.JoinHostPort(suiteIP, "0"))
	require.NoError(t, err)

	srv := &http.Server{
		Handler:           proxy,
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = srv.ServeTLS(ln, "", "") }()

	t.Cleanup(func() { _ = srv.Close() })

	return ln.Addr().String()
}
