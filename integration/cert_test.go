package integration

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/dockertestutil"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/miekg/dns"
	"github.com/ory/dockertest/v3"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errNoSuiteAddr = errors.New("test suite has no address in the scenario network")

const (
	webserverPort = 80
	// webserverListing is in every page tsic's web server returns.
	webserverListing = "Directory listing"
	// headersPort is where headersEcho listens.
	headersPort = 8081
	// spoofedLogin is an identity header a client claims for itself.
	spoofedLogin = "Tailscale-User-Login: mallory@test.no"
)

// headersEcho answers every request with the request's headers.
const headersEcho = `import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Echo(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(str(self.headers).encode())


HTTPServer(("127.0.0.1", int(sys.argv[1])), Echo).serve_forever()
`

// TestTailscaleCert runs `tailscale cert` on every client version against
// headscale's real rfc2136 provider, then runs every `tailscale serve`
// mode on each and fetches it from another user's node. A TSIG-checked
// DNS server and Pebble (Let's Encrypt's test CA) run inside this test
// process; the containers reach them through the test suite's address in
// the scenario network.
//
// Not parallel: Pebble reads its knobs from the environment.
func TestTailscaleCert(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
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

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{
			tsic.WithCACert(pebbleCA),
			// So curl trusts certificates Pebble issues.
			tsic.WithCACert(issuerRoot),
			tsic.WithPackages("curl"),
			// Backend for the serve proxies.
			tsic.WithWebserver(webserverPort),
			tsic.WithExtraCommands("export TS_DEBUG_ACME_DIRECTORY_URL=" + directoryURL),
		},
		hsic.WithTestName("cert"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_CERTIFICATES_ENABLED":          "true",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_NAME":       "rfc2136",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_SERVER":     net.JoinHostPort(suiteIP, zone.port),
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_NAME":   "headscale.",
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY_ALG":    dns.HmacSHA256,
			"HEADSCALE_DNS_CHALLENGE_PROVIDER_KEY":        tsigKey,
			"HEADSCALE_DNS_CHALLENGE_PROPAGATION_TIMEOUT": "0s",
		}),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(issuerRoot))

	for _, client := range allClients {
		fqdn, err := client.FQDN()
		require.NoError(t, err)

		fqdn = strings.TrimSuffix(fqdn, ".")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(c, err)
			assert.Contains(c, status.CertDomains, fqdn)
		}, 30*time.Second, 500*time.Millisecond, "%s should be offered a certificate name", client.Hostname())

		_, stderr, err := client.Execute(
			[]string{"tailscale", "cert", "--cert-file", "/tmp/cert.pem", "--key-file", "/tmp/key.pem", fqdn},
			dockertestutil.ExecuteCommandTimeout(2*time.Minute),
		)
		require.NoError(t, err, "tailscale cert on %s: %s", client.Hostname(), stderr)

		certPEM, err := client.ReadFile("/tmp/cert.pem")
		require.NoError(t, err)

		leaf, intermediates := parseChain(t, certPEM)
		_, err = leaf.Verify(x509.VerifyOptions{
			DNSName:       fqdn,
			Roots:         roots,
			Intermediates: intermediates,
		})
		require.NoError(t, err, "certificate for %s", fqdn)
	}

	// serve refuses HTTPS without the https cap. With it, every serve mode
	// works: HTTPS from text or a proxy, plain HTTP, raw TCP, and TCP behind
	// TLS with the certificate obtained above. Proxied requests carry the
	// identity of the user-owned node that sent them, replacing any the
	// client sent itself. The fetcher belongs to a second user, whose
	// display name differs from its login, so the headers must name the
	// requester rather than the serving node's owner, and login apart from
	// name.
	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	_, err = headscale.Execute([]string{
		"headscale", "users", "create", "user2",
		"--email=user2@test.no", "--display-name=User Two",
	})
	require.NoError(t, err)

	users, err := headscale.MapUsers()
	require.NoError(t, err)

	key, err := scenario.CreatePreAuthKey(mustParseID(users["user2"].Id), false, false)
	require.NoError(t, err)

	fetcher, err := scenario.CreateTailscaleNode("head",
		tsic.WithNetwork(scenario.Networks()[0]),
		tsic.WithCACert(issuerRoot),
		tsic.WithPackages("curl"),
	)
	require.NoError(t, err)

	scenario.GetOrCreateUser("user2").Clients[fetcher.Hostname()] = fetcher

	require.NoError(t, fetcher.Login(headscale.GetEndpoint(), key.Key))
	require.NoError(t, fetcher.WaitForRunning(integrationutil.PeerSyncTimeout()))

	backend := fmt.Sprintf("127.0.0.1:%d", webserverPort)
	headersBackend := fmt.Sprintf("127.0.0.1:%d", headersPort)

	for _, client := range allClients {
		fqdn, err := client.FQDN()
		require.NoError(t, err)

		fqdn = strings.TrimSuffix(fqdn, ".")

		require.NoError(t, client.WriteFile("/tmp/headers.py", []byte(headersEcho)))
		_, stderr, err := client.Execute([]string{
			"sh", "-c", fmt.Sprintf("python3 /tmp/headers.py %d >/dev/null 2>&1 &", headersPort),
		})
		require.NoError(t, err, "starting headers echo on %s: %s", client.Hostname(), stderr)

		for _, args := range [][]string{
			{"text:" + client.Hostname()},
			{"--https=8443", "http://" + backend},
			{"--http=8080", "text:" + client.Hostname()},
			{"--tcp=2222", "tcp://" + backend},
			{"--tls-terminated-tcp=9443", "tcp://" + backend},
			{"--https=8444", "http://" + headersBackend},
		} {
			_, stderr, err := client.Execute(append([]string{"tailscale", "serve", "--bg", "--yes"}, args...))
			require.NoError(t, err, "tailscale serve %v on %s: %s", args, client.Hostname(), stderr)
		}

		for url, wants := range map[string][]string{
			"https://" + fqdn:           {client.Hostname()},
			"https://" + fqdn + ":8443": {webserverListing},
			"http://" + fqdn + ":8080":  {client.Hostname()},
			"http://" + fqdn + ":2222":  {webserverListing},
			"https://" + fqdn + ":9443": {webserverListing},
			"https://" + fqdn + ":8444": {
				"Tailscale-User-Login: user2@test.no",
				"Tailscale-User-Name: User Two",
			},
		} {
			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				body, _, err := fetcher.Execute([]string{
					"curl", "--silent", "--fail", "--max-time", "10",
					"--header", spoofedLogin,
					"--connect-to", fqdn + "::" + client.MustIPv4().String() + ":", url,
				}, dockertestutil.ExecuteCommandTimeout(20*time.Second))
				assert.NoError(c, err)

				for _, want := range wants {
					assert.Contains(c, body, want)
				}

				assert.NotContains(c, body, spoofedLogin)
			}, 60*time.Second, time.Second, "%s should be served", url)
		}
	}
}

// suiteAddrIn returns this test process's address in network, which the
// containers on that network can reach.
func suiteAddrIn(network *dockertest.Network) (string, error) {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return "", err
	}

	for _, cfg := range network.Network.IPAM.Config {
		_, subnet, err := net.ParseCIDR(cfg.Subnet)
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && subnet.Contains(ipnet.IP) {
				return ipnet.IP.String(), nil
			}
		}
	}

	return "", errNoSuiteAddr
}

// updateDNS is an authoritative DNS server for one zone that accepts
// RFC 2136 updates signed with a TSIG key, like a BIND zone with an
// update-policy, so an issued certificate proves headscale signs them. It
// serves TCP only: both rfc2136 and Pebble use TCP.
type updateDNS struct {
	addr, port string

	mu  sync.Mutex
	txt map[string][]string
}

func startUpdateDNS(t *testing.T, keyName, key string) *updateDNS {
	t.Helper()

	ln, err := net.Listen("tcp", ":0") //nolint:noctx,gosec // containers must reach it
	require.NoError(t, err)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)

	z := &updateDNS{addr: net.JoinHostPort("127.0.0.1", port), port: port, txt: map[string][]string{}}
	srv := &dns.Server{
		Listener:   ln,
		TsigSecret: map[string]string{keyName: key},
		Handler:    z,
		// The default rejects UPDATE as not implemented.
		MsgAcceptFunc: func(dns.Header) dns.MsgAcceptAction { return dns.MsgAccept },
	}

	go func() { _ = srv.ActivateAndServe() }()

	t.Cleanup(func() { _ = srv.Shutdown() })

	return z
}

func (z *updateDNS) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	m := new(dns.Msg)
	m.SetReply(r)
	m.Authoritative = true

	z.mu.Lock()
	defer z.mu.Unlock()

	if r.Opcode == dns.OpcodeUpdate {
		if r.IsTsig() == nil || w.TsigStatus() != nil {
			m.Rcode = dns.RcodeRefused
		} else {
			for _, rr := range r.Ns {
				txt, ok := rr.(*dns.TXT)
				if !ok {
					continue
				}

				name := strings.ToLower(txt.Hdr.Name)
				value := strings.Join(txt.Txt, "")

				switch txt.Hdr.Class {
				case dns.ClassINET:
					z.txt[name] = append(z.txt[name], value)
				case dns.ClassNONE:
					z.txt[name] = slices.DeleteFunc(z.txt[name], func(v string) bool { return v == value })
				}
			}

			// rfc2136 rejects an unsigned reply to a signed update.
			tsig := r.IsTsig()
			m.SetTsig(tsig.Hdr.Name, tsig.Algorithm, 300, time.Now().Unix())
		}

		_ = w.WriteMsg(m)

		return
	}

	for _, q := range r.Question {
		if q.Qtype != dns.TypeTXT {
			continue
		}

		for _, v := range z.txt[strings.ToLower(q.Name)] {
			m.Answer = append(m.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
				Txt: []string{v},
			})
		}
	}

	_ = w.WriteMsg(m)
}

// startPebble runs Pebble, validating DNS-01 challenges against resolver,
// and returns its ACME directory URL as the containers see it, the
// certificate they must trust to reach it, and the root of the
// certificates it issues. Pebble only accepts requests signed for an
// https URL, so it cannot run over plain HTTP.
func startPebble(t *testing.T, resolver *updateDNS, suiteIP string) (string, []byte, []byte) {
	t.Helper()

	// Validate at once and deterministically: no random delay, no
	// rejected nonces, no authorization reuse across orders.
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	t.Setenv("PEBBLE_AUTHZREUSE", "0")

	logger := log.New(os.Stderr, "pebble ", log.LstdFlags)
	store := db.NewMemoryStore()
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default"},
	})
	validator := va.New(logger, 0, 0, false, resolver.addr, store)
	acme := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, false, 0, 0)

	ln, err := net.Listen("tcp", ":0") //nolint:noctx,gosec // containers must reach it
	require.NoError(t, err)

	cert, certPEM := selfSignedCert(t, suiteIP)
	srv := &http.Server{
		Handler:           withFinalizeLocation(acme.Handler()),
		ReadHeaderTimeout: 10 * time.Second,
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
	}

	go func() { _ = srv.ServeTLS(ln, "", "") }()

	t.Cleanup(func() { _ = srv.Close() })

	port := strconv.Itoa(ln.Addr().(*net.TCPAddr).Port) //nolint:forcetypeassert // tcp listener

	issuerRoot := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: authority.GetRootCert(0).DER})

	return "https://" + net.JoinHostPort(suiteIP, port) + wfe.DirectoryPath, certPEM, issuerRoot
}

// withFinalizeLocation adds the order URL as Location to finalize replies.
// The Tailscale client polls the order at that URL until the certificate
// is issued; Let's Encrypt sends it, Pebble does not.
func withFinalizeLocation(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if id, ok := strings.CutPrefix(r.URL.Path, "/finalize-order/"); ok {
			w.Header().Set("Location", "https://"+r.Host+"/my-order/"+id)
		}

		next.ServeHTTP(w, r)
	})
}

// selfSignedCert returns a certificate for ip that is its own CA.
func selfSignedCert(t *testing.T, ip string) (tls.Certificate, []byte) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	tmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "pebble"},
		IPAddresses:           []net.IP{net.ParseIP(ip)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)

	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key},
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// parseChain returns the leaf of a PEM chain and a pool of the rest.
func parseChain(t *testing.T, chainPEM []byte) (*x509.Certificate, *x509.CertPool) {
	t.Helper()

	var certs []*x509.Certificate

	for block, rest := pem.Decode(chainPEM); block != nil; block, rest = pem.Decode(rest) {
		cert, err := x509.ParseCertificate(block.Bytes)
		require.NoError(t, err)

		certs = append(certs, cert)
	}

	require.NotEmpty(t, certs, "no certificate in PEM")

	intermediates := x509.NewCertPool()
	for _, c := range certs[1:] {
		intermediates.AddCert(c)
	}

	return certs[0], intermediates
}
