package hscontrol

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"log"
	"net"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/certmagic"
	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/letsencrypt/pebble/v2/ca"
	"github.com/letsencrypt/pebble/v2/db"
	"github.com/letsencrypt/pebble/v2/va"
	"github.com/letsencrypt/pebble/v2/wfe"
	"github.com/mholt/acmez/v3/acme"
	"github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	acmeTestZone = "example.com."
	acmeTestHost = "headscale.example.com"
)

// testACME is an in-process ACME CA (Pebble) with an authoritative DNS
// server for acmeTestZone. The DNS server answers TXT from provider, so a
// DNS-01 record published through it is what the CA validates.
type testACME struct {
	directory string
	resolver  string
	roots     *x509.CertPool
	provider  *dnstest.Provider
}

// startTestACME validates HTTP-01 on httpPort and TLS-ALPN-01 on tlsPort
// of 127.0.0.1, where acmeTestHost resolves to.
func startTestACME(t *testing.T, httpPort, tlsPort int) *testACME {
	t.Helper()

	// Validate at once and deterministically.
	t.Setenv("PEBBLE_VA_NOSLEEP", "1")
	t.Setenv("PEBBLE_WFE_NONCEREJECT", "0")
	t.Setenv("PEBBLE_AUTHZREUSE", "0")

	provider := &dnstest.Provider{}
	resolver := startZoneServer(t, provider)

	logger := log.New(os.Stderr, "pebble ", log.LstdFlags)
	store := db.NewMemoryStore()
	authority := ca.New(logger, store, "", "ecdsa", 0, 1, map[string]ca.Profile{
		"default": {Description: "default"},
	})
	validator := va.New(logger, httpPort, tlsPort, false, resolver, store)
	acme := wfe.New(logger, store, validator, authority, []string{"pebble.letsencrypt.org"}, false, false, 0, 0)

	srv := httptest.NewTLSServer(acme.Handler())
	t.Cleanup(srv.Close)

	directoryRoots := x509.NewCertPool()
	directoryRoots.AddCert(srv.Certificate())

	prev := acmeTrustedRoots
	acmeTrustedRoots = directoryRoots

	t.Cleanup(func() { acmeTrustedRoots = prev })

	roots := x509.NewCertPool()
	roots.AddCert(authority.GetRootCert(0).Cert)

	return &testACME{
		directory: srv.URL + wfe.DirectoryPath,
		resolver:  resolver,
		roots:     roots,
		provider:  provider,
	}
}

// startZoneServer serves acmeTestZone over UDP and TCP on one port:
// certmagic finds the zone over UDP, Pebble validates over TCP.
func startZoneServer(t *testing.T, provider *dnstest.Provider) string {
	t.Helper()

	handler := dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
		m := new(dns.Msg)
		m.SetReply(r)
		m.Authoritative = true

		q := r.Question[0]
		hdr := dns.RR_Header{Name: q.Name, Class: dns.ClassINET, Rrtype: q.Qtype, Ttl: 60}

		switch {
		case !strings.HasSuffix(strings.ToLower(q.Name), acmeTestZone):
			m.Rcode = dns.RcodeRefused
		case q.Qtype == dns.TypeSOA && strings.EqualFold(q.Name, acmeTestZone):
			m.Answer = []dns.RR{&dns.SOA{
				Hdr: hdr, Ns: "ns." + acmeTestZone, Mbox: "hostmaster." + acmeTestZone,
				Serial: 1, Refresh: 60, Retry: 60, Expire: 60, Minttl: 60,
			}}
		case q.Qtype == dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: hdr, A: net.IPv4(127, 0, 0, 1)}}
		case q.Qtype == dns.TypeTXT:
			for _, v := range provider.Values(strings.ToLower(q.Name)) {
				m.Answer = append(m.Answer, &dns.TXT{Hdr: hdr, Txt: []string{v}})
			}
		}

		_ = w.WriteMsg(m)
	})

	var lc net.ListenConfig

	pc, err := lc.ListenPacket(t.Context(), "udp", "127.0.0.1:0")
	require.NoError(t, err)

	ln, err := lc.Listen(t.Context(), "tcp", pc.LocalAddr().String())
	require.NoError(t, err)

	for _, srv := range []*dns.Server{
		{PacketConn: pc, Handler: handler},
		{Listener: ln, Handler: handler},
	} {
		go func() { _ = srv.ActivateAndServe() }()

		t.Cleanup(func() { _ = srv.Shutdown() })
	}

	return pc.LocalAddr().String()
}

func freePort(t *testing.T) int {
	t.Helper()

	var lc net.ListenConfig

	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	require.NoError(t, err)

	_, port, err := net.SplitHostPort(ln.Addr().String())
	require.NoError(t, err)
	require.NoError(t, ln.Close())

	p, err := strconv.Atoi(port)
	require.NoError(t, err)

	return p
}

// TestDNS01SolverWait pins that headscale's own certificate waits for the
// value certmagic published, at the name it published it.
func TestDNS01SolverWait(t *testing.T) {
	provider := &dnstest.Provider{}

	var waited []string

	s := dns01Solver{
		DNS01Solver: &certmagic.DNS01Solver{
			DNSProvider: provider,
			Resolvers:   []string{startZoneServer(t, provider)},
		},
		wait: func(_ context.Context, fqdn, value string) error {
			waited = []string{fqdn, value}

			return nil
		},
	}
	ch := acme.Challenge{
		Type:             acme.ChallengeTypeDNS01,
		KeyAuthorization: "token.thumbprint",
		Identifier:       acme.Identifier{Type: "dns", Value: acmeTestHost},
	}

	require.NoError(t, s.Present(t.Context(), ch))
	require.NoError(t, s.Wait(t.Context(), ch))

	fqdn := "_acme-challenge." + acmeTestHost + "."

	require.Len(t, waited, 2)
	assert.Equal(t, fqdn, waited[0])
	assert.Equal(t, provider.Values(fqdn), waited[1:])
}

// TestACMETLSSettings obtains headscale's own certificate from Pebble with
// each challenge type, serving it the way [Headscale.Serve] does.
func TestACMETLSSettings(t *testing.T) {
	for _, challenge := range []string{
		types.DNS01ChallengeType,
		types.HTTP01ChallengeType,
		types.TLSALPN01ChallengeType,
	} {
		t.Run(challenge, func(t *testing.T) {
			httpPort, tlsPort := freePort(t), freePort(t)
			acme := startTestACME(t, httpPort, tlsPort)

			h := &Headscale{cfg: &types.Config{
				ServerURL: "https://" + acmeTestHost,
				Addr:      net.JoinHostPort("127.0.0.1", strconv.Itoa(tlsPort)),
				TLS: types.TLSConfig{ACME: types.ACMEConfig{
					Hostname:      acmeTestHost,
					ChallengeType: challenge,
					HTTPListen:    net.JoinHostPort("127.0.0.1", strconv.Itoa(httpPort)),
					URL:           acme.directory,
					CacheDir:      t.TempDir(),
				}},
				DNSChallenge: types.DNSChallengeConfig{
					Provider:  acme.provider,
					Resolvers: []string{acme.resolver},
				},
			}}

			bundle, err := h.getTLSSettings(t.Context())
			require.NoError(t, err)
			t.Cleanup(bundle.Stop)

			ln, err := tls.Listen("tcp", h.cfg.Addr, bundle.Config)
			require.NoError(t, err)
			t.Cleanup(func() { _ = ln.Close() })

			go func() {
				for {
					conn, err := ln.Accept()
					if err != nil {
						return
					}

					go func() {
						defer conn.Close()

						_ = conn.(*tls.Conn).HandshakeContext(t.Context()) //nolint:forcetypeassert // tls listener
					}()
				}
			}()

			if bundle.ACMEServer != nil {
				go func() { _ = bundle.ACMEServer.Serve(bundle.ACMEListener) }()

				t.Cleanup(func() { _ = bundle.ACMEServer.Close() })
			}

			require.NoError(t, bundle.Manage(t.Context()))

			assert.EventuallyWithT(t, func(c *assert.CollectT) {
				var d tls.Dialer

				d.Config = &tls.Config{ServerName: acmeTestHost, RootCAs: acme.roots, MinVersion: tls.VersionTLS12}

				conn, err := d.DialContext(t.Context(), "tcp", h.cfg.Addr)
				if assert.NoError(c, err) {
					_ = conn.Close()
				}
			}, 30*time.Second, 200*time.Millisecond, "headscale should serve a certificate from the ACME CA")

			if challenge == types.DNS01ChallengeType {
				assert.NotEmpty(t, acme.provider.Calls(), "DNS-01 must publish through the DNS provider")
				assert.EventuallyWithT(t, func(c *assert.CollectT) {
					assert.Empty(c, acme.provider.Values("_acme-challenge."+acmeTestHost+"."))
				}, 10*time.Second, 100*time.Millisecond, "challenge record should be removed")
			}
		})
	}
}
