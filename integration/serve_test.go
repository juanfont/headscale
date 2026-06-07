package integration

import (
	"strings"
	"testing"
	"time"

	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestServeHTTPSCertDomains verifies that, when per-node HTTPS certificates
// are enabled (dns.https_certs), headscale advertises each node's own FQDN
// in DNSConfig.CertDomains. The Tailscale client treats `tailscale serve
// --https` / `tailscale cert` as unavailable unless CertDomains is set, so
// this is the control-plane signal that unlocks the feature.
//
// The full certificate issuance flow (ACME DNS-01 against Let's Encrypt) is
// intentionally not exercised here: it requires base_domain to be a real,
// publicly delegated zone reachable by Let's Encrypt, which is not available
// in CI. The embedded authoritative DNS server and the /machine/set-dns
// handler are covered by unit tests in hscontrol/dns and hscontrol.
func TestServeHTTPSCertDomains(t *testing.T) {
	IntegrationSkip(t)
	t.Parallel()

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{"user1"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("servecerts"),
		hsic.WithConfigEnv(map[string]string{
			"HEADSCALE_DNS_HTTPS_CERTS_ENABLED": "true",
			// A non-privileged port avoids clashing with anything the
			// container might bind on :53; delegation is irrelevant here
			// since we only assert the advertised CertDomains.
			"HEADSCALE_DNS_HTTPS_CERTS_LISTEN_ADDR": ":15353",
		}),
	)
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, allClients, 1)

	client := allClients[0]

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nm, err := client.Netmap()
		assert.NoError(c, err)

		if nm == nil || !nm.SelfNode.Valid() {
			assert.Fail(c, "client has no valid self node in netmap yet")
			return
		}

		// CertDomains are FQDNs without a trailing dot; the node's own
		// MagicDNS name must be present.
		want := strings.TrimSuffix(nm.SelfNode.Name(), ".")
		assert.Equal(c, []string{want}, nm.DNS.CertDomains,
			"client netmap should advertise its own FQDN in DNSConfig.CertDomains")
	}, 60*time.Second, 2*time.Second, "CertDomains should be advertised to the client")
}
