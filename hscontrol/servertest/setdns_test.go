package servertest_test

import (
	"crypto/sha256"
	"encoding/base64"
	"slices"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/dns/dnstest"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/tailcfg/nodecap"
	"tailscale.com/types/netmap"
)

// TestSetDNS drives the real client's SetDNS over Noise, the call
// `tailscale cert` makes for each ACME DNS-01 challenge.
func TestSetDNS(t *testing.T) {
	t.Parallel()

	const domain = "ts.example.com"

	provider := &dnstest.Provider{}
	srv := servertest.NewServer(t,
		servertest.WithMagicDNS(domain),
		servertest.WithCertificates(provider),
	)
	user := srv.CreateUser(t, "cert-user")

	laptop := servertest.NewClient(t, srv, "laptop", servertest.WithUser(user))
	desktop := servertest.NewClient(t, srv, "desktop", servertest.WithUser(user))

	// Without the name in CertDomains the client refuses to run ACME, and
	// without the https cap `tailscale serve` refuses HTTPS.
	laptop.WaitForCondition(t, "cert domain and https cap", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil &&
				slices.Equal(nm.DNS.CertDomains, []string{"laptop." + domain}) &&
				hasCap(nm, nodecap.HTTPS)
		})

	value := func(seed string) string {
		sum := sha256.Sum256([]byte(seed))

		return base64.RawURLEncoding.EncodeToString(sum[:])
	}

	nodeKey := func(c *servertest.TestClient) tailcfg.SetDNSRequest {
		return tailcfg.SetDNSRequest{
			NodeKey: c.Direct().GetPersist().PrivateNodeKey().Public(),
			Type:    "TXT",
		}
	}

	req := nodeKey(laptop)
	req.Name = "_acme-challenge.laptop." + domain
	req.Value = value("laptop")
	require.NoError(t, laptop.Direct().SetDNS(t.Context(), &req))
	assert.Equal(t, []string{value("laptop")}, provider.Values(req.Name+"."))

	// desktop asks for laptop's challenge name with its own key.
	req = nodeKey(desktop)
	req.Name = "_acme-challenge.laptop." + domain
	req.Value = value("desktop")
	require.ErrorContains(t, desktop.Direct().SetDNS(t.Context(), &req), "403")

	// desktop presents laptop's node key on its own Noise session.
	req = nodeKey(laptop)
	req.Name = "_acme-challenge.laptop." + domain
	req.Value = value("forged")
	require.ErrorContains(t, desktop.Direct().SetDNS(t.Context(), &req), "401")

	assert.Len(t, provider.Calls(), 1, "rejected requests must not reach the DNS provider")

	// The certificate name follows a rename, lowercased; the client only
	// runs ACME for a name it finds in CertDomains.
	_, renameChange, err := srv.State().RenameNode(findNodeID(t, srv, "laptop"), "NoteBook")
	require.NoError(t, err)
	srv.App.Change(renameChange)

	laptop.WaitForCondition(t, "cert domain follows rename", 10*time.Second,
		func(nm *netmap.NetworkMap) bool {
			return nm != nil && slices.Equal(nm.DNS.CertDomains, []string{"notebook." + domain})
		})
}
