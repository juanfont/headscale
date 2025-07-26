package integration

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
)

// TestAuthWebFlowAuthenticationPingAll tests the web authentication flow and
// verifies that all nodes can ping each other after successful authentication.
//
// This test sets up a scenario with two users and their corresponding nodes.
// It configures Headscale with a login URL and then simulates the web login
// flow for each node. After the nodes are authenticated, it checks that they
// can all ping each other, ensuring that the web authentication is working
// correctly and that the nodes are properly connected to the network.
func TestAuthWebFlowAuthenticationPingAll(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	if err != nil {
		t.Fatalf("failed to create scenario: %s", err)
	}
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("webauthping"),
		hsic.WithEmbeddedDERPServerOnly(),
		hsic.WithTLS(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

// TestAuthWebFlowLogoutAndRelogin tests the scenario where a set of nodes are
// logged out and then logged back in using the web authentication flow.
//
// This test sets up a scenario with two users and their nodes. It first logs
// them in using the web flow and verifies that they can communicate. It then
// logs out all nodes and logs them back in again using the same web flow. The
// test verifies that the nodes can successfully re-authenticate, that their IP
// addresses remain the same, and that they can still ping each other after
// re-login.
func TestAuthWebFlowLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	assertNoErr(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("weblogout"),
		hsic.WithTLS(),
	)
	assertNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	assertNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	assertNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	headscale, err := scenario.Headscale()
	assertNoErrGetHeadscale(t, err)

	var listNodes []*v1.Node
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, len(allClients), "Node count should match client count after login")
	}, 20*time.Second, 1*time.Second)
	nodeCountBeforeLogout := len(listNodes)
	t.Logf("node count before logout: %d", nodeCountBeforeLogout)

	clientIPs := make(map[TailscaleClient][]netip.Addr)
	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}
		clientIPs[client] = ips
	}

	for _, client := range allClients {
		err := client.Logout()
		if err != nil {
			t.Fatalf("failed to logout client %s: %s", client.Hostname(), err)
		}
	}

	err = scenario.WaitForTailscaleLogout()
	assertNoErrLogout(t, err)

	t.Logf("all clients logged out")

	for _, userName := range spec.Users {
		err = scenario.RunTailscaleUpWithURL(userName, headscale.GetEndpoint())
		if err != nil {
			t.Fatalf("failed to run tailscale up (%q): %s", headscale.GetEndpoint(), err)
		}
	}

	t.Logf("all clients logged in again")

	allIps, err = scenario.ListTailscaleClientsIPs()
	assertNoErrListClientIPs(t, err)

	allAddrs = lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success = pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should match before logout count after re-login")
	}, 20*time.Second, 1*time.Second)
	t.Logf("node count first login: %d, after relogin: %d", nodeCountBeforeLogout, len(listNodes))

	for _, client := range allClients {
		ips, err := client.IPs()
		if err != nil {
			t.Fatalf("failed to get IPs for client %s: %s", client.Hostname(), err)
		}

		// lets check if the IPs are the same
		if len(ips) != len(clientIPs[client]) {
			t.Fatalf("IPs changed for client %s", client.Hostname())
		}

		for _, ip := range ips {
			found := slices.Contains(clientIPs[client], ip)

			if !found {
				t.Fatalf(
					"IPs changed for client %s. Used to be %v now %v",
					client.Hostname(),
					clientIPs[client],
					ips,
				)
			}
		}
	}

	t.Logf("all clients IPs are the same")
}
