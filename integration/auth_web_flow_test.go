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
	"github.com/stretchr/testify/require"
)

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
		hsic.WithDERPAsIP(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))
}

func TestAuthWebFlowLogoutAndRelogin(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)
	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithTestName("weblogout"),
		hsic.WithDERPAsIP(),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	allIps, err := scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	err = scenario.WaitForTailscaleSync()
	requireNoErrSync(t, err)

	// assertClientsState(t, allClients)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Collect expected node IDs for validation
	expectedNodes := collectExpectedNodeIDs(t, allClients)

	// Validate initial connection state
	validateInitialConnection(t, headscale, expectedNodes)

	var listNodes []*v1.Node
	t.Logf("Validating initial node count after web auth at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes after web authentication")
		assert.Len(ct, listNodes, len(allClients), "Expected %d nodes after web auth, got %d", len(allClients), len(listNodes))
	}, 30*time.Second, 2*time.Second, "validating node count matches client count after web authentication")
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
	requireNoErrLogout(t, err)

	// Validate that all nodes are offline after logout
	validateLogoutComplete(t, headscale, expectedNodes)

	t.Logf("all clients logged out")

	for _, userName := range spec.Users {
		err = scenario.RunTailscaleUpWithURL(userName, headscale.GetEndpoint())
		if err != nil {
			t.Fatalf("failed to run tailscale up (%q): %s", headscale.GetEndpoint(), err)
		}
	}

	t.Logf("all clients logged in again")

	allIps, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	allAddrs = lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success = pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

	t.Logf("Validating node persistence after logout at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err, "Failed to list nodes after web flow logout")
		assert.Len(ct, listNodes, nodeCountBeforeLogout, "Node count should remain unchanged after logout - expected %d nodes, got %d", nodeCountBeforeLogout, len(listNodes))
	}, 60*time.Second, 2*time.Second, "validating node persistence in database after web flow logout")
	t.Logf("node count first login: %d, after relogin: %d", nodeCountBeforeLogout, len(listNodes))

	// Validate connection state after relogin
	validateReloginComplete(t, headscale, expectedNodes)

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
