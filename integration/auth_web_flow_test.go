package integration

import (
	"fmt"
	"net/netip"
	"slices"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
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

func TestAuthWebFlowLogoutAndReloginSameUser(t *testing.T) {
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

	allIps, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	allAddrs = lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success = pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d", success, len(allClients)*len(allIps))

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

// TestAuthWebFlowLogoutAndReloginNewUser tests the scenario where multiple Tailscale clients
// initially authenticate using the web-based authentication flow (where users visit a URL
// in their browser to authenticate), then all clients log out and log back in as a different user.
//
// This test validates the "user switching" behavior in headscale's web authentication flow:
// - Multiple clients authenticate via web flow, each to their respective users (user1, user2)
// - All clients log out simultaneously
// - All clients log back in via web flow, but this time they all authenticate as user1
// - The test verifies that user1 ends up with all the client nodes
// - The test verifies that user2's original nodes still exist in the database but are offline
// - The test verifies network connectivity works after the user switch
//
// This scenario is important for organizations that need to reassign devices between users
// or when consolidating multiple user accounts. It ensures that headscale properly handles
// the security implications of user switching while maintaining node persistence in the database.
//
// The test uses headscale's web authentication flow, which is the most user-friendly method
// where authentication happens through a web browser rather than pre-shared keys or OIDC.
func TestAuthWebFlowLogoutAndReloginNewUser(t *testing.T) {
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
		hsic.WithTestName("webflowrelnewuser"),
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
		assert.NoError(ct, err, "Failed to list nodes after initial web authentication")
		assert.Len(ct, listNodes, len(allClients), "Expected %d nodes after web auth, got %d", len(allClients), len(listNodes))
	}, 30*time.Second, 2*time.Second, "validating node count matches client count after initial web authentication")
	nodeCountBeforeLogout := len(listNodes)
	t.Logf("node count before logout: %d", nodeCountBeforeLogout)

	// Log out all clients
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

	// Log all clients back in as user1 using web flow
	// We manually iterate over all clients and authenticate each one as user1
	// This tests the cross-user re-authentication behavior where ALL clients
	// (including those originally from user2) are registered to user1
	for _, client := range allClients {
		loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
		if err != nil {
			t.Fatalf("failed to get login URL for client %s: %s", client.Hostname(), err)
		}

		body, err := doLoginURL(client.Hostname(), loginURL)
		if err != nil {
			t.Fatalf("failed to complete login for client %s: %s", client.Hostname(), err)
		}

		// Register all clients as user1 (this is where cross-user registration happens)
		// This simulates: headscale nodes register --user user1 --key <key>
		scenario.runHeadscaleRegister("user1", body)
	}

	// Wait for all clients to reach running state
	for _, client := range allClients {
		err := client.WaitForRunning(integrationutil.PeerSyncTimeout())
		if err != nil {
			t.Fatalf("%s tailscale node has not reached running: %s", client.Hostname(), err)
		}
	}

	t.Logf("all clients logged back in as user1")

	var user1Nodes []*v1.Node
	t.Logf("Validating user1 node count after relogin at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user1Nodes, err = headscale.ListNodes("user1")
		assert.NoError(ct, err, "Failed to list nodes for user1 after web flow relogin")
		assert.Len(ct, user1Nodes, len(allClients), "User1 should have all %d clients after web flow relogin, got %d nodes", len(allClients), len(user1Nodes))
	}, 60*time.Second, 2*time.Second, "validating user1 has all client nodes after web flow user switch relogin")

	// Collect expected node IDs for user1 after relogin
	expectedUser1Nodes := make([]types.NodeID, 0, len(user1Nodes))
	for _, node := range user1Nodes {
		expectedUser1Nodes = append(expectedUser1Nodes, types.NodeID(node.GetId()))
	}

	// Validate connection state after relogin as user1
	validateReloginComplete(t, headscale, expectedUser1Nodes)

	// Validate that user2's old nodes still exist in database (but are expired/offline)
	// When CLI registration creates new nodes for user1, user2's old nodes remain
	var user2Nodes []*v1.Node
	t.Logf("Validating user2 old nodes remain in database after CLI registration to user1 at %s", time.Now().Format(TimestampFormat))
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error
		user2Nodes, err = headscale.ListNodes("user2")
		assert.NoError(ct, err, "Failed to list nodes for user2 after CLI registration to user1")
		assert.Len(ct, user2Nodes, len(allClients)/2, "User2 should still have %d old nodes (likely expired) after CLI registration to user1, got %d nodes", len(allClients)/2, len(user2Nodes))
	}, 30*time.Second, 2*time.Second, "validating user2 old nodes remain in database after CLI registration to user1")

	t.Logf("Validating client login states after web flow user switch at %s", time.Now().Format(TimestampFormat))
	for _, client := range allClients {
		assert.EventuallyWithT(t, func(ct *assert.CollectT) {
			status, err := client.Status()
			assert.NoError(ct, err, "Failed to get status for client %s", client.Hostname())
			assert.Equal(ct, "user1@test.no", status.User[status.Self.UserID].LoginName, "Client %s should be logged in as user1 after web flow user switch, got %s", client.Hostname(), status.User[status.Self.UserID].LoginName)
		}, 30*time.Second, 2*time.Second, fmt.Sprintf("validating %s is logged in as user1 after web flow user switch", client.Hostname()))
	}

	// Test connectivity after user switch
	allIps, err = scenario.ListTailscaleClientsIPs()
	requireNoErrListClientIPs(t, err)

	allAddrs := lo.Map(allIps, func(x netip.Addr, index int) string {
		return x.String()
	})

	success := pingAllHelper(t, allClients, allAddrs)
	t.Logf("%d successful pings out of %d after web flow user switch", success, len(allClients)*len(allIps))
}

// TestWebAuthAdvertiseTags tests the advertise-tags functionality for web-authenticated nodes.
//
// This test validates that user-owned nodes can use --advertise-tags during registration:
// 1. A node with allowed tags in --advertise-tags gets those tags applied
// 2. A node with forbidden tags in --advertise-tags only gets the allowed ones
// 3. A node without --advertise-tags has no tags
//
// Per the Tailscale spec and headscale implementation:
// - User-owned nodes (authenticated via web flow) CAN use --advertise-tags during `tailscale up`
// - Tags are only added if the node's IP is in the tagOwner's IP set (NodeCanHaveTag)
// - --advertise-tags is ONLY processed during registration, not via `tailscale set`.
func TestWebAuthAdvertiseTags(t *testing.T) {
	IntegrationSkip(t)

	user := "webtaguser"

	// ACL policy that authorizes some tags for the user
	// tag:allowed and tag:allowed2 are owned by the user
	// tag:forbidden is NOT owned by the user (no tagOwner entry)
	policy := &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:allowed":  policyv2.Owners{ptr.To(policyv2.Username(user + "@"))},
			"tag:allowed2": policyv2.Owners{ptr.To(policyv2.Username(user + "@"))},
			// tag:forbidden intentionally has no owner - requests for it should be denied
		},
		ACLs: []policyv2.ACL{
			{
				Action:       "accept",
				Sources:      []policyv2.Alias{policyv2.Wildcard},
				Destinations: []policyv2.AliasWithPorts{{Alias: policyv2.Wildcard, Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}}},
			},
		},
	}

	spec := ScenarioSpec{
		NodesPerUser: 0, // We'll create the nodes manually
		Users:        []string{user},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		nil,
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("webauth-advtags"),
		hsic.WithTLS(),
		hsic.WithDERPAsIP(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// ========================================================================
	// Test 1: Node with allowed tags - should be approved and added
	// ========================================================================
	t.Logf("Test 1: Registering node with allowed tag (tag:allowed)")

	client1, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:allowed"}),
	)
	require.NoError(t, err)

	// Web flow authentication
	loginURL1, err := client1.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body1, err := doLoginURL(client1.Hostname(), loginURL1)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(user, body1)
	require.NoError(t, err)

	err = client1.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify the tag was added
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(user)
		assert.NoError(c, err)

		var node1 *v1.Node

		for _, n := range nodes {
			if n.GetName() == client1.Hostname() {
				node1 = n
				break
			}
		}

		assert.NotNil(c, node1, "Node should exist")

		if node1 != nil {
			assert.Contains(c, node1.GetValidTags(), "tag:allowed", "Node should have tag:allowed")
			assert.Len(c, node1.GetValidTags(), 1, "Node should have exactly 1 tag")
			t.Logf("Test 1: Node has tags: %v", node1.GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for node with allowed tag")

	t.Logf("Test 1 PASSED: tag:allowed was approved and added during registration")

	// ========================================================================
	// Test 2: Node with forbidden tag - should NOT be added
	// ========================================================================
	t.Logf("Test 2: Registering node with forbidden tag (tag:forbidden) - should NOT be added")

	client2, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:forbidden"}),
	)
	require.NoError(t, err)

	loginURL2, err := client2.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body2, err := doLoginURL(client2.Hostname(), loginURL2)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(user, body2)
	require.NoError(t, err)

	err = client2.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify the forbidden tag was NOT added
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(user)
		assert.NoError(c, err)

		var node2 *v1.Node

		for _, n := range nodes {
			if n.GetName() == client2.Hostname() {
				node2 = n
				break
			}
		}

		assert.NotNil(c, node2, "Node should exist")

		if node2 != nil {
			assert.NotContains(c, node2.GetValidTags(), "tag:forbidden", "Node should NOT have tag:forbidden")
			assert.Empty(c, node2.GetValidTags(), "Node should have no tags - forbidden tag was rejected")
			t.Logf("Test 2: Node has tags: %v", node2.GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying forbidden tag was not added")

	t.Logf("Test 2 PASSED: tag:forbidden was correctly rejected")

	// ========================================================================
	// Test 3: Node with mixed tags - only allowed should be added
	// ========================================================================
	t.Logf("Test 3: Registering node with mixed tags (tag:allowed2,tag:forbidden)")

	client3, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:allowed2,tag:forbidden"}),
	)
	require.NoError(t, err)

	loginURL3, err := client3.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body3, err := doLoginURL(client3.Hostname(), loginURL3)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(user, body3)
	require.NoError(t, err)

	err = client3.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify only allowed2 was added, forbidden was rejected
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(user)
		assert.NoError(c, err)

		var node3 *v1.Node

		for _, n := range nodes {
			if n.GetName() == client3.Hostname() {
				node3 = n
				break
			}
		}

		assert.NotNil(c, node3, "Node should exist")

		if node3 != nil {
			assert.Contains(c, node3.GetValidTags(), "tag:allowed2", "Node should have tag:allowed2")
			assert.NotContains(c, node3.GetValidTags(), "tag:forbidden", "Node should NOT have tag:forbidden")
			assert.Len(c, node3.GetValidTags(), 1, "Node should have exactly 1 tag")
			t.Logf("Test 3: Node has tags: %v", node3.GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying mixed tags handled correctly")

	t.Logf("Test 3 PASSED: only allowed tags were added, forbidden was rejected")

	// ========================================================================
	// Test 4: Node without advertise-tags - should have no tags
	// ========================================================================
	t.Logf("Test 4: Registering node without --advertise-tags")

	client4, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		// No WithExtraLoginArgs - no advertise-tags
	)
	require.NoError(t, err)

	loginURL4, err := client4.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body4, err := doLoginURL(client4.Hostname(), loginURL4)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(user, body4)
	require.NoError(t, err)

	err = client4.WaitForRunning(integrationutil.PeerSyncTimeout())
	require.NoError(t, err)

	// Verify node has no tags
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(user)
		assert.NoError(c, err)

		var node4 *v1.Node

		for _, n := range nodes {
			if n.GetName() == client4.Hostname() {
				node4 = n
				break
			}
		}

		assert.NotNil(c, node4, "Node should exist")

		if node4 != nil {
			assert.Empty(c, node4.GetValidTags(), "Node should have no tags")
			t.Logf("Test 4: Node has tags: %v", node4.GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying node has no tags")

	t.Logf("Test 4 PASSED: node without advertise-tags has no tags")

	t.Logf("All advertise-tags tests completed successfully")
}
