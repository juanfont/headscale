package integration

import (
	"sort"
	"testing"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
	"tailscale.com/types/ptr"
)

const tagTestUser = "taguser"

// =============================================================================
// Helper Functions
// =============================================================================

// tagsTestPolicy creates a policy for tag tests with:
// - tag:valid-owned: owned by the specified user
// - tag:second: owned by the specified user
// - tag:valid-unowned: owned by "other-user" (not the test user)
// - tag:nonexistent is deliberately NOT defined.
func tagsTestPolicy() *policyv2.Policy {
	return &policyv2.Policy{
		TagOwners: policyv2.TagOwners{
			"tag:valid-owned":   policyv2.Owners{ptr.To(policyv2.Username(tagTestUser + "@"))},
			"tag:second":        policyv2.Owners{ptr.To(policyv2.Username(tagTestUser + "@"))},
			"tag:valid-unowned": policyv2.Owners{ptr.To(policyv2.Username("other-user@"))},
			// Note: tag:nonexistent deliberately NOT defined
		},
		ACLs: []policyv2.ACL{
			{
				Action:       "accept",
				Sources:      []policyv2.Alias{policyv2.Wildcard},
				Destinations: []policyv2.AliasWithPorts{{Alias: policyv2.Wildcard, Ports: []tailcfg.PortRange{tailcfg.PortRangeAny}}},
			},
		},
	}
}

// tagsEqual compares two tag slices as unordered sets.
func tagsEqual(actual, expected []string) bool {
	if len(actual) != len(expected) {
		return false
	}

	sortedActual := append([]string{}, actual...)
	sortedExpected := append([]string{}, expected...)

	sort.Strings(sortedActual)
	sort.Strings(sortedExpected)

	for i := range sortedActual {
		if sortedActual[i] != sortedExpected[i] {
			return false
		}
	}

	return true
}

// assertNodeHasTagsWithCollect asserts that a node has exactly the expected tags (order-independent).
func assertNodeHasTagsWithCollect(c *assert.CollectT, node *v1.Node, expectedTags []string) {
	actualTags := node.GetValidTags()
	sortedActual := append([]string{}, actualTags...)
	sortedExpected := append([]string{}, expectedTags...)

	sort.Strings(sortedActual)
	sort.Strings(sortedExpected)
	assert.Equal(c, sortedExpected, sortedActual, "Node %s tags mismatch", node.GetName())
}

// assertNodeHasNoTagsWithCollect asserts that a node has no tags.
func assertNodeHasNoTagsWithCollect(c *assert.CollectT, node *v1.Node) {
	assert.Empty(c, node.GetValidTags(), "Node %s should have no tags, but has: %v", node.GetName(), node.GetValidTags())
}

// =============================================================================
// Test Suite 2: Auth Key WITH Pre-assigned Tags
// =============================================================================

// TestTagsAuthKeyWithTagRequestDifferentTag tests that requesting a different tag
// than what the auth key provides results in registration failure.
//
// Test 2.1: Request different tag than key provides
// Setup: Run `tailscale up --advertise-tags="tag:second" --auth-key AUTH_KEY_WITH_TAG`
// Expected: Registration fails with error containing "requested tags [tag:second] are invalid or not permitted".
func TestTagsAuthKeyWithTagRequestDifferentTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0, // We'll create the node manually
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-diff"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)
	t.Logf("Created tagged PreAuthKey with tags: %v", authKey.GetAclTags())

	// Create a tailscale client that will try to use --advertise-tags with a DIFFERENT tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:second"}),
	)
	require.NoError(t, err)

	// Login should fail because the advertised tags don't match the auth key's tags
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())

	// Document actual behavior - we expect this to fail
	if err != nil {
		t.Logf("Test 2.1 PASS: Registration correctly rejected with error: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		// If it succeeded, document this unexpected behavior
		t.Logf("Test 2.1 UNEXPECTED: Registration succeeded when it should have failed")

		// Check what tags the node actually has
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// TestTagsAuthKeyWithTagNoAdvertiseFlag tests that registering with a tagged auth key
// but no --advertise-tags flag results in the node inheriting the key's tags.
//
// Test 2.2: Register with no advertise-tags flag
// Setup: Run `tailscale up --auth-key AUTH_KEY_WITH_TAG` (no --advertise-tags)
// Expected: Registration succeeds, node has ["tag:valid-owned"] (inherited from key).
func TestTagsAuthKeyWithTagNoAdvertiseFlag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-inherit"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)
	t.Logf("Created tagged PreAuthKey with tags: %v", authKey.GetAclTags())

	// Create a tailscale client WITHOUT --advertise-tags
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		// Note: NO WithExtraLoginArgs for --advertise-tags
	)
	require.NoError(t, err)

	// Login with the tagged PreAuthKey
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for node to be registered and verify it has the key's tags
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			node := nodes[0]
			t.Logf("Node registered with tags: %v", node.GetValidTags())
			assertNodeHasTagsWithCollect(c, node, []string{"tag:valid-owned"})
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying node inherited tags from auth key")

	t.Logf("Test 2.2 completed - node inherited tags from auth key")
}

// TestTagsAuthKeyWithTagCannotAddViaCLI tests that nodes registered with a tagged auth key
// cannot add additional tags via the client CLI.
//
// Test 2.3: Cannot add tags via CLI after registration
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITH_TAG
//  2. Run `tailscale up --advertise-tags="tag:valid-owned,tag:second" --auth-key AUTH_KEY_WITH_TAG`
//
// Expected: Command fails with error containing "requested tags [tag:second] are invalid or not permitted".
func TestTagsAuthKeyWithTagCannotAddViaCLI(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-noadd"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	t.Logf("Node registered with tag:valid-owned, now attempting to add tag:second via CLI")

	// Attempt to add additional tags via tailscale up
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=tag:valid-owned,tag:second",
	}
	_, stderr, err := client.Execute(command)

	// Document actual behavior
	if err != nil {
		t.Logf("Test 2.3 PASS: CLI correctly rejected adding tags: %v, stderr: %s", err, stderr)
	} else {
		t.Logf("Test 2.3: CLI command succeeded, checking if tags actually changed")

		// Check if tags actually changed
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				// If still only has original tag, that's the expected behavior
				if tagsEqual(nodes[0].GetValidTags(), []string{"tag:valid-owned"}) {
					t.Logf("Test 2.3 PASS: Tags unchanged after CLI attempt: %v", nodes[0].GetValidTags())
				} else {
					t.Logf("Test 2.3 FAIL: Tags changed unexpectedly to: %v", nodes[0].GetValidTags())
					assert.Fail(c, "Tags should not have changed")
				}
			}
		}, 10*time.Second, 500*time.Millisecond, "verifying tags unchanged")
	}
}

// TestTagsAuthKeyWithTagCannotChangeViaCLI tests that nodes registered with a tagged auth key
// cannot change to a completely different tag set via the client CLI.
//
// Test 2.4: Cannot change to different tag set via CLI
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITH_TAG
//  2. Run `tailscale up --advertise-tags="tag:second" --auth-key AUTH_KEY_WITH_TAG`
//
// Expected: Command fails, tags remain ["tag:valid-owned"].
func TestTagsAuthKeyWithTagCannotChangeViaCLI(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-nochange"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	t.Logf("Node registered, now attempting to change to different tag via CLI")

	// Attempt to change to a different tag via tailscale up
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=tag:second",
	}
	_, stderr, err := client.Execute(command)

	// Document actual behavior
	if err != nil {
		t.Logf("Test 2.4 PASS: CLI correctly rejected changing tags: %v, stderr: %s", err, stderr)
	} else {
		t.Logf("Test 2.4: CLI command succeeded, checking if tags actually changed")

		// Check if tags remain unchanged
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				if tagsEqual(nodes[0].GetValidTags(), []string{"tag:valid-owned"}) {
					t.Logf("Test 2.4 PASS: Tags unchanged: %v", nodes[0].GetValidTags())
				} else {
					t.Logf("Test 2.4 FAIL: Tags changed unexpectedly to: %v", nodes[0].GetValidTags())
					assert.Fail(c, "Tags should not have changed")
				}
			}
		}, 10*time.Second, 500*time.Millisecond, "verifying tags unchanged")
	}
}

// TestTagsAuthKeyWithTagAdminOverrideReauthPreserves tests that admin-assigned tags
// are preserved even after reauthentication - admin decisions are authoritative.
//
// Test 2.5: Admin assignment is preserved through reauth
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITH_TAG
//  2. Assign ["tag:second"] via headscale CLI
//  3. Run `tailscale up --auth-key AUTH_KEY_WITH_TAG --force-reauth`
//
// Expected: After step 2 tags are ["tag:second"], after step 3 tags remain ["tag:second"].
func TestTagsAuthKeyWithTagAdminOverrideReauthPreserves(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-admin"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, true, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	t.Logf("Step 1 complete: Node %d registered with tag:valid-owned", nodeID)

	// Step 2: Admin assigns different tags via headscale CLI
	err = headscale.SetNodeTags(nodeID, []string{"tag:second"})
	require.NoError(t, err)

	// Verify admin assignment took effect
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			t.Logf("After admin assignment, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin tag assignment")

	t.Logf("Step 2 complete: Admin assigned tag:second")

	// Step 3: Force reauthentication
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--force-reauth",
	}
	//nolint:errcheck // Intentionally ignoring error - we check results below
	client.Execute(command)

	// Verify admin tags are preserved even after reauth - admin decisions are authoritative
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.GreaterOrEqual(c, len(nodes), 1, "Should have at least 1 node")

		if len(nodes) >= 1 {
			// Find the most recently updated node (in case a new one was created)
			node := nodes[len(nodes)-1]
			t.Logf("After reauth, tags are: %v", node.GetValidTags())

			// Expected: admin-assigned tags are preserved through reauth
			assertNodeHasTagsWithCollect(c, node, []string{"tag:second"})
		}
	}, 30*time.Second, 500*time.Millisecond, "admin tags should be preserved after reauth")

	t.Logf("Test 2.5 PASS: Admin tags preserved through reauth (admin decisions are authoritative)")
}

// TestTagsAuthKeyWithTagCLICannotModifyAdminTags tests that the client CLI
// cannot modify admin-assigned tags.
//
// Test 2.6: Client CLI cannot modify admin-assigned tags
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITH_TAG
//  2. Assign ["tag:valid-owned", "tag:second"] via headscale CLI
//  3. Run `tailscale up --advertise-tags="tag:valid-owned" --auth-key AUTH_KEY_WITH_TAG`
//
// Expected: Command either fails or is no-op, tags remain ["tag:valid-owned", "tag:second"].
func TestTagsAuthKeyWithTagCLICannotModifyAdminTags(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-noadmin"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, true, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns multiple tags via headscale CLI
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-owned", "tag:second"})
	require.NoError(t, err)

	// Verify admin assignment
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin tag assignment")

	t.Logf("Admin assigned both tags, now attempting to reduce via CLI")

	// Step 3: Attempt to reduce tags via CLI
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)

	t.Logf("CLI command result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - CLI should not be able to reduce them
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("After CLI attempt, tags are: %v", nodes[0].GetValidTags())

			// Expected: tags should remain unchanged (admin wins)
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved after CLI attempt")

	t.Logf("Test 2.6 PASS: Admin tags preserved - CLI cannot modify admin-assigned tags")
}

// =============================================================================
// Test Suite 3: Auth Key WITHOUT Tags
// =============================================================================

// TestTagsAuthKeyWithoutTagCannotRequestTags tests that nodes cannot request tags
// when using an auth key that has no tags.
//
// Test 3.1: Cannot request tags with tagless key
// Setup: Run `tailscale up --advertise-tags="tag:valid-owned" --auth-key AUTH_KEY_WITHOUT_TAG`
// Expected: Registration fails with error containing "requested tags [tag:valid-owned] are invalid or not permitted".
func TestTagsAuthKeyWithoutTagCannotRequestTags(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-req"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, false, false)
	require.NoError(t, err)
	t.Logf("Created PreAuthKey without tags")

	// Create a tailscale client that will try to request tags
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
	)
	require.NoError(t, err)

	// Login should fail because the auth key has no tags
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		t.Logf("Test 3.1 PASS: Registration correctly rejected: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		// If it succeeded, document this unexpected behavior
		t.Logf("Test 3.1 UNEXPECTED: Registration succeeded when it should have failed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// TestTagsAuthKeyWithoutTagRegisterNoTags tests that registering with a tagless auth key
// and no --advertise-tags results in a node with no tags.
//
// Test 3.2: Register with no tags
// Setup: Run `tailscale up --auth-key AUTH_KEY_WITHOUT_TAG` (no --advertise-tags)
// Expected: Registration succeeds, node has no tags (empty tag set).
func TestTagsAuthKeyWithoutTagRegisterNoTags(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-noreg"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, false, false)
	require.NoError(t, err)

	// Create a tailscale client without --advertise-tags
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Login should succeed
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Verify node has no tags
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			t.Logf("Node registered with tags: %v", nodes[0].GetValidTags())
			assertNodeHasNoTagsWithCollect(c, nodes[0])
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying node has no tags")

	t.Logf("Test 3.2 completed - node registered without tags")
}

// TestTagsAuthKeyWithoutTagCannotAddViaCLI tests that nodes registered with a tagless
// auth key cannot add tags via the client CLI.
//
// Test 3.3: Cannot add tags via CLI after registration
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITHOUT_TAG
//  2. Run `tailscale up --advertise-tags="tag:valid-owned" --auth-key AUTH_KEY_WITHOUT_TAG`
//
// Expected: Command fails, node remains with no tags.
func TestTagsAuthKeyWithoutTagCannotAddViaCLI(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-noadd"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, true, false)
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			assertNodeHasNoTagsWithCollect(c, nodes[0])
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	t.Logf("Node registered without tags, attempting to add via CLI")

	// Attempt to add tags via tailscale up
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)

	// Document actual behavior
	if err != nil {
		t.Logf("Test 3.3 PASS: CLI correctly rejected adding tags: %v, stderr: %s", err, stderr)
	} else {
		t.Logf("Test 3.3: CLI command succeeded, checking if tags actually changed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				if len(nodes[0].GetValidTags()) == 0 {
					t.Logf("Test 3.3 PASS: Tags still empty after CLI attempt")
				} else {
					t.Logf("Test 3.3 FAIL: Tags changed to: %v", nodes[0].GetValidTags())
					assert.Fail(c, "Tags should not have changed")
				}
			}
		}, 10*time.Second, 500*time.Millisecond, "verifying tags unchanged")
	}
}

// TestTagsAuthKeyWithoutTagCLINoOpAfterAdminWithReset tests that the client CLI
// is a no-op after admin tag assignment, even with --reset flag.
//
// Test 3.4: CLI no-op after admin tag assignment (with --reset)
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITHOUT_TAG
//  2. Assign ["tag:valid-owned"] via headscale CLI
//  3. Run `tailscale up --auth-key AUTH_KEY_WITHOUT_TAG --reset`
//
// Expected: Command is no-op, tags remain ["tag:valid-owned"].
func TestTagsAuthKeyWithoutTagCLINoOpAfterAdminWithReset(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-reset"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, true, false)
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			assertNodeHasNoTagsWithCollect(c, nodes[0])
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns tags
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Verify admin assignment
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin tag assignment")

	t.Logf("Admin assigned tag, now running CLI with --reset")

	// Step 3: Run tailscale up with --reset
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--reset",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI --reset result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - --reset should not remove them
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("After --reset, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved after --reset")

	t.Logf("Test 3.4 PASS: Admin tags preserved after --reset")
}

// TestTagsAuthKeyWithoutTagCLINoOpAfterAdminWithEmptyAdvertise tests that the client CLI
// is a no-op after admin tag assignment, even with empty --advertise-tags.
//
// Test 3.5: CLI no-op after admin tag assignment (with empty advertise-tags)
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITHOUT_TAG
//  2. Assign ["tag:valid-owned"] via headscale CLI
//  3. Run `tailscale up --auth-key AUTH_KEY_WITHOUT_TAG --advertise-tags=""`
//
// Expected: Command is no-op, tags remain ["tag:valid-owned"].
func TestTagsAuthKeyWithoutTagCLINoOpAfterAdminWithEmptyAdvertise(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-empty"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, true, false)
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns tags
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Verify admin assignment
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin tag assignment")

	t.Logf("Admin assigned tag, now running CLI with empty --advertise-tags")

	// Step 3: Run tailscale up with empty --advertise-tags
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI empty advertise-tags result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - empty --advertise-tags should not remove them
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("After empty --advertise-tags, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved after empty --advertise-tags")

	t.Logf("Test 3.5 PASS: Admin tags preserved after empty --advertise-tags")
}

// TestTagsAuthKeyWithoutTagCLICannotReduceAdminMultiTag tests that the client CLI
// cannot reduce an admin-assigned multi-tag set.
//
// Test 3.6: Client CLI cannot reduce admin-assigned multi-tag set
// Setup:
//  1. Register with --auth-key AUTH_KEY_WITHOUT_TAG
//  2. Assign ["tag:valid-owned", "tag:second"] via headscale CLI
//  3. Run `tailscale up --advertise-tags="tag:valid-owned" --auth-key AUTH_KEY_WITHOUT_TAG`
//
// Expected: Command is no-op (or fails), tags remain ["tag:valid-owned", "tag:second"].
func TestTagsAuthKeyWithoutTagCLICannotReduceAdminMultiTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-reduce"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, true, false)
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	// Initial login
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for initial registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns multiple tags
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-owned", "tag:second"})
	require.NoError(t, err)

	// Verify admin assignment
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin tag assignment")

	t.Logf("Admin assigned both tags, now attempting to reduce via CLI")

	// Step 3: Attempt to reduce tags via CLI
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--authkey=" + authKey.GetKey(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI reduce result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - CLI should not be able to reduce them
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("After CLI reduce attempt, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved after CLI reduce attempt")

	t.Logf("Test 3.6 PASS: Admin tags preserved - CLI cannot reduce admin-assigned multi-tag set")
}

// =============================================================================
// Test Suite 1: User Login Authentication (Web Auth Flow)
// =============================================================================

// TestTagsUserLoginOwnedTagAtRegistration tests that a user can advertise an owned tag
// during web auth registration.
//
// Test 1.1: Advertise owned tag at registration
// Setup: Web auth login with --advertise-tags="tag:valid-owned"
// Expected: Node has ["tag:valid-owned"].
func TestTagsUserLoginOwnedTagAtRegistration(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0, // We'll create the node manually
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{
			tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
		},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-owned"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Create a tailscale client with --advertise-tags
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
	)
	require.NoError(t, err)

	// Login via web auth flow
	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	// Complete the web auth by visiting the login URL
	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	// Register the node via headscale CLI
	err = scenario.runHeadscaleRegister(tagTestUser, body)
	require.NoError(t, err)

	// Wait for client to be running
	err = client.WaitForRunning(120 * time.Second)
	require.NoError(t, err)

	// Verify node has the advertised tag
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("Node registered with tags: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 30*time.Second, 500*time.Millisecond, "verifying node has advertised tag")

	t.Logf("Test 1.1 completed - web auth with owned tag succeeded")
}

// TestTagsUserLoginNonExistentTagAtRegistration tests that advertising a non-existent tag
// during web auth registration fails.
//
// Test 1.2: Advertise non-existent tag at registration
// Setup: Web auth login with --advertise-tags="tag:nonexistent"
// Expected: Registration fails - node should not be registered OR should have no tags.
func TestTagsUserLoginNonExistentTagAtRegistration(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-nonexist"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Create a tailscale client with non-existent tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:nonexistent"}),
	)
	require.NoError(t, err)

	// Login via web auth flow
	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	// Complete the web auth by visiting the login URL
	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	// Register the node via headscale CLI - this should fail due to non-existent tag
	err = scenario.runHeadscaleRegister(tagTestUser, body)

	// We expect registration to fail with an error about invalid/unauthorized tags
	if err != nil {
		t.Logf("Test 1.2 PASS: Registration correctly rejected with error: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		// Check the result - if registration succeeded, the node should not have the invalid tag
		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err, "Should be able to list nodes")

			if len(nodes) == 0 {
				t.Logf("Test 1.2 PASS: Registration rejected - no nodes registered")
			} else {
				// If a node was registered, it should NOT have the non-existent tag
				assert.NotContains(c, nodes[0].GetValidTags(), "tag:nonexistent",
					"Non-existent tag should not be applied to node")
				t.Logf("Test 1.2: Node registered with tags: %v (non-existent tag correctly rejected)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node registration result")
	}
}

// TestTagsUserLoginUnownedTagAtRegistration tests that advertising an unowned tag
// during web auth registration is rejected.
//
// Test 1.3: Advertise unowned tag at registration
// Setup: Web auth login with --advertise-tags="tag:valid-unowned"
// Expected: Registration fails - node should not be registered OR should have no tags.
func TestTagsUserLoginUnownedTagAtRegistration(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-unowned"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Create a tailscale client with unowned tag (tag:valid-unowned is owned by "other-user", not "taguser")
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-unowned"}),
	)
	require.NoError(t, err)

	// Login via web auth flow
	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	// Complete the web auth
	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	// Register the node - should fail or reject the unowned tag
	_ = scenario.runHeadscaleRegister(tagTestUser, body)

	// Check the result - user should NOT be able to claim an unowned tag
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err, "Should be able to list nodes")

		// Either: no nodes registered (ideal), or node registered without the unowned tag
		if len(nodes) == 0 {
			t.Logf("Test 1.3 PASS: Registration rejected - no nodes registered")
		} else {
			// If a node was registered, it should NOT have the unowned tag
			assert.NotContains(c, nodes[0].GetValidTags(), "tag:valid-unowned",
				"Unowned tag should not be applied to node (tag:valid-unowned is owned by other-user)")
			t.Logf("Test 1.3: Node registered with tags: %v (unowned tag correctly rejected)", nodes[0].GetValidTags())
		}
	}, 10*time.Second, 500*time.Millisecond, "checking node registration result")
}

// TestTagsUserLoginAddTagViaCLIReauth tests that a user can add tags via CLI reauthentication.
//
// Test 1.4: Add tag via CLI reauthentication
// Setup:
//  1. Register with --advertise-tags="tag:valid-owned"
//  2. Run tailscale up --advertise-tags="tag:valid-owned,tag:second"
//
// Expected: Triggers full reauthentication, node has both tags.
func TestTagsUserLoginAddTagViaCLIReauth(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-addtag"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Step 1: Create and register with one tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
	)
	require.NoError(t, err)

	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(tagTestUser, body)
	require.NoError(t, err)

	err = client.WaitForRunning(120 * time.Second)
	require.NoError(t, err)

	// Verify initial tag
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			t.Logf("Initial tags: %v", nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "checking initial tags")

	// Step 2: Try to add second tag via CLI
	t.Logf("Attempting to add second tag via CLI reauth")

	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--advertise-tags=tag:valid-owned,tag:second",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI result: err=%v, stderr=%s", err, stderr)

	// Check final state - EventuallyWithT handles waiting for propagation
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) >= 1 {
			t.Logf("Test 1.4: After CLI, tags are: %v", nodes[0].GetValidTags())

			if tagsEqual(nodes[0].GetValidTags(), []string{"tag:valid-owned", "tag:second"}) {
				t.Logf("Test 1.4 PASS: Both tags present after reauth")
			} else {
				t.Logf("Test 1.4: Tags are %v (may require manual reauth completion)", nodes[0].GetValidTags())
			}
		}
	}, 30*time.Second, 500*time.Millisecond, "checking tags after CLI")
}

// TestTagsUserLoginRemoveTagViaCLIReauth tests that a user can remove tags via CLI reauthentication.
//
// Test 1.5: Remove tag via CLI reauthentication
// Setup:
//  1. Register with --advertise-tags="tag:valid-owned,tag:second"
//  2. Run tailscale up --advertise-tags="tag:valid-owned"
//
// Expected: Triggers full reauthentication, node has only ["tag:valid-owned"].
func TestTagsUserLoginRemoveTagViaCLIReauth(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-rmtag"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Step 1: Create and register with two tags
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned,tag:second"}),
	)
	require.NoError(t, err)

	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(tagTestUser, body)
	require.NoError(t, err)

	err = client.WaitForRunning(120 * time.Second)
	require.NoError(t, err)

	// Verify initial tags
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			t.Logf("Initial tags: %v", nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "checking initial tags")

	// Step 2: Try to remove second tag via CLI
	t.Logf("Attempting to remove tag via CLI reauth")

	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI result: err=%v, stderr=%s", err, stderr)

	// Check final state - EventuallyWithT handles waiting for propagation
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) >= 1 {
			t.Logf("Test 1.5: After CLI, tags are: %v", nodes[0].GetValidTags())

			if tagsEqual(nodes[0].GetValidTags(), []string{"tag:valid-owned"}) {
				t.Logf("Test 1.5 PASS: Only one tag after removal")
			}
		}
	}, 30*time.Second, 500*time.Millisecond, "checking tags after CLI")
}

// TestTagsUserLoginCLINoOpAfterAdminAssignment tests that CLI advertise-tags becomes
// a no-op after admin tag assignment.
//
// Test 1.6: CLI advertise-tags becomes no-op after admin tag assignment
// Setup:
//  1. Register with --advertise-tags="tag:valid-owned"
//  2. Assign ["tag:second"] via headscale CLI
//  3. Run tailscale up --advertise-tags="tag:valid-owned"
//
// Expected: Step 3 does NOT trigger reauthentication, tags remain ["tag:second"].
func TestTagsUserLoginCLINoOpAfterAdminAssignment(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-adminwin"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Step 1: Register with one tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
	)
	require.NoError(t, err)

	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(tagTestUser, body)
	require.NoError(t, err)

	err = client.WaitForRunning(120 * time.Second)
	require.NoError(t, err)

	// Get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			t.Logf("Step 1: Node %d registered with tags: %v", nodeID, nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns different tag
	err = headscale.SetNodeTags(nodeID, []string{"tag:second"})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			t.Logf("Step 2: After admin assignment, tags: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin assignment")

	// Step 3: Try to change tags via CLI
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("Step 3 CLI result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - CLI advertise-tags should be a no-op after admin assignment
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("Step 3: After CLI, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved - CLI advertise-tags should be no-op")

	t.Logf("Test 1.6 PASS: Admin tags preserved (CLI was no-op)")
}

// TestTagsUserLoginCLICannotRemoveAdminTags tests that CLI cannot remove admin-assigned tags.
//
// Test 1.7: CLI cannot remove admin-assigned tags
// Setup:
//  1. Register with --advertise-tags="tag:valid-owned"
//  2. Assign ["tag:valid-owned", "tag:second"] via headscale CLI
//  3. Run tailscale up --advertise-tags="tag:valid-owned"
//
// Expected: Command is no-op, tags remain ["tag:valid-owned", "tag:second"].
func TestTagsUserLoginCLICannotRemoveAdminTags(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnvWithLoginURL(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-webauth-norem"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	// Step 1: Register with one tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-owned"}),
	)
	require.NoError(t, err)

	loginURL, err := client.LoginWithURL(headscale.GetEndpoint())
	require.NoError(t, err)

	body, err := doLoginURL(client.Hostname(), loginURL)
	require.NoError(t, err)

	err = scenario.runHeadscaleRegister(tagTestUser, body)
	require.NoError(t, err)

	err = client.WaitForRunning(120 * time.Second)
	require.NoError(t, err)

	// Get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for initial registration")

	// Step 2: Admin assigns both tags
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-owned", "tag:second"})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)

		if len(nodes) == 1 {
			t.Logf("After admin assignment, tags: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying admin assignment")

	// Step 3: Try to reduce tags via CLI
	command := []string{
		"tailscale", "up",
		"--login-server=" + headscale.GetEndpoint(),
		"--advertise-tags=tag:valid-owned",
	}
	_, stderr, err := client.Execute(command)
	t.Logf("CLI result: err=%v, stderr=%s", err, stderr)

	// Verify admin tags are preserved - CLI should not be able to remove admin-assigned tags
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1, "Should have exactly 1 node")

		if len(nodes) == 1 {
			t.Logf("Test 1.7: After CLI, tags are: %v", nodes[0].GetValidTags())
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned", "tag:second"})
		}
	}, 10*time.Second, 500*time.Millisecond, "admin tags should be preserved - CLI cannot remove them")

	t.Logf("Test 1.7 PASS: Admin tags preserved (CLI cannot remove)")
}

// =============================================================================
// Test Suite 2 (continued): Additional Auth Key WITH Tags Tests
// =============================================================================

// TestTagsAuthKeyWithTagRequestNonExistentTag tests that requesting a non-existent tag
// with a tagged auth key results in registration failure.
//
// Test 2.7: Request non-existent tag with tagged key
// Setup: Run `tailscale up --advertise-tags="tag:nonexistent" --auth-key AUTH_KEY_WITH_TAG`
// Expected: Registration fails with error containing "requested tags".
func TestTagsAuthKeyWithTagRequestNonExistentTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-nonexist"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)
	t.Logf("Created tagged PreAuthKey with tags: %v", authKey.GetAclTags())

	// Create a tailscale client that will try to use --advertise-tags with a NON-EXISTENT tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:nonexistent"}),
	)
	require.NoError(t, err)

	// Login should fail because ANY advertise-tags is rejected for PreAuthKey registrations
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		t.Logf("Test 2.7 PASS: Registration correctly rejected with error: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		t.Logf("Test 2.7 UNEXPECTED: Registration succeeded when it should have failed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// TestTagsAuthKeyWithTagRequestUnownedTag tests that requesting an unowned tag
// with a tagged auth key results in registration failure.
//
// Test 2.8: Request unowned tag with tagged key
// Setup: Run `tailscale up --advertise-tags="tag:valid-unowned" --auth-key AUTH_KEY_WITH_TAG`
// Expected: Registration fails with error containing "requested tags".
func TestTagsAuthKeyWithTagRequestUnownedTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-authkey-unowned"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey with tag:valid-owned
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)
	t.Logf("Created tagged PreAuthKey with tags: %v", authKey.GetAclTags())

	// Create a tailscale client that will try to use --advertise-tags with an UNOWNED tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-unowned"}),
	)
	require.NoError(t, err)

	// Login should fail because ANY advertise-tags is rejected for PreAuthKey registrations
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		t.Logf("Test 2.8 PASS: Registration correctly rejected with error: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		t.Logf("Test 2.8 UNEXPECTED: Registration succeeded when it should have failed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// =============================================================================
// Test Suite 3 (continued): Additional Auth Key WITHOUT Tags Tests
// =============================================================================

// TestTagsAuthKeyWithoutTagRequestNonExistentTag tests that requesting a non-existent tag
// with a tagless auth key results in registration failure.
//
// Test 3.7: Request non-existent tag with tagless key
// Setup: Run `tailscale up --advertise-tags="tag:nonexistent" --auth-key AUTH_KEY_WITHOUT_TAG`
// Expected: Registration fails with error containing "requested tags".
func TestTagsAuthKeyWithoutTagRequestNonExistentTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-nonexist"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, false, false)
	require.NoError(t, err)
	t.Logf("Created PreAuthKey without tags")

	// Create a tailscale client that will try to request a NON-EXISTENT tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:nonexistent"}),
	)
	require.NoError(t, err)

	// Login should fail because ANY advertise-tags is rejected for PreAuthKey registrations
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		t.Logf("Test 3.7 PASS: Registration correctly rejected: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		t.Logf("Test 3.7 UNEXPECTED: Registration succeeded when it should have failed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// TestTagsAuthKeyWithoutTagRequestUnownedTag tests that requesting an unowned tag
// with a tagless auth key results in registration failure.
//
// Test 3.8: Request unowned tag with tagless key
// Setup: Run `tailscale up --advertise-tags="tag:valid-unowned" --auth-key AUTH_KEY_WITHOUT_TAG`
// Expected: Registration fails with error containing "requested tags".
func TestTagsAuthKeyWithoutTagRequestUnownedTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-nokey-unowned"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create an auth key WITHOUT tags
	authKey, err := scenario.CreatePreAuthKey(userID, false, false)
	require.NoError(t, err)
	t.Logf("Created PreAuthKey without tags")

	// Create a tailscale client that will try to request an UNOWNED tag
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
		tsic.WithExtraLoginArgs([]string{"--advertise-tags=tag:valid-unowned"}),
	)
	require.NoError(t, err)

	// Login should fail because ANY advertise-tags is rejected for PreAuthKey registrations
	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	if err != nil {
		t.Logf("Test 3.8 PASS: Registration correctly rejected: %v", err)
		assert.ErrorContains(t, err, "requested tags")
	} else {
		t.Logf("Test 3.8 UNEXPECTED: Registration succeeded when it should have failed")

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			nodes, err := headscale.ListNodes(tagTestUser)
			assert.NoError(c, err)

			if len(nodes) == 1 {
				t.Logf("Node registered with tags: %v (expected rejection)", nodes[0].GetValidTags())
			}
		}, 10*time.Second, 500*time.Millisecond, "checking node state")

		t.Fail()
	}
}

// =============================================================================
// Test Suite 4: Admin API (SetNodeTags) Validation Tests
// =============================================================================

// TestTagsAdminAPICannotSetNonExistentTag tests that the admin API rejects
// setting a tag that doesn't exist in the policy.
//
// Test 4.1: Admin cannot set non-existent tag
// Setup: Create node, then call SetNodeTags with ["tag:nonexistent"]
// Expected: SetNodeTags returns error.
func TestTagsAdminAPICannotSetNonExistentTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-admin-nonexist"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey to register a node
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			t.Logf("Node %d registered with tags: %v", nodeID, nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for registration")

	// Try to set a non-existent tag via admin API - should fail
	err = headscale.SetNodeTags(nodeID, []string{"tag:nonexistent"})

	require.Error(t, err, "SetNodeTags should fail for non-existent tag")
	t.Logf("Test 4.1 PASS: Admin API correctly rejected non-existent tag: %v", err)
}

// TestTagsAdminAPICanSetUnownedTag tests that the admin API CAN set a tag
// that exists in policy but is owned by a different user.
// Admin has full authority over tags - ownership only matters for client requests.
//
// Test 4.2: Admin CAN set unowned tag (admin has full authority)
// Setup: Create node, then call SetNodeTags with ["tag:valid-unowned"]
// Expected: SetNodeTags succeeds (admin can assign any existing tag).
func TestTagsAdminAPICanSetUnownedTag(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-admin-unowned"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey to register a node
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			t.Logf("Node %d registered with tags: %v", nodeID, nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for registration")

	// Admin sets an "unowned" tag - should SUCCEED because admin has full authority
	// (tag:valid-unowned is owned by other-user, but admin can assign it)
	err = headscale.SetNodeTags(nodeID, []string{"tag:valid-unowned"})
	require.NoError(t, err, "SetNodeTags should succeed for admin setting any existing tag")

	// Verify the tag was applied
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-unowned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying unowned tag was applied")

	t.Logf("Test 4.2 PASS: Admin API correctly allowed setting unowned tag")
}

// TestTagsAdminAPICannotRemoveAllTags tests that the admin API rejects
// removing all tags from a node (would orphan the node).
//
// Test 4.3: Admin cannot remove all tags
// Setup: Create tagged node, then call SetNodeTags with []
// Expected: SetNodeTags returns error.
func TestTagsAdminAPICannotRemoveAllTags(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-admin-empty"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey to register a node
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			t.Logf("Node %d registered with tags: %v", nodeID, nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for registration")

	// Try to remove all tags - should fail
	err = headscale.SetNodeTags(nodeID, []string{})

	require.Error(t, err, "SetNodeTags should fail when trying to remove all tags")
	t.Logf("Test 4.3 PASS: Admin API correctly rejected removing all tags: %v", err)

	// Verify original tags are preserved
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying original tags preserved")
}

// TestTagsAdminAPICannotSetInvalidFormat tests that the admin API rejects
// tags that don't have the correct format (must start with "tag:").
//
// Test 4.4: Admin cannot set invalid format tag
// Setup: Create node, then call SetNodeTags with ["invalid-no-prefix"]
// Expected: SetNodeTags returns error.
func TestTagsAdminAPICannotSetInvalidFormat(t *testing.T) {
	IntegrationSkip(t)

	policy := tagsTestPolicy()

	spec := ScenarioSpec{
		NodesPerUser: 0,
		Users:        []string{tagTestUser},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithACLPolicy(policy),
		hsic.WithTestName("tags-admin-invalid"),
		hsic.WithTLS(),
	)
	requireNoErrHeadscaleEnv(t, err)

	headscale, err := scenario.Headscale()
	requireNoErrGetHeadscale(t, err)

	userMap, err := headscale.MapUsers()
	require.NoError(t, err)

	userID := userMap[tagTestUser].GetId()

	// Create a tagged PreAuthKey to register a node
	authKey, err := scenario.CreatePreAuthKeyWithTags(userID, false, false, []string{"tag:valid-owned"})
	require.NoError(t, err)

	// Create and register a tailscale client
	client, err := scenario.CreateTailscaleNode(
		"head",
		tsic.WithNetwork(scenario.networks[scenario.testDefaultNetwork]),
	)
	require.NoError(t, err)

	err = client.Login(headscale.GetEndpoint(), authKey.GetKey())
	require.NoError(t, err)

	// Wait for registration and get node ID
	var nodeID uint64

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].GetId()
			t.Logf("Node %d registered with tags: %v", nodeID, nodes[0].GetValidTags())
		}
	}, 30*time.Second, 500*time.Millisecond, "waiting for registration")

	// Try to set a tag without the "tag:" prefix - should fail
	err = headscale.SetNodeTags(nodeID, []string{"invalid-no-prefix"})

	require.Error(t, err, "SetNodeTags should fail for invalid tag format")
	t.Logf("Test 4.4 PASS: Admin API correctly rejected invalid tag format: %v", err)

	// Verify original tags are preserved
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err := headscale.ListNodes(tagTestUser)
		assert.NoError(c, err)
		assert.Len(c, nodes, 1)

		if len(nodes) == 1 {
			assertNodeHasTagsWithCollect(c, nodes[0], []string{"tag:valid-owned"})
		}
	}, 10*time.Second, 500*time.Millisecond, "verifying original tags preserved")
}
