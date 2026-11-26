package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

func TestNodeCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-user", "other-user"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-node"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	nodes := make([]*clientv0.Node, 5)

	for index := range nodes {
		nodes[index] = registerFakeNode(t, headscale, fmt.Sprintf("node-%d", index+1), "node-user")
	}

	// Test list all nodes after added seconds
	var listAll []clientv0.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(ct, err)
		assert.Len(ct, listAll, len(nodes), "Should list all nodes after CLI operations")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	assert.Equal(t, "1", listAll[0].Id)
	assert.Equal(t, "2", listAll[1].Id)
	assert.Equal(t, "3", listAll[2].Id)
	assert.Equal(t, "4", listAll[3].Id)
	assert.Equal(t, "5", listAll[4].Id)

	assert.Equal(t, "node-1", listAll[0].Hostname)
	assert.Equal(t, "node-2", listAll[1].Hostname)
	assert.Equal(t, "node-3", listAll[2].Hostname)
	assert.Equal(t, "node-4", listAll[3].Hostname)
	assert.Equal(t, "node-5", listAll[4].Hostname)

	otherUserMachines := make([]*clientv0.Node, 2)

	for index := range otherUserMachines {
		otherUserMachines[index] = registerFakeNode(t, headscale, fmt.Sprintf("otheruser-node-%d", index+1), "other-user")
	}

	// Test list all nodes after added otherUser
	var listAllWithotherUser []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllWithotherUser,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list after adding other-user nodes")

	// All nodes, nodes + otherUser
	assert.Len(t, listAllWithotherUser, 7)

	assert.Equal(t, "6", listAllWithotherUser[5].Id)
	assert.Equal(t, "7", listAllWithotherUser[6].Id)

	assert.Equal(t, "otheruser-node-1", listAllWithotherUser[5].Hostname)
	assert.Equal(t, "otheruser-node-2", listAllWithotherUser[6].Hostname)

	// Test list all nodes after added otherUser
	var listOnlyotherUserMachineUser []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--filter",
				"owner=other-user",
				"--output",
				"json",
			},
			&listOnlyotherUserMachineUser,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list filtered by other-user")

	assert.Len(t, listOnlyotherUserMachineUser, 2)

	assert.Equal(t, "6", listOnlyotherUserMachineUser[0].Id)
	assert.Equal(t, "7", listOnlyotherUserMachineUser[1].Id)

	assert.Equal(
		t,
		"otheruser-node-1",
		listOnlyotherUserMachineUser[0].Hostname,
	)
	assert.Equal(
		t,
		"otheruser-node-2",
		listOnlyotherUserMachineUser[1].Hostname,
	)

	// Delete a nodes
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"delete",
			"4",
			"--force",
		},
	)
	require.NoError(t, err)

	// Test: list main user after node is deleted
	var listOnlyMachineUserAfterDelete []clientv0.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--filter",
				"owner=node-user",
				"--output",
				"json",
			},
			&listOnlyMachineUserAfterDelete,
		)
		assert.NoError(ct, err)
		assert.Len(ct, listOnlyMachineUserAfterDelete, 4, "Should have 4 nodes for node-user after deletion")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}

func TestNodeExpireCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-expire-user"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-nodeexpire"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	nodes := make([]*clientv0.Node, 5)

	for index := range nodes {
		nodes[index] = registerFakeNode(t, headscale, fmt.Sprintf("node-%d", index+1), "node-expire-user")
	}

	var listAll []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list in expire test")

	assert.Len(t, listAll, 5)

	// With node.expiry defaulting to 0, non-tagged nodes never expire unless
	// explicitly expired.
	for i := range 5 {
		assert.True(t, listAll[i].Expiry.IsNull(),
			"node %d should not expire (no default node.expiry)", i)
	}

	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"expire",
				listAll[idx].Id,
			},
		)
		require.NoError(t, err)
	}

	var listAllAfterExpiry []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterExpiry,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list after expiry")

	assert.Len(t, listAllAfterExpiry, 5)

	for i := range 3 {
		expiry, err := listAllAfterExpiry[i].Expiry.Get()
		require.NoError(t, err, "node %d should have an expiry", i)
		assert.True(t, expiry.Before(time.Now()))
		assert.True(t, listAllAfterExpiry[i].Expired)
	}

	assert.True(t, listAllAfterExpiry[3].Expiry.IsNull())
	assert.True(t, listAllAfterExpiry[4].Expiry.IsNull())
}

func TestNodeRenameCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"node-rename-command"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-noderename"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	nodes := make([]*clientv0.Node, 5)

	for index := range nodes {
		nodes[index] = registerFakeNode(t, headscale, fmt.Sprintf("node-%d", index+1), "node-rename-command")
	}

	var listAll []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAll,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list in rename test")

	assert.Len(t, listAll, 5)

	assert.Contains(t, listAll[0].Name, "node-1")
	assert.Contains(t, listAll[1].Name, "node-2")
	assert.Contains(t, listAll[2].Name, "node-3")
	assert.Contains(t, listAll[3].Name, "node-4")
	assert.Contains(t, listAll[4].Name, "node-5")

	for idx := range 3 {
		res, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"set",
				listAll[idx].Id,
				"--name",
				fmt.Sprintf("newnode-%d", idx+1),
			},
		)
		require.NoError(t, err)

		assert.Contains(t, res, fmt.Sprintf("(newnode-%d) was node-%d.", idx+1, idx+1))
	}

	var listAllAfterRename []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterRename,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list after rename")

	assert.Len(t, listAllAfterRename, 5)

	assert.Equal(t, "newnode-1", listAllAfterRename[0].Name)
	assert.Equal(t, "newnode-2", listAllAfterRename[1].Name)
	assert.Equal(t, "newnode-3", listAllAfterRename[2].Name)
	assert.Contains(t, listAllAfterRename[3].Name, "node-4")
	assert.Contains(t, listAllAfterRename[4].Name, "node-5")

	// Test failure for too long names
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"set",
			listAll[4].Id,
			"--name",
			strings.Repeat("t", 64),
		},
	)
	require.ErrorContains(t, err, "--name: expected length <= 63")

	var listAllAfterRenameAttempt []clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--output",
				"json",
			},
			&listAllAfterRenameAttempt,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for nodes list after failed rename attempt")

	assert.Len(t, listAllAfterRenameAttempt, 5)

	assert.Equal(t, "newnode-1", listAllAfterRenameAttempt[0].Name)
	assert.Equal(t, "newnode-2", listAllAfterRenameAttempt[1].Name)
	assert.Equal(t, "newnode-3", listAllAfterRenameAttempt[2].Name)
	assert.Contains(t, listAllAfterRenameAttempt[3].Name, "node-4")
	assert.Contains(t, listAllAfterRenameAttempt[4].Name, "node-5")
}

func TestPreAuthKeyCorrectUserLoggedInCommand(t *testing.T) {
	IntegrationSkip(t)

	//nolint:goconst // test data, not worth extracting
	user1 := "user1"
	//nolint:goconst // test data, not worth extracting
	user2 := "user2"

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user1},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cli-paklogin"),
		hsic.WithACLPolicy(allowAllWithTagOwners(user2, "tag:test1", "tag:test2")),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	_, err = headscale.CreateUser(user2)
	require.NoError(t, err)

	// A key has one owner: the tags. user2 does not own it, as a user cannot
	// own a node that tags own.
	var user2Key clientv0.CreatedAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"auth",
			"keys",
			"create",
			"tag:test1,tag:test2",
			"--reusable",
			"--expiry",
			"24h",
			"--output",
			"json",
		},
		&user2Key,
	)
	require.NoError(t, err)

	var listNodes []*clientv0.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 1, "Should have exactly 1 node for user1")

		if len(listNodes) == 1 {
			assert.Equal(ct, user1, integrationutil.OwnerUser(listNodes[0].Owner).Name, "Node should belong to user1")
		}
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second)
	require.Len(t, listNodes, 1)

	userNodeID := listNodes[0].Id

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	require.Len(t, allClients, 1)

	client := allClients[0]

	// Log out from user1
	err = client.Logout()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleLogout()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.NotContains(ct, []string{"Starting", "Running"}, status.BackendState,
			"Expected node to be logged out, backend state: %s", status.BackendState)
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	err = client.Login(headscale.GetEndpoint(), user2Key.Key)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState, "Expected node to be logged in, backend state: %s", status.BackendState)
		// The PreAuthKey was created with tags, so the node is tagged, and a
		// tagged node sees itself as a user of its own, named after it, as on SaaS.
		assert.Equal(ct, strings.TrimSuffix(status.Self.DNSName, "."), status.User[status.Self.UserID].LoginName,
			"Expected the tagged node to be a user of its own")
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		// A tagged key converts the machine's user-owned node in place,
		// whoever made the key, so its tags own it.
		assert.Len(ct, listNodes, 1, "Should still have 1 node after re-login with a tagged key")

		if len(listNodes) == 1 {
			assert.Equal(ct, userNodeID, listNodes[0].Id, "The node should be converted, not replaced")
			assert.True(ct, listNodes[0].Owner.MustGet().User.IsNull(), "a tagged node has no user: its tags own it")
			assert.ElementsMatch(ct, []string{"tag:test1", "tag:test2"}, integrationutil.OwnerTags(listNodes[0].Owner))
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}

func TestTaggedNodesCLIOutput(t *testing.T) {
	IntegrationSkip(t)

	user1 := "user1"
	user2 := "user2"

	spec := ScenarioSpec{
		NodesPerUser: 1,
		Users:        []string{user1},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("tagcli"),
		hsic.WithACLPolicy(allowAllWithTagOwners(user2, "tag:test1", "tag:test2")),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	_, err = headscale.CreateUser(user2)
	require.NoError(t, err)

	// A key has one owner: the tags. user2 does not own it, as a user cannot
	// own a node that tags own.
	var user2Key clientv0.CreatedAuthKey

	err = executeAndUnmarshal(
		headscale,
		[]string{
			"headscale",
			"auth",
			"keys",
			"create",
			"tag:test1,tag:test2",
			"--reusable",
			"--expiry",
			"24h",
			"--output",
			"json",
		},
		&user2Key,
	)
	require.NoError(t, err)

	var userNodeID string

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1, "Should have exactly 1 node for user1")

		if len(nodes) == 1 {
			userNodeID = nodes[0].Id
		}
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)

	require.Len(t, allClients, 1)

	client := allClients[0]

	// Log out from user1
	err = client.Logout()
	require.NoError(t, err)

	err = scenario.WaitForTailscaleLogout()
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.NotContains(ct, []string{"Starting", "Running"}, status.BackendState,
			"Expected node to be logged out, backend state: %s", status.BackendState)
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	// Log in with the tagged PreAuthKey
	err = client.Login(headscale.GetEndpoint(), user2Key.Key)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState, "Expected node to be logged in, backend state: %s", status.BackendState)
		// A tagged node sees itself as a user of its own, named after it, as on SaaS.
		assert.Equal(ct, strings.TrimSuffix(status.Self.DNSName, "."), status.User[status.Self.UserID].LoginName,
			"Expected the tagged node to be a user of its own")
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	// A tagged key converts the machine's user-owned node in place.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		listNodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 1, "Should still have 1 node after re-login with tagged key")

		if len(listNodes) == 1 {
			assert.Equal(ct, userNodeID, listNodes[0].Id, "The node should be converted, not replaced")
			assert.True(ct, listNodes[0].Owner.MustGet().User.IsNull(), "a tagged node has no user: its tags own it")
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Test: tailscale status names a tagged node, not "userid:<n>". This is the
	// fix for issue #2970; the node is its own user, named after it, as on SaaS.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		stdout, stderr, err := client.Execute([]string{"tailscale", "status"})
		assert.NoError(ct, err, "tailscale status command should succeed, stderr: %s", stderr)

		t.Logf("Tailscale status output:\n%s", stdout)

		// The output should NOT show a raw numeric userid to the user
		assert.NotContains(ct, stdout, "userid:", "Tailscale status should not show numeric userid for tagged nodes")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}

// TestNodeExpireFlagsCommand covers the expiry that `nodes set --expiry` sets:
// a time in the future, and never, so the node never expires.
func TestNodeExpireFlagsCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-nodeexpireflags", []string{"expire-flags-user"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	nodeID := registerFakeNode(t, headscale, "flagnode", "expire-flags-user").Id

	// The mutations are verified by reading the node back (authoritative,
	// eventually-consistent) rather than trusting the mutation's immediate
	// response.
	getNode := func(ct *assert.CollectT) *clientv0.Node {
		var node clientv0.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "get", nodeID, "--output", "json"},
			&node,
		)
		if !assert.NoError(ct, err) {
			return nil
		}

		return &node
	}

	// Set a future expiry, then confirm the node reports it.
	future := time.Now().Add(2 * time.Hour).UTC()

	_, err := headscale.Execute([]string{
		"headscale", "nodes", "set", nodeID,
		"--expiry", future.Format(time.RFC3339),
		"--output", "json",
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		n := getNode(ct)
		if n == nil {
			return
		}

		expiry, err := n.Expiry.Get()
		if assert.NoError(ct, err, "expiry should be set") {
			assert.True(ct, expiry.After(time.Now()), "expiry should be in the future")
		}
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second, "Waiting for future expiry to apply")

	// Disable expiry entirely; the node should then report no expiry.
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "set", nodeID,
		"--expiry", "never",
		"--output", "json",
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		n := getNode(ct)
		if n == nil {
			return
		}

		assert.True(ct, n.Expiry.IsNull(), "a node that never expires has a null expiry")
		assert.False(ct, n.Expired)
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second, "Waiting for --expiry never to clear expiry")
}

// TestNodeCommandValidation exercises the validation and error permutations of
// the node subcommands against a single populated server: a missing node,
// non-existent nodes, and malformed values (bad expiry time, bad tag, bad
// CIDR). One real node is registered so the "valid id, bad value" paths
// reach the server.
func TestNodeCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-nodeval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	id := registerFakeNode(t, headscale, "valnode", "user1").Id

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"delete missing node", []string{"nodes", "delete", "--force"}, "`nodes delete` needs 1 argument, got 0."},
		{"delete nonexistent", []string{"nodes", "delete", "99999", "--force"}, `no node matches "99999"`},
		{"set missing node", []string{"nodes", "set", "--name", "newname"}, "`nodes set` needs 1 argument, got 0."},
		{"set nonexistent", []string{"nodes", "set", "99999", "--name", "newname"}, `no node matches "99999"`},
		{"set name too long", []string{"nodes", "set", id, "--name", strings.Repeat("t", 64)}, "expected length <= 63"},
		{"set invalid time", []string{"nodes", "set", id, "--expiry", "not-a-time"}, `"not-a-time" is not a valid --expiry`},
		{"expire missing node", []string{"nodes", "expire"}, "`nodes expire` needs 1 argument, got 0."},
		{"expire nonexistent", []string{"nodes", "expire", "99999"}, `no node matches "99999"`},
		{"tags missing node", []string{"nodes", "tags", "set", "--force"}, "`nodes tags set` needs 2 arguments, got 0."},
		{"tags empty", []string{"nodes", "tags", "set", id, "", "--force"}, "the tag list is empty"},
		{"tags not in policy", []string{"nodes", "tags", "set", id, "tag:undefined", "--force"}, "these tags are not in the policy: tag:undefined."},
		{"routes missing node", []string{"nodes", "routes", "set", "10.0.0.0/24"}, "`nodes routes set` needs 2 arguments, got 1."},
		{"routes nonexistent", []string{"nodes", "routes", "set", "99999", "10.0.0.0/24"}, `no node matches "99999"`},
		{"routes invalid cidr", []string{"nodes", "routes", "set", id, "notacidr"}, `"notacidr" is not a route`},
		// `nodes register` is gone; `auth register` answers a registration.
		{"register nonexistent user", []string{"auth", "register", types.MustAuthID().Raw(), "ghost"}, `no user matches "ghost"`},
		{"register invalid auth id", []string{"auth", "register", "badkey", "user1"}, "<auth-id> is not an auth ID"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestNodeTagCommand exercises `headscale nodes tags set` against a live node:
// it sets tags (converting a user-owned node into a tagged node) and validates
// the error paths (no tags, a tag the policy does not name).
func TestNodeTagCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users:        []string{"user1"},
		NodesPerUser: 1,
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	// tag:test1 / tag:test2 must be defined in the policy and owned by user1,
	// otherwise `nodes tags set` is refused: tags must exist in tagOwners.
	policy := &policyv2.Policy{
		ACLs: []policyv2.ACL{
			{
				Action:   "accept",
				Protocol: "tcp",
				Sources:  []policyv2.Alias{wildcard()},
				Destinations: []policyv2.AliasWithPorts{
					aliasWithPorts(wildcard(), tailcfg.PortRangeAny),
				},
			},
		},
		TagOwners: policyv2.TagOwners{
			policyv2.Tag("tag:test1"): policyv2.Owners{usernameOwner("user1@")},
			policyv2.Tag("tag:test2"): policyv2.Owners{usernameOwner("user1@")},
		},
	}

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{},
		hsic.WithTestName("cli-nodetag"),
		hsic.WithACLPolicy(policy),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	require.NoError(t, scenario.WaitForTailscaleSync())

	var nodeID string

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		if len(nodes) == 1 {
			nodeID = nodes[0].Id
			assert.Equal(ct, "user1", integrationutil.OwnerUser(nodes[0].Owner).Name, "node should start user-owned")
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	idStr := nodeID

	// Set two tags. The command response is round-tripped (transport check);
	// the resulting tag state is asserted via the authoritative list read-back
	// below rather than the immediate mutation response.
	tagged := assertJSONRoundtrip[*clientv0.Node](t, headscale, []string{
		"headscale", "nodes", "tags", "set", idStr, "tag:test1,tag:test2",
		"--force",
		"--output", "json",
	})
	assert.Equal(t, nodeID, tagged.Id, "tag response should be for the same node")

	// The node is now a tagged node, owned by its tags.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		if len(nodes) == 1 {
			assert.True(ct, nodes[0].Owner.MustGet().User.IsNull(), "a tagged node has no user: its tags own it")
			assert.ElementsMatch(ct, []string{"tag:test1", "tag:test2"}, integrationutil.OwnerTags(nodes[0].Owner))
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Error: tagged nodes must keep at least one tag, so an empty tag set is
	// rejected.
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "tags", "set", idStr, "", "--force",
	})
	require.ErrorContains(t, err, "A tagged node needs at least one tag.")

	// Error: malformed tag (missing the "tag:" prefix).
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "tags", "set", idStr, "not-a-valid-tag", "--force",
	})
	// What it says today does not name the form of a tag; it says the policy
	// does not name this one.
	require.ErrorContains(t, err, "these tags are not in the policy: not-a-valid-tag.")

	// Neither refusal changed the tags. The tag list shows the tags and the
	// node that has them.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var tags []clientv0.Tag

		err := executeAndUnmarshal(headscale, []string{"headscale", "nodes", "tags", "list", idStr, "--output", "json"}, &tags)
		assert.NoError(ct, err)

		names := make([]string, 0, len(tags))
		for _, tag := range tags {
			names = append(names, tag.Tag)
		}

		assert.ElementsMatch(ct, []string{"tag:test1", "tag:test2"}, names)
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}

// TestNodeRouteCommands exercises `nodes routes set`, `clear` and `list`
// end-to-end against a client that advertises a subnet route.
func TestNodeRouteCommands(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users:        []string{"user1"},
		NodesPerUser: 1,
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv(
		[]tsic.Option{tsic.WithAcceptRoutes()},
		hsic.WithTestName("cli-noderoutes"),
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	requireNoErrListClients(t, err)
	require.Len(t, allClients, 1)

	require.NoError(t, scenario.WaitForTailscaleSync())

	const route = "10.33.0.0/24"

	// Advertise a subnet route from the client.
	_, _, err = allClients[0].Execute([]string{"tailscale", "set", "--advertise-routes=" + route})
	require.NoError(t, err)

	require.NoError(t, scenario.WaitForTailscaleSync())

	// The advertised route should show up as available (but not approved).
	var nodeID string

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var nodes []clientv0.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "routes", "list", "--output", "json"},
			&nodes,
		)
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1, "routes list should show the route-advertising node")

		if len(nodes) == 1 {
			nodeID = nodes[0].Id
			assert.Contains(ct, nodes[0].AdvertisedRoutes, route)
			assert.Empty(ct, nodes[0].EnabledRoutes)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	idStr := nodeID

	// Approve the route via the CLI.
	approved := assertJSONRoundtrip[*clientv0.Node](t, headscale, []string{
		"headscale", "nodes", "routes", "set", idStr, route,
		"--output", "json",
	})
	assert.Contains(t, approved.EnabledRoutes, route)

	// routes list of the node should report the approved route as one it
	// serves.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var nodes []clientv0.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "routes", "list", idStr, "--output", "json"},
			&nodes,
		)
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		if len(nodes) == 1 {
			assert.Contains(ct, nodes[0].EnabledRoutes, route)
			assert.Contains(ct, nodes[0].ServingRoutes, route)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Remove all approved routes.
	cleared := assertJSONRoundtrip[*clientv0.Node](t, headscale, []string{
		"headscale", "nodes", "routes", "clear", idStr,
		"--output", "json",
	})
	assert.Empty(t, cleared.EnabledRoutes, "approved routes should be cleared")
}

// TestNodeUpdateClientCommand verifies that `headscale nodes update-client`
// answers every client version as Tailscale does. The test clients have
// auto-updates off, so Hostinfo.AllowsUpdate is false and each is "not found".
func TestNodeUpdateClientCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		NodesPerUser: len(MustTestVersions),
		Users:        []string{"node-update-user"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-nodeupdate"))
	require.NoError(t, err)

	err = scenario.WaitForTailscaleSync()
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	allClients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)

	var nodes []*clientv0.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		nodes, err = headscale.ListNodes()
		assert.NoError(c, err)
		assert.Len(c, nodes, len(allClients))

		for _, node := range nodes {
			assert.True(c, node.ConnectedToControl, "node %s should be online", node.Hostname)
		}
	}, integrationutil.ScaledTimeout(30*time.Second), integrationutil.FastPoll, "Waiting for all nodes to be online")

	for _, node := range nodes {
		_, err := headscale.Execute([]string{
			"headscale",
			"nodes",
			"update-client",
			node.Id,
		})
		require.Error(t, err, "node %s has auto-updates off and must be refused", node.Hostname)
		assert.Contains(t, err.Error(), "does not allow remote updates", "node %s", node.Hostname)
	}

	// Unknown nodes are rejected before anything is sent.
	_, err = headscale.Execute([]string{
		"headscale",
		"nodes",
		"update-client",
		"9999",
	})
	require.ErrorContains(t, err, `no node matches "9999"`)
}
