package integration

import (
	"fmt"
	"strings"
	"testing"
	"time"

	clientv1 "github.com/juanfont/headscale/gen/client/v1"
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

	regIDs := []string{
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
	}
	nodes := make([]*clientv1.Node, len(regIDs))

	require.NoError(t, err)

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		require.NoError(t, err)

		var node clientv1.Node

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"auth",
					"register",
					"--user",
					"node-user",
					"--auth-id",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for node registration")

		nodes[index] = &node
	}

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Len(ct, nodes, len(regIDs), "Should have correct number of nodes after CLI operations")
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second)

	// Test list all nodes after added seconds
	var listAll []clientv1.Node

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
		assert.Len(ct, listAll, len(regIDs), "Should list all nodes after CLI operations")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	assert.Equal(t, "1", listAll[0].Id)
	assert.Equal(t, "2", listAll[1].Id)
	assert.Equal(t, "3", listAll[2].Id)
	assert.Equal(t, "4", listAll[3].Id)
	assert.Equal(t, "5", listAll[4].Id)

	assert.Equal(t, "node-1", listAll[0].Name)
	assert.Equal(t, "node-2", listAll[1].Name)
	assert.Equal(t, "node-3", listAll[2].Name)
	assert.Equal(t, "node-4", listAll[3].Name)
	assert.Equal(t, "node-5", listAll[4].Name)

	otherUserRegIDs := []string{
		types.MustAuthID().String(),
		types.MustAuthID().String(),
	}
	otherUserMachines := make([]*clientv1.Node, len(otherUserRegIDs))

	require.NoError(t, err)

	for index, regID := range otherUserRegIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("otheruser-node-%d", index+1),
				"--user",
				"other-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		require.NoError(t, err)

		var node clientv1.Node

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"auth",
					"register",
					"--user",
					"other-user",
					"--auth-id",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for other-user node registration")

		otherUserMachines[index] = &node
	}

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		assert.Len(ct, otherUserMachines, len(otherUserRegIDs), "Should have correct number of otherUser machines after CLI operations")
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second)

	// Test list all nodes after added otherUser
	var listAllWithotherUser []clientv1.Node

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

	assert.Equal(t, "otheruser-node-1", listAllWithotherUser[5].Name)
	assert.Equal(t, "otheruser-node-2", listAllWithotherUser[6].Name)

	// Test list all nodes after added otherUser
	var listOnlyotherUserMachineUser []clientv1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--user",
				"other-user",
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
		listOnlyotherUserMachineUser[0].Name,
	)
	assert.Equal(
		t,
		"otheruser-node-2",
		listOnlyotherUserMachineUser[1].Name,
	)

	// Delete a nodes
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"delete",
			"--identifier",
			// Delete the last added machine
			"4",
			"--output",
			"json",
			"--force",
		},
	)
	require.NoError(t, err)

	// Test: list main user after node is deleted
	var listOnlyMachineUserAfterDelete []clientv1.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"nodes",
				"list",
				"--user",
				"node-user",
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

	regIDs := []string{
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
	}
	nodes := make([]*clientv1.Node, len(regIDs))

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-expire-user",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		require.NoError(t, err)

		var node clientv1.Node

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"auth",
					"register",
					"--user",
					"node-expire-user",
					"--auth-id",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for node-expire-user node registration")

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []clientv1.Node

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

	// With node.expiry defaulting to 0, non-tagged nodes have zero expiry
	// (never expire unless explicitly expired).
	for i := range 5 {
		assert.True(t, listAll[i].Expiry == nil || listAll[i].Expiry.IsZero(),
			"node %d should have zero expiry (no default node.expiry)", i)
	}

	for idx := range 3 {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"expire",
				"--identifier",
				listAll[idx].Id,
			},
		)
		require.NoError(t, err)
	}

	var listAllAfterExpiry []clientv1.Node

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

	require.NotNil(t, listAllAfterExpiry[0].Expiry)
	require.NotNil(t, listAllAfterExpiry[1].Expiry)
	require.NotNil(t, listAllAfterExpiry[2].Expiry)
	assert.True(t, listAllAfterExpiry[0].Expiry.Before(time.Now()))
	assert.True(t, listAllAfterExpiry[1].Expiry.Before(time.Now()))
	assert.True(t, listAllAfterExpiry[2].Expiry.Before(time.Now()))
	assert.True(t, listAllAfterExpiry[3].Expiry == nil || listAllAfterExpiry[3].Expiry.IsZero())
	assert.True(t, listAllAfterExpiry[4].Expiry == nil || listAllAfterExpiry[4].Expiry.IsZero())
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

	regIDs := []string{
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
		types.MustAuthID().String(),
	}
	nodes := make([]*clientv1.Node, len(regIDs))

	require.NoError(t, err)

	for index, regID := range regIDs {
		_, err := headscale.Execute(
			[]string{
				"headscale",
				"debug",
				"create-node",
				"--name",
				fmt.Sprintf("node-%d", index+1),
				"--user",
				"node-rename-command",
				"--key",
				regID,
				"--output",
				"json",
			},
		)
		require.NoError(t, err)

		var node clientv1.Node

		assert.EventuallyWithT(t, func(c *assert.CollectT) {
			err = executeAndUnmarshal(
				headscale,
				[]string{
					"headscale",
					"auth",
					"register",
					"--user",
					"node-rename-command",
					"--auth-id",
					regID,
					"--output",
					"json",
				},
				&node,
			)
			assert.NoError(c, err)
		}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for node-rename-command node registration")

		nodes[index] = &node
	}

	assert.Len(t, nodes, len(regIDs))

	var listAll []clientv1.Node

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

	assert.Contains(t, listAll[0].GivenName, "node-1")
	assert.Contains(t, listAll[1].GivenName, "node-2")
	assert.Contains(t, listAll[2].GivenName, "node-3")
	assert.Contains(t, listAll[3].GivenName, "node-4")
	assert.Contains(t, listAll[4].GivenName, "node-5")

	for idx := range 3 {
		res, err := headscale.Execute(
			[]string{
				"headscale",
				"nodes",
				"rename",
				"--identifier",
				listAll[idx].Id,
				fmt.Sprintf("newnode-%d", idx+1),
			},
		)
		require.NoError(t, err)

		assert.Contains(t, res, "Node renamed")
	}

	var listAllAfterRename []clientv1.Node

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

	assert.Equal(t, "newnode-1", listAllAfterRename[0].GivenName)
	assert.Equal(t, "newnode-2", listAllAfterRename[1].GivenName)
	assert.Equal(t, "newnode-3", listAllAfterRename[2].GivenName)
	assert.Contains(t, listAllAfterRename[3].GivenName, "node-4")
	assert.Contains(t, listAllAfterRename[4].GivenName, "node-5")

	// Test failure for too long names
	_, err = headscale.Execute(
		[]string{
			"headscale",
			"nodes",
			"rename",
			"--identifier",
			listAll[4].Id,
			strings.Repeat("t", 64),
		},
	)
	require.ErrorContains(t, err, "is too long, max length is 63 bytes")

	var listAllAfterRenameAttempt []clientv1.Node

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

	assert.Equal(t, "newnode-1", listAllAfterRenameAttempt[0].GivenName)
	assert.Equal(t, "newnode-2", listAllAfterRenameAttempt[1].GivenName)
	assert.Equal(t, "newnode-3", listAllAfterRenameAttempt[2].GivenName)
	assert.Contains(t, listAllAfterRenameAttempt[3].GivenName, "node-4")
	assert.Contains(t, listAllAfterRenameAttempt[4].GivenName, "node-5")
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
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	u2, err := headscale.CreateUser(user2)
	require.NoError(t, err)

	var user2Key clientv1.PreAuthKey

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				u2.Id,
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
			},
			&user2Key,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user2 preauth key creation")

	var listNodes []*clientv1.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 1, "Should have exactly 1 node for user1")
		assert.Equal(ct, user1, listNodes[0].User.Name, "Node should belong to user1")
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

	err = client.Login(headscale.GetEndpoint(), user2Key.Key)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState, "Expected node to be logged in, backend state: %s", status.BackendState)
		// With tags-as-identity model, tagged nodes show as [types.TaggedDevices] user (2147455555)
		// The PreAuthKey was created with tags, so the node is tagged
		assert.Equal(ct, "userid:2147455555", status.Self.UserID.String(), "Expected node to be logged in as tagged-devices user")
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 2, "Should have 2 nodes after re-login")
		assert.Equal(ct, user1, listNodes[0].User.Name, "First node should belong to user1")
		// Second node is tagged (created with tagged PreAuthKey), so it shows as "tagged-devices"
		assert.Equal(ct, "tagged-devices", listNodes[1].User.Name, "Second node should be tagged-devices")
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
	)
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	u2, err := headscale.CreateUser(user2)
	require.NoError(t, err)

	var user2Key clientv1.PreAuthKey

	// Create a tagged PreAuthKey for user2
	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(
			headscale,
			[]string{
				"headscale",
				"preauthkeys",
				"--user",
				u2.Id,
				"create",
				"--reusable",
				"--expiration",
				"24h",
				"--output",
				"json",
				"--tags",
				"tag:test1,tag:test2",
			},
			&user2Key,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user2 tagged preauth key creation")

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

	// Log in with the tagged PreAuthKey (from user2, with tags)
	err = client.Login(headscale.GetEndpoint(), user2Key.Key)
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)
		assert.Equal(ct, "Running", status.BackendState, "Expected node to be logged in, backend state: %s", status.BackendState)
		// With tags-as-identity model, tagged nodes show as [types.TaggedDevices] user (2147455555)
		assert.Equal(ct, "userid:2147455555", status.Self.UserID.String(), "Expected node to be logged in as tagged-devices user")
	}, integrationutil.StatusReadyTimeout, 2*time.Second)

	// Wait for the second node to appear
	var listNodes []*clientv1.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		listNodes, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, listNodes, 2, "Should have 2 nodes after re-login with tagged key")
		assert.Equal(ct, user1, listNodes[0].User.Name, "First node should belong to user1")
		assert.Equal(ct, "tagged-devices", listNodes[1].User.Name, "Second node should be tagged-devices")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Test: tailscale status output should show "tagged-devices" not "userid:2147455555"
	// This is the fix for issue #2970 - the Tailscale client should display user-friendly names
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		stdout, stderr, err := client.Execute([]string{"tailscale", "status"})
		assert.NoError(ct, err, "tailscale status command should succeed, stderr: %s", stderr)

		t.Logf("Tailscale status output:\n%s", stdout)

		// The output should contain "tagged-devices" for tagged nodes
		assert.Contains(ct, stdout, "tagged-devices", "Tailscale status should show 'tagged-devices' for tagged nodes")

		// The output should NOT show the raw numeric userid to the user
		assert.NotContains(ct, stdout, "userid:2147455555", "Tailscale status should not show numeric userid for tagged nodes")
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}

// TestNodeExpireFlagsCommand covers the two `nodes expire` flags that the basic
// expire test does not: --expiry (set a future expiry) and --disable (clear
// expiry so the node never expires).
func TestNodeExpireFlagsCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-nodeexpireflags", []string{"expire-flags-user"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	regID := types.MustAuthID().String()

	_, err := headscale.Execute([]string{
		"headscale", "debug", "create-node",
		"--name", "flagnode",
		"--user", "expire-flags-user",
		"--key", regID,
		"--output", "json",
	})
	require.NoError(t, err)

	var node clientv1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale", "auth", "register",
				"--user", "expire-flags-user",
				"--auth-id", regID,
				"--output", "json",
			},
			&node,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for node registration")

	nodeID := node.Id

	// listNodeByID returns the node with the given id from `nodes list`. The
	// expire mutations are verified by reading the node back (authoritative,
	// eventually-consistent) rather than trusting the mutation's immediate
	// response.
	listNodeByID := func(ct *assert.CollectT) *clientv1.Node {
		var nodes []clientv1.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "list", "--output", "json"},
			&nodes,
		)
		require.NoError(ct, err)

		for i := range nodes {
			if nodes[i].Id == node.Id {
				return &nodes[i]
			}
		}

		assert.Fail(ct, "node not found in list", "id %s", nodeID)

		return nil
	}

	// Set a future expiry, then confirm the node reports it.
	future := time.Now().Add(2 * time.Hour).UTC()

	_, err = headscale.Execute([]string{
		"headscale", "nodes", "expire",
		"--identifier", nodeID,
		"--expiry", future.Format(time.RFC3339),
		"--output", "json",
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		n := listNodeByID(ct)
		if n == nil {
			return
		}

		assert.True(ct, n.Expiry != nil && !n.Expiry.IsZero(), "expiry should be set")
		assert.True(ct, n.Expiry != nil && n.Expiry.After(time.Now()), "expiry should be in the future")
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second, "Waiting for future expiry to apply")

	// Disable expiry entirely; the node should then report no expiry.
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "expire",
		"--identifier", nodeID,
		"--disable",
		"--output", "json",
	})
	require.NoError(t, err)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		n := listNodeByID(ct)
		if n == nil {
			return
		}

		// --disable clears the expiry (nil), so the node has no expiry in the
		// future — it never expires. A nil expiry deserialises to the Unix
		// epoch rather than the zero time, so assert "not in the future"
		// rather than IsZero.
		assert.False(ct, n.Expiry != nil && n.Expiry.After(time.Now()),
			"disabled node should not have a future expiry")
	}, integrationutil.ScaledTimeout(15*time.Second), 1*time.Second, "Waiting for --disable to clear expiry")
}

// TestNodeCommandValidation exercises the validation and error permutations of
// the node subcommands and their flags against a single populated server: a
// missing required --identifier, non-existent identifiers, and malformed flag
// values (bad expiry time, bad tag, bad CIDR). One real node is registered so
// the "valid id, bad value" paths reach the server.
func TestNodeCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-nodeval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	regID := types.MustAuthID().String()

	_, err := headscale.Execute([]string{
		"headscale", "debug", "create-node",
		"--name", "valnode", "--user", "user1", "--key", regID, "--output", "json",
	})
	require.NoError(t, err)

	var node clientv1.Node

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "auth", "register", "--user", "user1", "--auth-id", regID, "--output", "json"},
			&node,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for node registration")

	id := node.Id

	// wantErr is matched with ErrorContains; an empty wantErr only requires
	// that the command fails (used where the exact message is not load-bearing).
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{"delete missing identifier", []string{"nodes", "delete", "--force"}, "identifier"},
		{"delete nonexistent", []string{"nodes", "delete", "--identifier", "99999", "--force"}, "node not found"},
		{"rename missing identifier", []string{"nodes", "rename", "newname"}, "identifier"},
		{"rename nonexistent", []string{"nodes", "rename", "--identifier", "99999", "newname"}, ""},
		{"rename too long", []string{"nodes", "rename", "--identifier", id, strings.Repeat("t", 64)}, "too long"},
		{"expire missing identifier", []string{"nodes", "expire"}, "identifier"},
		{"expire nonexistent", []string{"nodes", "expire", "--identifier", "99999"}, ""},
		{"expire invalid time", []string{"nodes", "expire", "--identifier", id, "--expiry", "not-a-time"}, "parsing expiry"},
		{"tag missing identifier", []string{"nodes", "tag", "--tags", "tag:x"}, "identifier"},
		{"tag empty", []string{"nodes", "tag", "--identifier", id}, "cannot remove all tags"},
		{"tag invalid format", []string{"nodes", "tag", "--identifier", id, "--tags", "notatag"}, "tag must start"},
		{"tag unpermitted", []string{"nodes", "tag", "--identifier", id, "--tags", "tag:undefined"}, "invalid or not permitted"},
		{"approve missing identifier", []string{"nodes", "approve-routes", "--routes", "10.0.0.0/24"}, "identifier"},
		{"approve nonexistent", []string{"nodes", "approve-routes", "--identifier", "99999", "--routes", "10.0.0.0/24"}, ""},
		{"approve invalid cidr", []string{"nodes", "approve-routes", "--identifier", id, "--routes", "notacidr"}, "parsing route"},
		// The deprecated `nodes register` alias drives its own RegisterNode path;
		// cover its error cases (the happy path is covered via `auth register`).
		{"register nonexistent user", []string{"nodes", "register", "--user", "ghost", "--key", types.MustAuthID().String()}, ""},
		{"register invalid key", []string{"nodes", "register", "--user", "user1", "--key", "badkey"}, ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			if tt.wantErr == "" {
				require.Error(t, err)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// TestNodeTagCommand exercises `headscale nodes tag` against a live node: it
// sets tags (converting a user-owned node into a tagged node) and validates the
// error paths (no tags, invalid tag format).
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
	// otherwise the admin `nodes tag` command is rejected as "invalid or not
	// permitted" — tags must exist in tagOwners.
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
			assert.Equal(ct, "user1", nodes[0].User.Name, "node should start user-owned")
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	idStr := nodeID

	// Set two tags. The command response is round-tripped (transport check);
	// the resulting tag state is asserted via the authoritative list read-back
	// below rather than the immediate mutation response.
	tagged := assertJSONRoundtrip[*clientv1.Node](t, headscale, []string{
		"headscale", "nodes", "tag",
		"--identifier", idStr,
		"--tags", "tag:test1,tag:test2",
		"--output", "json",
	})
	assert.Equal(t, nodeID, tagged.Id, "tag response should be for the same node")

	// The node is now a tagged node, presented as the tagged-devices user.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		nodes, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		if len(nodes) == 1 {
			assert.Equal(ct, "tagged-devices", nodes[0].User.Name, "tagged node shows as tagged-devices")
			assert.ElementsMatch(ct, []string{"tag:test1", "tag:test2"}, nodes[0].Tags)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Error: tagged nodes must keep at least one tag, so an empty tag set is
	// rejected.
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "tag",
		"--identifier", idStr,
	})
	require.ErrorContains(t, err, "cannot remove all tags")

	// Error: malformed tag (missing the "tag:" prefix).
	_, err = headscale.Execute([]string{
		"headscale", "nodes", "tag",
		"--identifier", idStr,
		"--tags", "not-a-valid-tag",
	})
	require.Error(t, err, "an invalid tag format must be rejected")
}

// TestNodeRouteCommands exercises `nodes approve-routes` and `nodes list-routes`
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
		var nodes []clientv1.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "list-routes", "--output", "json"},
			&nodes,
		)
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1, "list-routes should show the route-advertising node")

		if len(nodes) == 1 {
			nodeID = nodes[0].Id
			assert.Contains(ct, nodes[0].AvailableRoutes, route)
			assert.Empty(ct, nodes[0].ApprovedRoutes)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	idStr := nodeID

	// Approve the route via the CLI.
	approved := assertJSONRoundtrip[*clientv1.Node](t, headscale, []string{
		"headscale", "nodes", "approve-routes",
		"--identifier", idStr,
		"--routes=" + route,
		"--output", "json",
	})
	assert.Contains(t, approved.ApprovedRoutes, route)

	// list-routes filtered by the identifier should report the approved route
	// as a primary subnet route.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var nodes []clientv1.Node

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "nodes", "list-routes", "--identifier", idStr, "--output", "json"},
			&nodes,
		)
		assert.NoError(ct, err)
		assert.Len(ct, nodes, 1)

		if len(nodes) == 1 {
			assert.Contains(ct, nodes[0].ApprovedRoutes, route)
			assert.Contains(ct, nodes[0].SubnetRoutes, route)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	// Remove all approved routes by passing an empty --routes value.
	cleared := assertJSONRoundtrip[*clientv1.Node](t, headscale, []string{
		"headscale", "nodes", "approve-routes",
		"--identifier", idStr,
		"--routes=",
		"--output", "json",
	})
	assert.Empty(t, cleared.ApprovedRoutes, "approved routes should be cleared")
}

// TestNodeBackfillIPsCommand exercises `nodes backfillips` against live nodes.
// With both IPv4 and IPv6 prefixes configured (the integration default) the
// command is a no-op for IP assignment, but it must still run cleanly and the
// nodes must retain their addresses.
func TestNodeBackfillIPsCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-backfillips", []string{"user1"}, 2)
	defer scenario.ShutdownAssertNoPanics(t)

	require.NoError(t, scenario.WaitForTailscaleSync())

	var before []*clientv1.Node

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var err error

		before, err = headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, before, 2)

		for _, n := range before {
			assert.NotEmpty(ct, n.IpAddresses, "node should have IPs before backfill")
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	out, err := headscale.Execute([]string{"headscale", "nodes", "backfillips", "--force"})
	require.NoError(t, err)
	assert.Contains(t, out, "backfilled")

	// Nodes must still have their IP addresses afterwards.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		after, err := headscale.ListNodes()
		assert.NoError(ct, err)
		assert.Len(ct, after, 2)

		for _, n := range after {
			assert.NotEmpty(ct, n.IpAddresses, "node should still have IPs after backfill")
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)
}
