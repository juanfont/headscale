package integration

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	tcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	clientv1 "github.com/juanfont/headscale/gen/client/v1"
	"github.com/juanfont/headscale/integration/hsic"
	"github.com/juanfont/headscale/integration/integrationutil"
	"github.com/juanfont/headscale/integration/tsic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestUserCommand(t *testing.T) {
	IntegrationSkip(t)

	spec := ScenarioSpec{
		Users: []string{"user1", "user2"},
	}

	scenario, err := NewScenario(spec)

	require.NoError(t, err)
	defer scenario.ShutdownAssertNoPanics(t)

	err = scenario.CreateHeadscaleEnv([]tsic.Option{}, hsic.WithTestName("cli-user"))
	require.NoError(t, err)

	headscale, err := scenario.Headscale()
	require.NoError(t, err)

	var (
		listUsers []*clientv1.User
		result    []string
	)

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listUsers,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listUsers, sortWithID)
		result = []string{listUsers[0].Name, listUsers[1].Name}

		assert.Equal(
			ct,
			[]string{"user1", "user2"},
			result,
			"Should have user1 and user2 in users list",
		)
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	_, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"rename",
			"--output=json",
			"--identifier=" + listUsers[1].Id,
			"--new-name=newname",
		},
	)
	require.NoError(t, err)

	var listAfterRenameUsers []*clientv1.User

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterRenameUsers,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listAfterRenameUsers, sortWithID)
		result = []string{listAfterRenameUsers[0].Name, listAfterRenameUsers[1].Name}

		assert.Equal(
			ct,
			[]string{"user1", "newname"},
			result,
			"Should have user1 and newname after rename operation",
		)
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	var listByUsername []*clientv1.User

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
				"--name=user1",
			},
			&listByUsername,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user list by username")

	slices.SortFunc(listByUsername, sortWithID)

	want := []*clientv1.User{
		{
			Id:    "1",
			Name:  "user1",
			Email: "user1@test.no",
		},
	}

	if diff := tcmp.Diff(want, listByUsername, cmpopts.IgnoreUnexported(clientv1.User{}), cmpopts.IgnoreFields(clientv1.User{}, "CreatedAt")); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	var listByID []*clientv1.User

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
				"--identifier=1",
			},
			&listByID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user list by ID")

	slices.SortFunc(listByID, sortWithID)

	want = []*clientv1.User{
		{
			Id:    "1",
			Name:  "user1",
			Email: "user1@test.no",
		},
	}

	if diff := tcmp.Diff(want, listByID, cmpopts.IgnoreUnexported(clientv1.User{}), cmpopts.IgnoreFields(clientv1.User{}, "CreatedAt")); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	deleteResult, err := headscale.Execute(
		[]string{
			"headscale",
			"users",
			"destroy",
			"--force",
			// Delete "user1"
			"--identifier=1",
		},
	)
	require.NoError(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterIDDelete []*clientv1.User

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterIDDelete,
		)
		assert.NoError(ct, err)

		slices.SortFunc(listAfterIDDelete, sortWithID)

		want := []*clientv1.User{
			{
				Id:    "2",
				Name:  "newname",
				Email: "user2@test.no",
			},
		}

		if diff := tcmp.Diff(want, listAfterIDDelete, cmpopts.IgnoreUnexported(clientv1.User{}), cmpopts.IgnoreFields(clientv1.User{}, "CreatedAt")); diff != "" {
			assert.Fail(ct, "unexpected users", "diff (-want +got):\n%s", diff)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	deleteResult, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"destroy",
			"--force",
			"--name=newname",
		},
	)
	require.NoError(t, err)
	assert.Contains(t, deleteResult, "User destroyed")

	var listAfterNameDelete []clientv1.User

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
			},
			&listAfterNameDelete,
		)
		assert.NoError(c, err)
		assert.Empty(c, listAfterNameDelete)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user list after name delete")
}

// TestUserCreateCommand exercises `headscale users create` with all of its
// optional flags (--display-name, --email, --picture-url), the --email list
// filter, and the validation error paths (duplicate name, missing flags).
func TestUserCreateCommand(t *testing.T) {
	IntegrationSkip(t)

	// One pre-existing user with a node so the server holds real data while we
	// create and inspect additional users via the CLI.
	scenario, headscale := setupCLIScenario(t, "cli-usercreate", []string{"existing"}, 1)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a user populated with every optional field. The created user is
	// returned on stdout and round-tripped through the User type.
	created := assertJSONRoundtrip[*clientv1.User](t, headscale, []string{
		"headscale",
		"users",
		"create",
		"cli-created",
		"--display-name", "CLI Created",
		"--email", "cli-created@example.com",
		"--picture-url", "https://example.com/avatar.png",
		"--output", "json",
	})

	assert.Equal(t, "cli-created", created.Name)
	assert.Equal(t, "CLI Created", created.DisplayName)
	assert.Equal(t, "cli-created@example.com", created.Email)
	assert.Equal(t, "https://example.com/avatar.png", created.ProfilePicUrl)

	// The created fields must survive a list query (read-after-write) and be
	// filterable by email.
	var byEmail []*clientv1.User

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--email", "cli-created@example.com",
				"--output", "json",
			},
			&byEmail,
		)
		assert.NoError(ct, err)
		assert.Len(ct, byEmail, 1, "exactly one user should match the email filter")
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user list by email")

	require.Len(t, byEmail, 1)
	assert.Equal(t, "cli-created", byEmail[0].Name)
	assert.Equal(t, "CLI Created", byEmail[0].DisplayName)
}

// TestUserCommandValidation exercises the validation and error permutations of
// the user subcommands and their flags: a missing name, a duplicate name, the
// required --new-name on rename, and the "--name or --identifier" requirement
// on rename/destroy. user1 already exists so the duplicate path has a conflict.
func TestUserCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-userval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// wantEmptyList means the command must succeed and return no users;
	// otherwise the command must fail, matching wantErr when it is non-empty.
	tests := []struct {
		name          string
		args          []string
		wantErr       string
		wantEmptyList bool
	}{
		{name: "create missing name", args: []string{"users", "create"}, wantErr: "missing parameters"},
		{name: "create duplicate", args: []string{"users", "create", "user1"}},
		{name: "rename missing new-name", args: []string{"users", "rename", "--identifier", "1"}, wantErr: "new-name"},
		{name: "rename missing selector", args: []string{"users", "rename", "--new-name", "x"}, wantErr: "--name or --identifier"},
		{name: "destroy missing selector", args: []string{"users", "destroy", "--force"}, wantErr: "--name or --identifier"},
		{name: "destroy nonexistent", args: []string{"users", "destroy", "--force", "--identifier", "99999"}},
		{name: "list nonexistent name is empty", args: []string{"users", "list", "--name", "ghost", "--output", "json"}, wantEmptyList: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := headscale.Execute(append([]string{"headscale"}, tt.args...))

			switch {
			case tt.wantEmptyList:
				require.NoError(t, err)

				var users []clientv1.User

				require.NoError(t, json.Unmarshal([]byte(out), &users))
				require.Empty(t, users)
			case tt.wantErr != "":
				require.ErrorContains(t, err, tt.wantErr)
			default:
				require.Error(t, err)
			}
		})
	}
}

// TestUserSetCommand exercises `headscale users set`: changing the display name
// and profile picture of an existing user, clearing the picture with an empty
// value, and the validation error paths.
//
// The point of the feature is that Tailscale clients render these fields, so the
// test does not stop at the API: it asserts the new profile actually arrives in
// the connected node's netmap as tailcfg.UserProfile.
func TestUserSetCommand(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-userset", []string{"userset"}, 1)
	defer scenario.ShutdownAssertNoPanics(t)

	clients, err := scenario.ListTailscaleClients()
	require.NoError(t, err)
	require.Len(t, clients, 1)

	client := clients[0]

	updated := assertJSONRoundtrip[*clientv1.User](t, headscale, []string{
		"headscale", "users", "set",
		"--name", "userset",
		"--display-name", "User Set",
		"--picture-url", "https://example.com/userset.png",
		"--output", "json",
	})

	assert.Equal(t, "userset", updated.Name)
	assert.Equal(t, "User Set", updated.DisplayName)
	assert.Equal(t, "https://example.com/userset.png", updated.ProfilePicUrl)

	// Read-after-write: the values must survive a list query.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		var users []*clientv1.User

		err := executeAndUnmarshal(headscale,
			[]string{"headscale", "users", "list", "--name", "userset", "--output", "json"},
			&users,
		)
		assert.NoError(ct, err)

		if !assert.Len(ct, users, 1) {
			return
		}

		assert.Equal(ct, "User Set", users[0].DisplayName)
		assert.Equal(ct, "https://example.com/userset.png", users[0].ProfilePicUrl)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll,
		"Waiting for the updated profile in users list")

	// End-to-end: the node must receive the new profile in its netmap without
	// reconnecting. This is what breaks if the write path only touches the
	// database and leaves the in-memory node copies stale.
	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		status, err := client.Status()
		assert.NoError(ct, err)

		if status == nil {
			return
		}

		profile := status.User[status.Self.UserID]
		assert.Equal(ct, "User Set", profile.DisplayName)
		assert.Equal(ct, "https://example.com/userset.png", profile.ProfilePicURL)
	}, integrationutil.ScaledTimeout(60*time.Second), 1*time.Second,
		"Waiting for the updated profile to reach the client netmap")

	// An empty value clears the field; the display name, not passed, stays.
	cleared := assertJSONRoundtrip[*clientv1.User](t, headscale, []string{
		"headscale", "users", "set",
		"--name", "userset",
		"--picture-url", "",
		"--output", "json",
	})

	assert.Empty(t, cleared.ProfilePicUrl)
	assert.Equal(t, "User Set", cleared.DisplayName)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no fields",
			args:    []string{"users", "set", "--name", "userset"},
			wantErr: "at least one of",
		},
		{
			name:    "missing selector",
			args:    []string{"users", "set", "--display-name", "x"},
			wantErr: "--name or --identifier",
		},
		{
			name:    "invalid picture url",
			args:    []string{"users", "set", "--name", "userset", "--picture-url", "not-a-url"},
			wantErr: "profile picture URL",
		},
		{
			name:    "unknown user",
			args:    []string{"users", "set", "--identifier", "99999", "--display-name", "x"},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
			} else {
				require.Error(t, err)
			}
		})
	}
}
