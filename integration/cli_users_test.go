package integration

import (
	"encoding/json"
	"slices"
	"testing"
	"time"

	tcmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
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
		listUsers []*clientv0.User
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
			"set",
			listUsers[1].Id,
			"--name=newname",
			"--output=json",
		},
	)
	require.NoError(t, err)

	var listAfterRenameUsers []*clientv0.User

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

	var listByUsername []*clientv0.User

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--output",
				"json",
				"--filter=name=user1",
			},
			&listByUsername,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user list by username")

	slices.SortFunc(listByUsername, sortWithID)

	want := []*clientv0.User{
		{
			Id:        "1",
			Name:      "user1",
			Email:     "user1@test.no",
			LoginName: "user1@test.no",
			Provider:  "local",
		},
	}

	if diff := tcmp.Diff(want, listByUsername, userCmpOpts...); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	var byID *clientv0.User

	assert.EventuallyWithT(t, func(c *assert.CollectT) {
		err = executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"get",
				"1",
				"--output",
				"json",
			},
			&byID,
		)
		assert.NoError(c, err)
	}, integrationutil.ScaledTimeout(10*time.Second), integrationutil.FastPoll, "Waiting for user get by ID")

	if diff := tcmp.Diff(want[0], byID, userCmpOpts...); diff != "" {
		t.Errorf("unexpected users (-want +got):\n%s", diff)
	}

	deleteResult, err := headscale.Execute(
		[]string{
			"headscale",
			"users",
			"delete",
			// Delete "user1"
			"1",
			"--force",
		},
	)
	require.NoError(t, err)
	assert.Contains(t, deleteResult, "User 1 (user1@test.no) deleted")

	var listAfterIDDelete []*clientv0.User

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

		want := []*clientv0.User{
			{
				Id:        "2",
				Name:      "newname",
				Email:     "user2@test.no",
				LoginName: "user2@test.no",
				Provider:  "local",
			},
		}

		if diff := tcmp.Diff(want, listAfterIDDelete, userCmpOpts...); diff != "" {
			assert.Fail(ct, "unexpected users", "diff (-want +got):\n%s", diff)
		}
	}, integrationutil.ScaledTimeout(20*time.Second), 1*time.Second)

	deleteResult, err = headscale.Execute(
		[]string{
			"headscale",
			"users",
			"delete",
			"newname",
			"--force",
		},
	)
	require.NoError(t, err)
	assert.Contains(t, deleteResult, "User 2 (user2@test.no) deleted")

	var listAfterNameDelete []clientv0.User

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
// optional flags (--display-name, --email, --picture-url) and the email
// filter of the list.
func TestUserCreateCommand(t *testing.T) {
	IntegrationSkip(t)

	// One pre-existing user with a node so the server holds real data while we
	// create and inspect additional users via the CLI.
	scenario, headscale := setupCLIScenario(t, "cli-usercreate", []string{"existing"}, 1)
	defer scenario.ShutdownAssertNoPanics(t)

	// Create a user populated with every optional field. The created user is
	// returned on stdout and round-tripped through the User type.
	created := assertJSONRoundtrip[*clientv0.User](t, headscale, []string{
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
	var byEmail []*clientv0.User

	assert.EventuallyWithT(t, func(ct *assert.CollectT) {
		err := executeAndUnmarshal(headscale,
			[]string{
				"headscale",
				"users",
				"list",
				"--filter", "email=cli-created@example.com",
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
// the user subcommands: a missing name, a duplicate name, set with nothing to
// change, and a missing or unknown user on set and delete. user1 already
// exists so the duplicate path has a conflict.
func TestUserCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-userval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// wantEmptyList means the command must succeed and return no users;
	// otherwise the command must fail with wantErr.
	tests := []struct {
		name          string
		args          []string
		wantErr       string
		wantEmptyList bool
	}{
		{name: "create missing name", args: []string{"users", "create"}, wantErr: "`users create` needs 1 argument, got 0."},
		{name: "create duplicate", args: []string{"users", "create", "user1"}, wantErr: `the name "user1" belongs to User 1`},
		{name: "set nothing to change", args: []string{"users", "set", "1"}, wantErr: "nothing to change"},
		{name: "set missing user", args: []string{"users", "set", "--name", "x"}, wantErr: "`users set` needs 1 argument, got 0."},
		{name: "delete missing user", args: []string{"users", "delete", "--force"}, wantErr: "`users delete` needs 1 argument, got 0."},
		{name: "delete nonexistent", args: []string{"users", "delete", "99999", "--force"}, wantErr: `no user matches "99999"`},
		{name: "list nonexistent name is empty", args: []string{"users", "list", "--filter", "name=ghost", "--output", "json"}, wantEmptyList: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			out, err := headscale.Execute(append([]string{"headscale"}, tt.args...))

			if tt.wantEmptyList {
				require.NoError(t, err)

				var users []clientv0.User

				require.NoError(t, json.Unmarshal([]byte(out), &users))
				require.Empty(t, users)

				return
			}

			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}

// userCmpOpts compare users on what a test sets: the time of creation is
// the server's, and an empty list of nodes is the same as none.
var userCmpOpts = []tcmp.Option{
	cmpopts.IgnoreFields(clientv0.User{}, "Created"),
	cmpopts.EquateEmpty(),
}
