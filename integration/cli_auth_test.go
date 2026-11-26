package integration

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAuthCommandValidation exercises the validation permutations of the auth
// subcommands: `register` against a non-existent user and a malformed or
// unknown auth ID, `approve`/`reject` against malformed and unknown auth IDs,
// and `approve` of a registration, which needs a user.
//
// approve of an SSH check is covered by the SSH check tests, and completing
// an interactive registration by `auth register` in the node tests and the
// web-auth flow tests.
func TestAuthCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-authval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Well-formed but unknown auth ID: the server has no such request.
	unknown := types.MustAuthID().Raw()

	const (
		notAnID = "is not an auth ID"
		gone    = "no auth request has this ID. It may have timed out, or it was answered already."
	)

	// A registration that waits, which approve must not answer.
	pending := types.MustAuthID().Raw()
	_, err := headscale.Execute([]string{"headscale", "debug", "create-node", "--name", "pending", "--key", pending})
	require.NoError(t, err)

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "register malformed auth-id", args: []string{"auth", "register", "not-valid", "user1"}, wantErr: notAnID},
		{name: "register nonexistent user", args: []string{"auth", "register", unknown, "ghost"}, wantErr: `no user matches "ghost"`},
		{name: "register unknown auth-id", args: []string{"auth", "register", unknown, "user1"}, wantErr: gone},
		{name: "approve malformed auth-id", args: []string{"auth", "approve", "not-valid"}, wantErr: notAnID},
		{name: "approve unknown auth-id", args: []string{"auth", "approve", unknown}, wantErr: gone},
		{name: "approve a registration", args: []string{"auth", "approve", pending}, wantErr: "this is a registration request. It needs a user"},
		{name: "reject malformed auth-id", args: []string{"auth", "reject", "not-valid", "--force"}, wantErr: notAnID},
		{name: "reject unknown auth-id", args: []string{"auth", "reject", unknown, "--force"}, wantErr: gone},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}

	// reject answers the registration, so it no longer waits.
	_, err = headscale.Execute([]string{"headscale", "auth", "reject", pending, "--force"})
	require.NoError(t, err)

	_, err = headscale.Execute([]string{"headscale", "auth", "register", pending, "user1"})
	require.ErrorContains(t, err, gone)
}
