package integration

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

// TestAuthCommandValidation exercises the validation permutations of the auth
// subcommands over the gRPC transport: `register` against a non-existent user
// and a malformed auth-id, and `approve`/`reject` against malformed and unknown
// auth-ids.
//
// approve/reject are only covered at this level: an approve carries an empty
// verdict that does not itself register a node — the waiting client is told to
// restart registration (hscontrol/auth.go waitForFollowup), so a driven
// web-login would hang. Completing an interactive registration is covered by
// `auth register` in the node tests and the web-auth flow tests.
func TestAuthCommandValidation(t *testing.T) {
	IntegrationSkip(t)

	scenario, headscale := setupCLIScenario(t, "cli-authval", []string{"user1"}, 0)
	defer scenario.ShutdownAssertNoPanics(t)

	// Well-formed (correct prefix/length) but unknown auth-id: the handler
	// reaches the cache lookup and reports no pending session.
	unknown := types.MustAuthID().String()

	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{name: "register malformed auth-id", args: []string{"auth", "register", "--user", "user1", "--auth-id", "not-valid"}, wantErr: "invalid"},
		{name: "register nonexistent user", args: []string{"auth", "register", "--user", "ghost", "--auth-id", unknown}, wantErr: "looking up user"},
		{name: "approve malformed auth-id", args: []string{"auth", "approve", "--auth-id", "not-valid"}, wantErr: "invalid auth_id"},
		{name: "approve unknown auth-id", args: []string{"auth", "approve", "--auth-id", unknown}, wantErr: "no pending auth session"},
		{name: "reject malformed auth-id", args: []string{"auth", "reject", "--auth-id", "not-valid"}, wantErr: "invalid auth_id"},
		{name: "reject unknown auth-id", args: []string{"auth", "reject", "--auth-id", unknown}, wantErr: "no pending auth session"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := headscale.Execute(append([]string{"headscale"}, tt.args...))
			require.ErrorContains(t, err, tt.wantErr)
		})
	}
}
