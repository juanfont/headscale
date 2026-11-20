package servertest_test

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/juanfont/headscale/hscontrol/servertest"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/netmap"
)

const hujson = "application/hujson"

// putPolicy writes pol as the policy file through the generated client.
func putPolicy(t *testing.T, c *clientv0.ClientWithResponses, dryRun bool, ifMatch, pol string) *clientv0.SetPolicyResponse {
	t.Helper()

	params := &clientv0.SetPolicyParams{DryRun: &dryRun}
	if ifMatch != "" {
		params.IfMatch = &ifMatch
	}

	resp, err := c.SetPolicyWithBodyWithResponse(t.Context(), params, hujson, strings.NewReader(pol))
	require.NoError(t, err)

	return resp
}

// answer is a decoded answer without the members that differ between two
// calls: the request ID, and the sentence for a person.
func answer(t *testing.T, body []byte) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(body, &m), string(body))
	delete(m, "requestId")
	delete(m, "detail")

	return m
}

// filterOf is the packet filter a client was sent.
func filterOf(nm *netmap.NetworkMap) string {
	if nm == nil {
		return ""
	}

	return fmt.Sprint(nm.PacketFilter)
}

// TestAPIv0Policy runs the policy operations through the generated client
// against a real server with connected nodes: each way a write is refused,
// as data, the dry run of each with the same answer, the guard of If-Match,
// and a dry run that leaves the policy, its ETag and the filters of the
// nodes as they were.
func TestAPIv0Policy(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	srv := servertest.NewServer(t)
	c := v0Client(t, srv)
	ctx := t.Context()

	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	na := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))
	na.WaitForPeers(t, 1, 10*time.Second)

	open := "{\n  // everyone\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"*\"], \"dst\": [\"*:*\"]}],\n}"
	resp := putPolicy(t, c, false, "", open)
	require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
	require.Equal(t, open, resp.JSON200.Policy)

	got, err := c.GetPolicyWithResponse(ctx)
	require.NoError(t, err)
	require.Equal(t, resp.JSON200, got.JSON200)
	require.Equal(t, resp.HTTPResponse.Header.Get("ETag"), got.HTTPResponse.Header.Get("ETag"))

	etag := got.HTTPResponse.Header.Get("ETag")

	na.WaitForCondition(t, "the open policy", 10*time.Second, func(nm *netmap.NetworkMap) bool { return len(nm.PacketFilter) > 0 })
	filter := filterOf(na.Netmap())

	unchanged := func(t *testing.T) {
		t.Helper()

		now, err := c.GetPolicyWithResponse(ctx)
		require.NoError(t, err)
		require.Equal(t, got.JSON200, now.JSON200)
		require.Equal(t, etag, now.HTTPResponse.Header.Get("ETag"))
		require.Equal(t, filter, filterOf(na.Netmap()))

		row, err := srv.State().GetPolicy()
		require.NoError(t, err)
		require.Equal(t, open, row.Data, "the stored row, which a restart installs")
	}

	other, _, err := srv.State().CreateUser(types.User{
		Name: "alice", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/alice", Valid: true},
	})
	require.NoError(t, err)

	refused := []struct {
		name        string
		pol         string
		errors      []any
		failedTests []any
		testsNotRun float64
	}{
		{
			name:        "does not parse",
			pol:         "{\n  \"acls\": [\n    {\"action\": \"accept\",, }\n  ]\n}",
			errors:      []any{map[string]any{"message": "invalid character ',' at start of value", "line": 3.0, "column": 25.0}},
			failedTests: []any{},
		},
		{
			name:        "does not validate",
			pol:         `{"acls": [{"action": "accept", "src": ["group:none"], "dst": ["*:*"]}]}`,
			errors:      []any{map[string]any{"message": `unknown group "group:none"`, "line": 1.0, "column": 40.0}},
			failedTests: []any{},
		},
		{
			name:        "does not validate, and its test does not run",
			pol:         `{"acls": [{"action": "accept", "src": ["group:none"], "dst": ["*:*"]}], "tests": [{"src": "bob@", "accept": ["bob@:22"]}]}`,
			errors:      []any{map[string]any{"message": `unknown group "group:none"`, "line": 1.0, "column": 40.0}},
			failedTests: []any{},
			testsNotRun: 1,
		},
		{
			name: "a name two users have",
			pol:  "{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"alice@\"], \"dst\": [\"*:*\"]}]\n}",
			errors: []any{map[string]any{
				"message": fmt.Sprintf(`"alice@" matches more than one user, so it matches none: %d (alice), %d (alice); give the users different names or emails, or name one by its provider identifier`, alice.ID, other.ID),
				"line":    2.0, "column": 41.0,
			}},
			failedTests: []any{},
		},
		{
			name: "tests fail",
			pol: `{
  "acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:22"]}],
  "ssh": [
    {"action": "accept", "src": ["bob@"], "dst": ["bob@"], "users": ["root"]},
    {"action": "check", "src": ["bob@"], "dst": ["bob@"], "users": ["ubuntu"]}
  ],
  "tests": [{"src": "bob@", "accept": ["bob@:80", "bob@:22"], "deny": ["bob@:22"]}],
  "sshTests": [
    {"src": "bob@", "dst": ["bob@"], "check": ["root"], "deny": ["ubuntu"]},
    {"src": "bob@", "dst": ["bob@"], "accept": ["admin"], "check": ["admin"]}
  ]
}`,
			errors: []any{},
			failedTests: []any{
				map[string]any{"kind": "acl", "index": 0.0, "src": "bob@", "dst": "bob@:80", "user": nil, "want": "accept", "got": "deny", "line": 7.0, "column": 13.0},
				map[string]any{"kind": "acl", "index": 0.0, "src": "bob@", "dst": "bob@:22", "user": nil, "want": "deny", "got": "accept", "line": 7.0, "column": 13.0},
				map[string]any{"kind": "ssh", "index": 0.0, "src": "bob@", "dst": "bob@", "user": "ubuntu", "want": "deny", "got": "check", "line": 9.0, "column": 5.0},
				map[string]any{"kind": "ssh", "index": 0.0, "src": "bob@", "dst": "bob@", "user": "root", "want": "check", "got": "accept", "line": 9.0, "column": 5.0},
				map[string]any{"kind": "ssh", "index": 1.0, "src": "bob@", "dst": "bob@", "user": "admin", "want": "accept", "got": "deny", "line": 10.0, "column": 5.0},
				map[string]any{"kind": "ssh", "index": 1.0, "src": "bob@", "dst": "bob@", "user": "admin", "want": "check", "got": "deny", "line": 10.0, "column": 5.0},
			},
		},
	}

	for _, tt := range refused {
		t.Run(tt.name, func(t *testing.T) {
			dry := putPolicy(t, c, true, "", tt.pol)
			require.Equal(t, http.StatusUnprocessableEntity, dry.StatusCode(), string(dry.Body))
			require.Equal(t, "policy_invalid", string(dry.ApplicationproblemJSON422.Code))

			details := answer(t, dry.Body)["details"].(map[string]any) //nolint:forcetypeassert // checked by the diff below

			want := map[string]any{
				"policyErrors": tt.errors, "policyErrorCount": float64(len(tt.errors)),
				"failedTests": tt.failedTests, "failedTestCount": float64(len(tt.failedTests)),
				"testsNotRun": tt.testsNotRun,
			}
			if diff := cmp.Diff(want, details); diff != "" {
				t.Errorf("details (-want +got):\n%s", diff)
			}

			unchanged(t)

			write := putPolicy(t, c, false, "", tt.pol)
			if diff := cmp.Diff(answer(t, write.Body), answer(t, dry.Body)); diff != "" {
				t.Errorf("the dry run answers what the write does (-write +dry run):\n%s", diff)
			}

			unchanged(t)
		})
	}

	t.Run("a valid dry run", func(t *testing.T) {
		pol := `{"acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:*"]}]}`

		dry := putPolicy(t, c, true, etag, pol)
		require.Equal(t, http.StatusOK, dry.StatusCode(), string(dry.Body))
		require.Empty(t, dry.HTTPResponse.Header.Get("ETag"))
		require.True(t, dry.JSON200.Updated.IsNull(), "nothing was stored")

		unchanged(t)

		stale := putPolicy(t, c, false, `"0000"`, pol)
		require.Equal(t, http.StatusPreconditionFailed, stale.StatusCode(), string(stale.Body))
		require.Equal(t, http.StatusPreconditionFailed, putPolicy(t, c, true, `"0000"`, pol).StatusCode())

		unchanged(t)

		write := putPolicy(t, c, false, etag, pol)
		require.Equal(t, http.StatusOK, write.StatusCode(), string(write.Body))

		if diff := cmp.Diff(write.JSON200, dry.JSON200, cmpopts.IgnoreFields(clientv0.Policy{}, "Updated")); diff != "" {
			t.Errorf("the dry run answers what the write does (-write +dry run):\n%s", diff)
		}

		na.WaitForCondition(t, "alice loses her access", 10*time.Second, func(nm *netmap.NetworkMap) bool { return filterOf(nm) != filter })

		again := putPolicy(t, c, false, etag, open)
		require.Equal(t, http.StatusPreconditionFailed, again.StatusCode(), "the ETag read before the write")
		require.Equal(t, "precondition_failed", string(again.ApplicationproblemJSON412.Code))

		none := putPolicy(t, c, false, "", open)
		require.Equal(t, http.StatusOK, none.StatusCode(), "no If-Match, no guard")
	})

	t.Run("reload", func(t *testing.T) {
		resp, err := c.ReloadPolicyWithResponse(ctx)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, resp.StatusCode(), string(resp.Body))
		require.Equal(t, open, resp.JSON200.Policy)
		require.Equal(t, clientv0.PolicyMode("database"), resp.JSON200.Mode)
	})
}

// TestAPIv0PolicyFile: in file mode the server watches the file. A save in
// any way an editor saves is in force and the nodes are told; a save it
// refuses, and a removed file, leave the last valid policy, with a warning
// in GET /health until a valid file is saved. A write is refused, a dry run
// checks.
func TestAPIv0PolicyFile(t *testing.T) { //nolint:tparallel // the steps build on each other
	t.Parallel()

	dir := t.TempDir()
	path := filepath.Join(dir, "policy.hujson")
	open := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]}`
	require.NoError(t, os.WriteFile(path, []byte(open), 0o600))

	srv := servertest.NewServer(t, servertest.WithPolicyFile(path))
	c := v0Client(t, srv)
	ctx := t.Context()

	alice := srv.CreateUser(t, "alice")
	bob := srv.CreateUser(t, "bob")
	na := servertest.NewClient(t, srv, "alice-laptop", servertest.WithUser(alice))
	servertest.NewClient(t, srv, "bob-laptop", servertest.WithUser(bob))
	na.WaitForPeers(t, 1, 10*time.Second)

	inForce := func(t *testing.T, want string) {
		t.Helper()

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := c.GetPolicyWithResponse(ctx)
			assert.NoError(ct, err)
			assert.Equal(ct, want, resp.JSON200.Policy)
		}, 10*time.Second, 20*time.Millisecond)
	}

	warnings := func(t *testing.T, want ...string) {
		t.Helper()

		require.EventuallyWithT(t, func(ct *assert.CollectT) {
			resp, err := c.GetHealthWithResponse(ctx)
			assert.NoError(ct, err)

			codes := make([]string, 0, len(resp.JSON200.Warnings))
			for _, w := range resp.JSON200.Warnings {
				codes = append(codes, string(w.Code))
			}

			assert.Equal(ct, append([]string{}, want...), codes)
		}, 10*time.Second, 20*time.Millisecond)
	}

	resp := putPolicy(t, c, false, "", open)
	require.Equal(t, http.StatusConflict, resp.StatusCode())
	require.Equal(t, "policy_read_only", string(resp.ApplicationproblemJSON409.Code))
	require.Equal(t, map[string]any{"path": path}, resp.ApplicationproblemJSON409.Details)

	dry := putPolicy(t, c, true, "", `{"acls": [`)
	require.Equal(t, http.StatusUnprocessableEntity, dry.StatusCode(), "a dry run checks in file mode")

	bobOnly := `{"acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:*"]}]}`

	// The file the server holds in force at the end of a step.
	var saved string

	t.Run("a write in place", func(t *testing.T) {
		filter := filterOf(na.Netmap())

		require.NoError(t, os.WriteFile(path, []byte(bobOnly), 0o600))
		inForce(t, bobOnly)
		na.WaitForCondition(t, "the nodes are told", 10*time.Second, func(nm *netmap.NetworkMap) bool { return filterOf(nm) != filter })
	})

	t.Run("a save the server refuses", func(t *testing.T) {
		require.NoError(t, os.WriteFile(path, []byte(`{"acls": [`), 0o600))
		warnings(t, "policy_file_invalid")
		inForce(t, bobOnly)

		reload, err := c.ReloadPolicyWithResponse(ctx)
		require.NoError(t, err)
		require.Equal(t, http.StatusUnprocessableEntity, reload.StatusCode(), "reload says why")
	})

	t.Run("a file renamed over it clears the warning", func(t *testing.T) {
		tmp := filepath.Join(dir, ".policy.hujson.tmp")
		require.NoError(t, os.WriteFile(tmp, []byte(open), 0o600))
		require.NoError(t, os.Rename(tmp, path))
		inForce(t, open)
		warnings(t)
	})

	t.Run("a removed file, then a new one", func(t *testing.T) {
		require.NoError(t, os.Remove(path))
		warnings(t, "policy_file_invalid")
		inForce(t, open)

		require.NoError(t, os.WriteFile(path, []byte(bobOnly), 0o600))
		inForce(t, bobOnly)
		warnings(t)
	})

	t.Run("refused for the users, in force once they change", func(t *testing.T) {
		other, _, err := srv.State().CreateUser(types.User{
			Name: "bob", Provider: util.RegisterMethodOIDC,
			ProviderIdentifier: sql.NullString{String: "https://idp.example.com/bob", Valid: true},
		})
		require.NoError(t, err)
		warnings(t, "policy_user_ambiguous")

		saved = "// bob alone\n" + bobOnly
		require.NoError(t, os.WriteFile(path, []byte(saved), 0o600))
		warnings(t, "policy_file_invalid", "policy_user_ambiguous")
		inForce(t, bobOnly)

		changes, err := srv.State().DeleteUser(types.UserID(other.ID))
		require.NoError(t, err)
		srv.App.Change(changes...)

		inForce(t, saved)
		warnings(t)
	})

	t.Run("a file emptied, blank or null is refused, as at a reload", func(t *testing.T) {
		for _, text := range []string{"", " \n\t", "null"} {
			require.NoError(t, os.WriteFile(path, []byte(text), 0o600))
			warnings(t, "policy_file_invalid")
			inForce(t, saved)

			require.NoError(t, os.WriteFile(path, []byte(saved), 0o600))
			warnings(t)
		}
	})
}
