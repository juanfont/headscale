package apiv0

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/stretchr/testify/require"
)

const (
	asHuJSON   = "Content-Type: application/hujson"
	policyOpen = `{
  // everyone reaches everything
  "acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}],
}`
	policyAlice = `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["*:*"]}]}`
)

func policyAPI(t *testing.T, opts ...func(*types.Config)) (Backend, humatest.TestAPI, string) {
	t.Helper()

	b := newBackend(t, opts...)

	key, _, err := b.State.CreateAPIKey(nil)
	require.NoError(t, err)

	return b, newTestAPI(t, b), "Authorization: Bearer " + key
}

func decodePolicy(t *testing.T, rec *httptest.ResponseRecorder) Policy {
	t.Helper()

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	var p Policy
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &p), rec.Body.String())

	return p
}

// putPolicy sends pol as the policy file, with args added to the request.
func putPolicy(api humatest.TestAPI, auth, query, pol string, args ...any) *httptest.ResponseRecorder {
	return api.Put(Prefix+"/policy"+query, append([]any{auth, asHuJSON, strings.NewReader(pol)}, args...)...)
}

// problemBody is a decoded problem with the members that differ between two
// calls left out.
func problemBody(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()

	var m map[string]any
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &m), rec.Body.String())
	delete(m, "requestId")

	return m
}

func TestGetPolicy(t *testing.T) {
	b, api, auth := policyAPI(t)

	rec := api.Get(Prefix+"/policy", auth)
	require.Equal(t, Policy{Mode: "database"}, decodePolicy(t, rec), "no policy is not an error")
	require.NotEmpty(t, rec.Header().Get("ETag"))

	stored, _, err := b.State.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	rec2 := api.Get(Prefix+"/policy", auth)
	require.Equal(t, Policy{Policy: policyOpen, Updated: new(micro(stored.UpdatedAt)), Mode: "database"}, decodePolicy(t, rec2), "the text as stored, comments kept")
	require.NotEqual(t, rec.Header().Get("ETag"), rec2.Header().Get("ETag"))
	require.Equal(t, rec2.Header().Get("ETag"), api.Get(Prefix+"/policy", auth).Header().Get("ETag"), "the ETag is stable")
}

func TestSetPolicy(t *testing.T) {
	b, api, auth := policyAPI(t)

	t.Run("the file as the body", func(t *testing.T) {
		rec := putPolicy(api, auth, "", policyOpen)
		got := decodePolicy(t, rec)
		require.Equal(t, policyOpen, got.Policy)
		require.NotNil(t, got.Updated)

		read := api.Get(Prefix+"/policy", auth)
		require.Equal(t, got, decodePolicy(t, read), "the answer is what a read gives")
		require.Equal(t, read.Header().Get("ETag"), rec.Header().Get("ETag"))
	})

	t.Run("as JSON", func(t *testing.T) {
		rec := api.Put(Prefix+"/policy", auth, map[string]any{"policy": policyAlice})
		require.JSONEq(t, policyAlice, decodePolicy(t, rec).Policy)
	})

	t.Run("checks of the request alone", func(t *testing.T) {
		decodeProblem(t, api.Put(Prefix+"/policy", auth, "Content-Type: text/plain", strings.NewReader(policyOpen)), CodeUnsupportedMediaType)
		decodeProblem(t, putPolicy(api, auth, "", "{\"acls\": [], \"x\": \"\xff\"}"), CodeInvalidRequest)

		p := decodeProblem(t, api.Put(Prefix+"/policy", auth, map[string]any{"policy": policyOpen, "polcy": ""}), CodeInvalidField)
		require.Equal(t, []string{"body.polcy"}, locations(p))

		p = decodeProblem(t, putPolicy(api, auth, "", policyOpen, "If-Match: 9b2c41"), CodeInvalidField)
		require.Equal(t, []string{"header.If-Match"}, locations(p))

		decodeProblem(t, putPolicy(api, auth, "", strings.Repeat(" ", maxPolicyBytes+1)), CodeTooLarge)
	})

	_ = b
}

// TestSetPolicyInvalid: each way a policy is refused, with the whole
// problem; a dry run answers the same problem, and nothing changes.
func TestSetPolicyInvalid(t *testing.T) {
	b, api, auth := policyAPI(t)

	alice, _, err := b.State.CreateUser(types.User{Name: "alice"})
	require.NoError(t, err)

	_, _, err = b.State.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	bob := b.State.CreateUserForTest("bob")
	bobNode := b.State.CreateRegisteredNodeForTest(bob, "bob-laptop")
	bobNode.User = bob
	b.State.PutNodeInStoreForTest(*bobNode)

	other, _, err := b.State.CreateUser(types.User{
		Name: "alice", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/alice", Valid: true},
	})
	require.NoError(t, err)

	tests := []struct {
		name   string
		pol    string
		errors []any
		notRun float64
	}{
		{
			name:   "does not parse",
			pol:    "{\n  \"acls\": [\n    {\"action\": \"accept\",, }\n  ]\n}",
			errors: []any{map[string]any{"message": "invalid character ',' at start of value", "line": 3.0, "column": 25.0}},
		},
		{
			name:   "does not validate",
			pol:    `{"acls": [{"action": "accept", "src": ["tag:none"], "dst": ["*:*"]}]}`,
			errors: []any{map[string]any{"message": `unknown tag "tag:none"`, "line": 1.0, "column": 40.0}},
		},
		{
			name: "a name two users have",
			pol:  "{\n  \"acls\": [{\"action\": \"accept\", \"src\": [\"alice@\"], \"dst\": [\"*:*\"]}]\n}",
			errors: []any{map[string]any{
				"message": `"alice@" matches more than one user, so it matches none: ` + alice.StringID() + ` (alice), ` + other.StringID() +
					` (alice); give the users different names or emails, or name one by its provider identifier`,
				"line": 2.0, "column": 41.0,
			}},
		},
		{
			name: "tests fail",
			pol: `{
  "acls": [{"action": "accept", "src": ["bob@"], "dst": ["*:22"]}],
  "ssh": [{"action": "check", "src": ["bob@"], "dst": ["bob@"], "users": ["root"]}],
  "tests": [{"src": "bob@", "accept": ["bob@:80"], "deny": ["bob@:22"]}],
  "sshTests": [{"src": "bob@", "dst": ["bob@"], "accept": ["root"], "deny": ["root"]}]
}`,
			errors: []any{},
		},
		{
			name: "an error and two tests, which do not run",
			pol: `{
  "acls": [{"action": "accept", "src": ["tag:none"], "dst": ["*:*"]}],
  "tests": [{"src": "bob@", "accept": ["bob@:22"]}],
  "sshTests": [{"src": "bob@", "dst": ["bob@"], "accept": ["root"]}]
}`,
			errors: []any{map[string]any{"message": `unknown tag "tag:none"`, "line": 2.0, "column": 41.0}},
			notRun: 2,
		},
		{
			name:   "a NUL byte",
			pol:    "{\"acls\": []}\n// \x00\n",
			errors: []any{map[string]any{"message": "the text has a NUL byte, which a policy cannot hold; remove it", "line": 2.0, "column": 4.0}},
		},
		{
			name:   "a name twice",
			pol:    `{"acls": [], "acls": []}`,
			errors: []any{map[string]any{"message": `"acls" is named twice in the same object; name it once`, "line": 1.0, "column": 14.0}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			before := api.Get(Prefix+"/policy", auth)

			dry := putPolicy(api, auth, "?dryRun=true", tt.pol)
			p := decodeProblem(t, dry, CodePolicyInvalid)

			require.Equal(t, tt.errors, p.Details["policyErrors"])

			require.InDelta(t, len(tt.errors), p.Details["policyErrorCount"], 0)
			require.InDelta(t, tt.notRun, p.Details["testsNotRun"], 0)

			if len(tt.errors) > 0 {
				require.Equal(t, []any{}, p.Details["failedTests"])
				require.InDelta(t, 0, p.Details["failedTestCount"], 0)
			}

			write := putPolicy(api, auth, "", tt.pol)
			decodeProblem(t, write, CodePolicyInvalid)

			if diff := cmp.Diff(problemBody(t, write), problemBody(t, dry), cmpopts.IgnoreMapEntries(func(k string, _ any) bool { return k == "detail" })); diff != "" {
				t.Errorf("the dry run answers what the write does (-write +dry run):\n%s", diff)
			}

			after := api.Get(Prefix+"/policy", auth)
			require.Equal(t, before.Body.String(), after.Body.String())
			require.Equal(t, before.Header().Get("ETag"), after.Header().Get("ETag"))
		})
	}

	t.Run("failed tests as data", func(t *testing.T) {
		p := decodeProblem(t, putPolicy(api, auth, "?dryRun=true", tests[3].pol), CodePolicyInvalid)
		require.Equal(t, []any{
			map[string]any{"kind": "acl", "index": 0.0, "src": "bob@", "dst": "bob@:80", "user": nil, "want": "accept", "got": "deny", "line": 4.0, "column": 13.0},
			map[string]any{"kind": "acl", "index": 0.0, "src": "bob@", "dst": "bob@:22", "user": nil, "want": "deny", "got": "accept", "line": 4.0, "column": 13.0},
			map[string]any{"kind": "ssh", "index": 0.0, "src": "bob@", "dst": "bob@", "user": "root", "want": "deny", "got": "check", "line": 5.0, "column": 16.0},
		}, p.Details["failedTests"])
		require.InDelta(t, 3, p.Details["failedTestCount"], 0)
		require.InDelta(t, 0, p.Details["testsNotRun"], 0, "they ran")
		require.Equal(t, []any{}, p.Details["policyErrors"])
	})
}

// TestSetPolicyDryRun: a dry run of a valid policy answers what the write
// answers, but updated null and no ETag, and changes nothing: not the
// policy in force, and not the stored row a restart would install.
func TestSetPolicyDryRun(t *testing.T) {
	b, api, auth := policyAPI(t)

	stored, _, err := b.State.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	before := api.Get(Prefix+"/policy", auth)
	filter, _ := b.State.Filter()

	pol := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}`

	dry := putPolicy(api, auth, "?dryRun=true", pol)
	dryBody := decodePolicy(t, dry)
	require.Empty(t, dry.Header().Get("ETag"), "a dry run guards nothing")
	require.Nil(t, dryBody.Updated, "nothing was stored")

	row, err := b.State.GetPolicy()
	require.NoError(t, err)
	require.Equal(t, policyOpen, row.Data, "a dry run stores nothing")
	require.True(t, stored.UpdatedAt.Equal(row.UpdatedAt))

	after := api.Get(Prefix+"/policy", auth)
	require.Equal(t, before.Body.String(), after.Body.String(), "a dry run stores nothing")
	require.Equal(t, before.Header().Get("ETag"), after.Header().Get("ETag"))

	afterFilter, _ := b.State.Filter()
	require.Equal(t, filter, afterFilter, "a dry run installs nothing")

	// All but updated, which only the write has, and the ETag.
	write := decodePolicy(t, putPolicy(api, auth, "", pol))
	if diff := cmp.Diff(write, dryBody, cmpopts.IgnoreFields(Policy{}, "Updated")); diff != "" {
		t.Errorf("the dry run answers what the write does (-write +dry run):\n%s", diff)
	}
}

func TestSetPolicyIfMatch(t *testing.T) {
	b, api, auth := policyAPI(t)

	_, _, err := b.State.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	etag := api.Get(Prefix+"/policy", auth).Header().Get("ETag")
	pol := `{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:22"]}]}`

	t.Run("a stale ETag", func(t *testing.T) {
		for _, h := range []string{`"0000"`, "W/" + etag} {
			decodeProblem(t, putPolicy(api, auth, "?dryRun=true", pol, "If-Match: "+h), CodePreconditionFailed)
			decodeProblem(t, putPolicy(api, auth, "", pol, "If-Match: "+h), CodePreconditionFailed)
		}

		decodeProblem(t, putPolicy(api, auth, "", `{"acls": [`, "If-Match: \"0000\""), CodePreconditionFailed)
	})

	t.Run("the ETag read", func(t *testing.T) {
		require.Equal(t, http.StatusOK, putPolicy(api, auth, "?dryRun=true", pol, "If-Match: "+etag).Code)

		rec := putPolicy(api, auth, "", pol, "If-Match: "+etag)
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.NotEqual(t, etag, rec.Header().Get("ETag"))

		decodeProblem(t, putPolicy(api, auth, "", policyOpen, "If-Match: "+etag), CodePreconditionFailed)
		require.Equal(t, http.StatusOK, putPolicy(api, auth, "", policyOpen, "If-Match: "+rec.Header().Get("ETag")).Code)
	})

	t.Run("none, and *", func(t *testing.T) {
		require.Equal(t, http.StatusOK, putPolicy(api, auth, "", pol).Code)
		require.Equal(t, http.StatusOK, putPolicy(api, auth, "", policyOpen, "If-Match: *").Code)
	})
}

// TestPolicyFileMode: the policy is read from a file. A write is refused,
// a dry run checks, a reload installs a valid file and refuses another, and
// GET /health warns until a valid file is in force.
func TestPolicyFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte(policyOpen), 0o600))

	_, api, auth := policyAPI(t, func(cfg *types.Config) {
		cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}
	})

	inForce := Policy{Policy: policyOpen, Mode: "file", Path: path}
	require.Equal(t, inForce, decodePolicy(t, api.Get(Prefix+"/policy", auth)))

	etag := api.Get(Prefix+"/policy", auth).Header().Get("ETag")

	p := decodeProblem(t, putPolicy(api, auth, "", policyOpen, "If-Match: \"0000\""), CodePolicyReadOnly)
	require.Equal(t, map[string]any{"path": path}, p.Details, "before the ETag")

	dry := decodePolicy(t, putPolicy(api, auth, "?dryRun=true", policyAlice, "If-Match: "+etag))
	require.Equal(t, Policy{Policy: policyAlice, Mode: "file", Path: path}, dry)

	onDisk, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, policyOpen, string(onDisk), "a dry run writes no file")
	decodeProblem(t, putPolicy(api, auth, "?dryRun=true", `{"acls": [`), CodePolicyInvalid)

	warnings := func() []Message {
		var h Health
		require.NoError(t, json.Unmarshal(api.Get(Prefix+"/health", auth).Body.Bytes(), &h))

		return h.Warnings
	}

	require.Empty(t, warnings())

	require.NoError(t, os.WriteFile(path, []byte("{\n  \"acls\": [\n"), 0o600))

	p = decodeProblem(t, api.Post(Prefix+"/policy/reload", auth), CodePolicyInvalid)
	require.Equal(t, []any{map[string]any{"message": "the text ends before the policy does", "line": 3.0, "column": 1.0}}, p.Details["policyErrors"])
	require.Equal(t, inForce, decodePolicy(t, api.Get(Prefix+"/policy", auth)), "the last valid policy stays")
	require.Equal(t, []Message{{
		Code:    WarningPolicyFileInvalid,
		Message: "The policy file is not valid; the last valid policy, or none, is in force.",
		Details: map[string]any{},
	}}, warnings())

	require.NoError(t, os.Remove(path))

	p = decodeProblem(t, api.Post(Prefix+"/policy/reload", auth), CodePolicyInvalid)
	require.Equal(t, []any{map[string]any{"message": "the policy file does not exist", "line": nil, "column": nil}}, p.Details["policyErrors"])

	require.NoError(t, os.WriteFile(path, []byte(policyAlice), 0o600))
	require.Equal(t, Policy{Policy: policyAlice, Mode: "file", Path: path}, decodePolicy(t, api.Post(Prefix+"/policy/reload", auth)))
	require.Empty(t, warnings(), "a valid file clears the warning")
}

func TestReloadPolicyDatabase(t *testing.T) {
	b, api, auth := policyAPI(t)

	stored, _, err := b.State.UpdatePolicy([]byte(policyOpen))
	require.NoError(t, err)

	require.Equal(t, Policy{Policy: policyOpen, Updated: new(micro(stored.UpdatedAt)), Mode: "database"}, decodePolicy(t, api.Post(Prefix+"/policy/reload", auth)))
}

// TestHealthPolicyUserAmbiguous: a second user with a name the policy in
// force uses makes the name match nobody; the health says so, and names the
// text, not the users.
func TestHealthPolicyUserAmbiguous(t *testing.T) {
	b, api, auth := policyAPI(t)

	_, _, err := b.State.CreateUser(types.User{Name: "alice"})
	require.NoError(t, err)

	_, _, err = b.State.UpdatePolicy([]byte(policyAlice))
	require.NoError(t, err)

	_, _, err = b.State.CreateUser(types.User{
		Name: "alice", Provider: util.RegisterMethodOIDC,
		ProviderIdentifier: sql.NullString{String: "https://idp.example.com/alice", Valid: true},
	})
	require.NoError(t, err)

	var h Health
	require.NoError(t, json.Unmarshal(api.Get(Prefix+"/health", auth).Body.Bytes(), &h))
	require.Equal(t, []Message{{
		Code:    WarningPolicyUserAmbiguous,
		Message: "The policy in force names 1 text that more than one user matches; it matches nobody.",
		Details: map[string]any{"count": 1.0},
	}}, h.Warnings)
}

// TestPolicyFileModeWithoutPath: the default config reads the policy from
// a file and names none. A write says so; a read and a reload answer that
// there is no policy.
func TestPolicyFileModeWithoutPath(t *testing.T) {
	_, api, auth := policyAPI(t, func(cfg *types.Config) {
		cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile}
	})

	none := Policy{Mode: "file"}
	require.Equal(t, none, decodePolicy(t, api.Get(Prefix+"/policy", auth)))
	require.Equal(t, none, decodePolicy(t, api.Post(Prefix+"/policy/reload", auth)))

	p := decodeProblem(t, putPolicy(api, auth, "", policyOpen), CodePolicyReadOnly)
	require.Equal(t, "No policy file is set (policy.path), and the policy cannot be written while policy.mode is file.", p.Detail)
	require.Equal(t, map[string]any{"path": ""}, p.Details)
}

// TestSetPolicyBodyForms: both forms of the body get the same answer, an
// empty one too.
func TestSetPolicyBodyForms(t *testing.T) {
	_, api, auth := policyAPI(t)

	empty := []any{map[string]any{"message": `policy is empty, use "{}" to allow all`, "line": nil, "column": nil}}

	for name, rec := range map[string]*httptest.ResponseRecorder{
		"the file, empty":   putPolicy(api, auth, "", ""),
		"JSON, empty text":  api.Put(Prefix+"/policy", auth, map[string]any{"policy": ""}),
		"the file, a blank": putPolicy(api, auth, "", " \n"),
	} {
		p := decodeProblem(t, rec, CodePolicyInvalid)
		require.Equal(t, empty, p.Details["policyErrors"], name)
	}

	p := decodeProblem(t, putPolicy(api, auth, "", "\ufeff"+policyOpen), CodePolicyInvalid)
	require.Equal(t, []any{map[string]any{
		"message": "the text has a byte-order mark, which HuJSON does not allow; save the file without it",
		"line":    1.0, "column": 1.0,
	}}, p.Details["policyErrors"])
}

// TestAcceptHuJSON: HuJSON is a request format of PUT /policy alone; as an
// Accept it is a type the server does not have, answered as JSON.
func TestAcceptHuJSON(t *testing.T) {
	_, api, auth := policyAPI(t)

	for _, path := range []string{"/users", "/policy"} {
		rec := api.Get(Prefix+path, auth, "Accept: application/hujson")
		require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
		require.Equal(t, "application/json", rec.Header().Get("Content-Type"), path)
	}
}

// TestPolicyRefusedTheSameEveryWay: one refused policy gives the same
// entries through every way in: a write, its dry run, and a reload of the
// file, which the watch of the file and SIGHUP run too.
func TestPolicyRefusedTheSameEveryWay(t *testing.T) {
	pols := []string{
		`{"acls": [{"action": "accept", "src": ["tag:nope", "group:nope"], "dst": ["nohost:22"]}]}`,
		"[1, 2]",
		"null",
		" \n\t",
		"{\n  \"acls\": [\n",
		`{"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}], "tests": [{"src": "nobody@", "accept": ["*:22"]}]}`,
		"{\"acls\": []}\n// \x00\n",
		`{"acls": [], "acls": []}`,
	}

	_, db, auth := policyAPI(t)

	path := filepath.Join(t.TempDir(), "policy.hujson")
	require.NoError(t, os.WriteFile(path, []byte(policyOpen), 0o600))

	_, file, fileAuth := policyAPI(t, func(cfg *types.Config) {
		cfg.Policy = types.PolicyConfig{Mode: types.PolicyModeFile, Path: path}
	})

	for _, pol := range pols {
		write := decodeProblem(t, putPolicy(db, auth, "", pol), CodePolicyInvalid).Details
		if pol == "null" {
			require.Equal(t, []any{map[string]any{"message": "the policy must be an object, such as {}", "line": 1.0, "column": 1.0}}, write["policyErrors"])
		}

		require.Equal(t, write, decodeProblem(t, putPolicy(db, auth, "?dryRun=true", pol), CodePolicyInvalid).Details, pol)

		require.NoError(t, os.WriteFile(path, []byte(pol), 0o600))
		require.Equal(t, write, decodeProblem(t, file.Post(Prefix+"/policy/reload", fileAuth), CodePolicyInvalid).Details, pol)
	}
}

// TestHealthPolicyStoredInvalid: a stored policy that a reload refuses, here
// null that a write of /api/v1 stored, is said in GET /health until a write
// succeeds.
func TestHealthPolicyStoredInvalid(t *testing.T) {
	b, api, auth := policyAPI(t)

	_, err := b.State.SetPolicyInDB("null")
	require.NoError(t, err)

	p := decodeProblem(t, api.Post(Prefix+"/policy/reload", auth), CodePolicyInvalid)
	require.Equal(t, []any{map[string]any{"message": "the policy must be an object, such as {}", "line": 1.0, "column": 1.0}}, p.Details["policyErrors"])

	var h Health
	require.NoError(t, json.Unmarshal(api.Get(Prefix+"/health", auth).Body.Bytes(), &h))
	require.Equal(t, []Message{{
		Code:    WarningPolicyStoredInvalid,
		Message: "The stored policy is not valid; the last valid policy, or none, is in force.",
		Details: map[string]any{},
	}}, h.Warnings)

	require.Equal(t, http.StatusOK, putPolicy(api, auth, "", policyOpen).Code)

	h = Health{}
	require.NoError(t, json.Unmarshal(api.Get(Prefix+"/health", auth).Body.Bytes(), &h))
	require.Empty(t, h.Warnings, "a write ends it")
}

var _ = time.Now
