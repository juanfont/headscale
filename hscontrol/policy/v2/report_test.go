package v2

import (
	"fmt"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/require"
)

func explainPolicy(t *testing.T, users types.Users, pol string) ([]PolicyError, []FailedTest) {
	t.Helper()

	err := ValidatePolicy([]byte(pol), users, sshTestNodes(users).ViewSlice())
	require.Error(t, err)

	requireSentences(t, []byte(pol), err)

	e := Explain([]byte(pol), err)

	return e.Errors, e.FailedTests
}

// goErrorMarks are the words of a Go error, of a decoder or of a step that
// wraps an error: none belongs in a sentence for a person.
var goErrorMarks = []string{
	"json:", "Go ", "v2.", "unmarshal", "%!", ": resolving:", "parsing ", "setting policy",
	"loading policy", "hujson:", "jsontext", "<nil>", "within \"/",
}

// requireSentences fails when an entry that Explain makes of err, which
// refused b, has a mark of a Go error. The table tests of the package that
// refuse a policy call it, so their corpus is checked.
func requireSentences(t *testing.T, b []byte, err error) {
	t.Helper()

	e := Explain(b, err)
	for _, p := range e.Errors {
		for _, mark := range goErrorMarks {
			if strings.Contains(p.Message, mark) {
				t.Errorf("Explain(%q) has %q, a mark of a Go error, in %q", b, mark, p.Message)
			}
		}
	}
}

func TestExplainPlacesProblems(t *testing.T) {
	users := sshTestUsers()

	tests := []struct {
		name string
		pol  string
		want []PolicyError
	}{
		{
			name: "syntax",
			pol:  "{\n  \"acls\": [\n    {\"action\": \"accept\",, }\n  ]\n}",
			want: []PolicyError{{Message: "invalid character ',' at start of value", Line: 3, Column: 25}},
		},
		{
			name: "a syntax error on one line, at its column",
			pol:  `{"acls": [{"action": "accept"} {"action": "accept"}]}`,
			want: []PolicyError{{Message: "invalid character '{' after array value (expecting ',' or ']')", Line: 1, Column: 32}},
		},
		{
			name: "a name twice in one object, at the second",
			pol:  "{\n  \"groups\": {},\n  \"groups\": {}\n}",
			want: []PolicyError{{Message: `"groups" is named twice in the same object; name it once`, Line: 3, Column: 3}},
		},
		{
			name: "a name twice deeper, at the second",
			pol:  `{"acls": [{"action": "accept", "src": ["*"], "action": "accept", "dst": ["*:*"]}]}`,
			want: []PolicyError{{Message: `"action" is named twice in the same object; name it once`, Line: 1, Column: 46}},
		},
		{
			name: "unknown field",
			pol:  "{\n  // a comment\n  \"acls\": [],\n  \"bogus\": 1\n}",
			want: []PolicyError{{Message: `unknown field: "bogus"`, Line: 4, Column: 12}},
		},
		{
			name: "a value of the wrong type",
			pol:  "{\n  \"tagOwners\": {\"tag:a\": 5}\n}",
			want: []PolicyError{{Message: "has a value of the wrong type", Line: 2, Column: 26}},
		},
		{
			name: "an unknown tag, group or host, each use at its own place",
			pol:  "{\n  \"acls\": [{\"action\": \"accept\",\n    \"src\": [\"tag:nope\", \"group:nope\"],\n    \"dst\": [\"nohost:22\", \"tag:nope:80\"]}]\n}",
			want: []PolicyError{
				{Message: `unknown tag "tag:nope"`, Line: 3, Column: 13},
				{Message: `unknown group "group:nope"`, Line: 3, Column: 25},
				{Message: `unknown host "nohost"`, Line: 4, Column: 13},
				{Message: `unknown tag "tag:nope"`, Line: 4, Column: 26},
			},
		},
		{
			name: "an unknown tag as a destination only",
			pol:  "{\"acls\": [{\"action\": \"accept\", \"src\": [\"*\"],\n  \"dst\": [\"tag:nope:22\"]}]}",
			want: []PolicyError{{Message: `unknown tag "tag:nope"`, Line: 2, Column: 11}},
		},
		{
			name: "other validation errors have no place",
			pol:  `{"acls": [{"action": "accept", "src": ["autogroup:internet"], "dst": ["*:*"]}]}`,
			want: []PolicyError{{Message: ErrAutogroupInternetSrc.Error()}},
		},
		{
			name: "not an object",
			pol:  "[1, 2]",
			want: []PolicyError{{Message: "the policy must be an object, such as {}", Line: 1, Column: 1}},
		},
		{
			name: "a byte-order mark",
			pol:  "\ufeff{}",
			want: []PolicyError{{Message: "the text has a byte-order mark, which HuJSON does not allow; save the file without it", Line: 1, Column: 1}},
		},
		{
			name: "cut short",
			pol:  "{\"acls\": [",
			want: []PolicyError{{Message: "the text ends before the policy does", Line: 1, Column: 11}},
		},
		{
			name: "blank reads as empty",
			pol:  " \n\t",
			want: []PolicyError{{Message: ErrPolicyEmpty.Error()}},
		},
		{
			name: "a test entry that is not valid",
			pol:  `{"tests": [{"src": "*", "accept": ["*:22"]}, {"src": "*", "accept": ["no-port"]}]}`,
			want: []PolicyError{{Message: `tests[1]: accept "no-port": hostport must contain a colon`, Line: 1, Column: 46}},
		},
		{
			name: "an sshTests entry that is not valid, at its entry",
			pol:  "{\"sshTests\": [\n  {\"dst\": [\"tag:x\"], \"accept\": [\"root\"]}]}",
			want: []PolicyError{
				{Message: `sshTests[0]: SSH tests entry must have a non-empty src`, Line: 2, Column: 3},
				{Message: `sshTests[0]: SSH tests dst contains unknown tag "tag:x"`, Line: 2, Column: 3},
			},
		},
		{
			name: "empty",
			pol:  "",
			want: []PolicyError{{Message: ErrPolicyEmpty.Error()}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, failed := explainPolicy(t, users, tt.pol)
			require.Empty(t, failed)

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Errorf("Explain() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExplainAmbiguousUser(t *testing.T) {
	users := append(sshTestUsers(), types.User{ID: 9, Name: "alice"})

	pol := `{
  "groups": {"group:ops": ["bob@", "alice@"]},
  "acls": [
    {"action": "accept", "src": ["alice@"], "dst": ["*:*"]},
    {"action": "accept", "src": ["group:ops"], "dst": ["alice@:22"]}
  ]
}`

	got, failed := explainPolicy(t, users, pol)
	require.Empty(t, failed)

	want := []PolicyError{{
		Message: `"alice@" matches more than one user, so it matches none: 1 (alice), 9 (alice); give the users different names or emails, or name one by its provider identifier`,
		Line:    2, Column: 36,
	}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("one entry for the text, where the policy first names it (-want +got):\n%s", diff)
	}

	// The text that the other APIs answer stays as it was.
	err := ValidatePolicy([]byte(pol), users, sshTestNodes(users).ViewSlice())
	require.ErrorIs(t, err, ErrMultipleUsersFound)
	require.ErrorContains(t, err, `validating policy user references: multiple errors:
	multiple users found: token "alice@" found: [ 1: alice, 9: alice,  ]`)

	pm, err := NewPolicyManager([]byte(pol), users, sshTestNodes(users).ViewSlice())
	require.NoError(t, err, "a stored policy still loads")
	require.Equal(t, []string{"alice@"}, pm.AmbiguousUsers())
}

func TestExplainFailedTests(t *testing.T) {
	users := sshTestUsers()

	pol := `{
  "tagOwners": {"tag:server": ["alice@"], "tag:prod": ["alice@"]},
  "acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:server:22"]}],
  "ssh": [
    {"action": "accept", "src": ["alice@"], "dst": ["tag:server"], "users": ["root"]},
    {"action": "check", "src": ["bob@"], "dst": ["tag:prod"], "users": ["root"]}
  ],
  "tests": [
    {"src": "alice@", "accept": ["tag:server:22"]},
    {"src": "bob@", "accept": ["tag:server:22"], "deny": ["tag:prod:22"]},
    {"src": "alice@", "deny": ["tag:server:22", "tag:prod:22"]},
    {"src": "nobody@", "accept": ["tag:server:22"]}
  ],
  "sshTests": [
    {"src": "alice@", "dst": ["tag:server"], "check": ["root"]},
    {"src": "bob@", "dst": ["tag:prod"], "deny": ["root"]},
    {"src": "alice@", "dst": ["tag:server"], "deny": ["root"]},
    {"src": "bob@", "dst": ["tag:server"], "accept": ["root"], "check": ["root"]}
  ]
}`

	problems, failed := explainPolicy(t, users, pol)

	wantFailed := []FailedTest{
		{Kind: "acl", Index: 1, Src: "bob@", Dst: "tag:server:22", Want: "accept", Got: "deny", Line: 10, Column: 5},
		{Kind: "acl", Index: 2, Src: "alice@", Dst: "tag:server:22", Want: "deny", Got: "accept", Line: 11, Column: 5},
		{Kind: "ssh", Index: 0, Src: "alice@", Dst: "tag:server", User: "root", Want: "check", Got: "accept", Line: 15, Column: 5},
		{Kind: "ssh", Index: 1, Src: "bob@", Dst: "tag:prod", User: "root", Want: "deny", Got: "check", Line: 16, Column: 5},
		{Kind: "ssh", Index: 2, Src: "alice@", Dst: "tag:server", User: "root", Want: "deny", Got: "accept", Line: 17, Column: 5},
		{Kind: "ssh", Index: 3, Src: "bob@", Dst: "tag:server", User: "root", Want: "accept", Got: "deny", Line: 18, Column: 5},
		{Kind: "ssh", Index: 3, Src: "bob@", Dst: "tag:server", User: "root", Want: "check", Got: "deny", Line: 18, Column: 5},
	}
	if diff := cmp.Diff(wantFailed, failed); diff != "" {
		t.Errorf("failed tests mismatch (-want +got):\n%s", diff)
	}

	wantProblems := []PolicyError{
		{Message: `tests[3]: the source "nobody@" matches no user`, Line: 12, Column: 5},
	}
	if diff := cmp.Diff(wantProblems, problems); diff != "" {
		t.Errorf("an entry that cannot run is a problem at the entry (-want +got):\n%s", diff)
	}
}

// TestExplainTestsNotRun: a policy refused before its tests counts them as
// not run; one whose tests ran and failed counts none.
func TestExplainTestsNotRun(t *testing.T) {
	users := sshTestUsers()

	for _, tt := range []struct {
		name, pol string
		notRun    int
		failed    int
	}{
		{
			name:   "an error and two tests",
			pol:    `{"acls": [{"action": "accept", "src": ["tag:nope"], "dst": ["*:*"]}], "tests": [{"src": "alice@", "accept": ["bob@:22"]}], "sshTests": [{"src": "alice@", "dst": ["bob@"], "accept": ["root"]}]}`,
			notRun: 2,
		},
		{
			name:   "only failing tests",
			pol:    `{"acls": [], "tests": [{"src": "alice@", "accept": ["bob@:22"]}, {"src": "bob@", "accept": ["alice@:22"]}]}`,
			failed: 2,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidatePolicy([]byte(tt.pol), users, sshTestNodes(users).ViewSlice())
			require.Error(t, err)

			e := Explain([]byte(tt.pol), err)
			require.Equal(t, tt.notRun, e.TestsNotRun)
			require.Equal(t, tt.failed, e.FailedTestCount)
		})
	}
}

func TestExplainBounds(t *testing.T) {
	users := sshTestUsers()

	pol := `{"acls": [{"action": "accept", "src": ["alice@"], "dst": ["tag:server:22"]}], "tagOwners": {"tag:server": ["alice@"]}, "tests": [`

	var tests strings.Builder

	for i := range maxExplained + 5 {
		if i > 0 {
			tests.WriteString(",")
		}

		tests.WriteString(`{"src": "bob@", "accept": ["tag:server:22"]}`)
	}

	pol += tests.String()

	pol += `]}`

	err := ValidatePolicy([]byte(pol), users, sshTestNodes(users).ViewSlice())
	require.Error(t, err)

	e := Explain([]byte(pol), err)
	require.Len(t, e.FailedTests, maxExplained)
	require.Equal(t, maxExplained+5, e.FailedTestCount, "the count is of every failed test")
	require.Empty(t, e.Errors, "the cut is no problem of the policy")
	require.Zero(t, e.ErrorCount)
}

// TestExplainSameThroughEveryStep: the steps that wrap an error on the way
// out (the manager's, the state's) leave the entries as they are.
func TestExplainSameThroughEveryStep(t *testing.T) {
	users := sshTestUsers()
	pol := []byte(`{"acls": [{"action": "accept", "src": ["tag:nope"], "dst": ["*:*"]}]}`)

	err := ValidatePolicy(pol, users, sshTestNodes(users).ViewSlice())
	require.Error(t, err)

	want := Explain(pol, err)
	require.Equal(t, []PolicyError{{Message: `unknown tag "tag:nope"`, Line: 1, Column: 40}}, want.Errors)

	for _, wrapped := range []error{
		fmt.Errorf("setting policy: %w", err),
		fmt.Errorf("loading policy: %w", fmt.Errorf("setting policy: %w", err)),
		&contextError{context: "parsing policy", err: err},
	} {
		require.Equal(t, want, Explain(pol, wrapped), wrapped.Error())
	}
}
