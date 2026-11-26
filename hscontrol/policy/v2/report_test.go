package v2

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/go-json-experiment/json/jsontext"
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
			name: "a name twice in two spellings the decoder takes as one, at the second",
			pol:  "{\n\"acls\": [],\n\"A_CLS\": []\n}",
			want: []PolicyError{{Message: `"A_CLS" is named twice in the same object; name it once`, Line: 3, Column: 1}},
		},
		{
			name: "a field twice in two spellings deeper, at the second",
			pol:  "{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"],\n\"S-RC\":[\"*\"]}]}",
			want: []PolicyError{{Message: `"S-RC" is named twice in the same object; name it once`, Line: 2, Column: 1}},
		},
		{
			name: "an unknown field under a field in another spelling",
			pol:  "{\"A_CLS\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"],\n\"bogus\":1}]}",
			want: []PolicyError{{Message: `unknown field: "bogus"`, Line: 2, Column: 9}},
		},
		{
			name: "a name with white space the decoder trims, at its own place",
			pol:  "{\"acls\":[{\"action\":\"accept\",\"src\":[\n\" tag:nope \",\n\"tag:nope\"],\"dst\":[\"*:*\"]}]}",
			want: []PolicyError{
				{Message: `unknown tag "tag:nope"`, Line: 2, Column: 1},
				{Message: `unknown tag "tag:nope"`, Line: 3, Column: 1},
			},
		},
		{
			name: "an unknown field in an SSH test, which a decode of its own reads",
			pol:  "{\"sshTests\":[{\"src\":\"a@\",\n\"bogus\":1}]}",
			want: []PolicyError{{Message: `unknown field: "bogus"`, Line: 2, Column: 9}},
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
			name: "an unknown host at its use, not at an SSH login of the same spelling",
			pol:  "{\n\"ssh\":[{\"action\":\"accept\",\"src\":[\"bob@\"],\"dst\":[\"bob@\"],\"users\":[\"build\"]}],\n\"acls\":[{\"action\":\"accept\",\"src\":[\"bob@\"],\"dst\":[\"build:22\"]}]\n}",
			want: []PolicyError{{Message: `unknown host "build"`, Line: 3, Column: 50}},
		},
		{
			name: "an unknown tag at its use, not at a via or a test of the same spelling",
			pol:  "{\n\"tests\":[{\"src\":\"bob@\",\"accept\":[\"tag:nope:22\"]}],\n\"grants\":[{\"src\":[\"bob@\"],\"dst\":[\"bob@\"],\"ip\":[\"*\"],\"via\":[\"tag:nope\"]}],\n\"acls\":[{\"action\":\"accept\",\"src\":[\"tag:nope\"],\"dst\":[\"*:*\"]}]\n}",
			want: []PolicyError{
				{Message: `unknown tag "tag:nope"`, Line: 4, Column: 35},
				{Message: `tag "tag:nope" not found`},
			},
		},
		{
			name: "an unknown group at its use, not at an SSH destination that refuses any group",
			pol:  "{\n\"ssh\":[{\"action\":\"accept\",\"src\":[\"bob@\"],\"dst\":[\"group:nope\"],\"users\":[\"root\"]}],\n\"acls\":[{\"action\":\"accept\",\"src\":[\"group:nope\"],\"dst\":[\"*:*\"]}]\n}",
			want: []PolicyError{
				{Message: `unknown group "group:nope"`, Line: 3, Column: 35},
				{Message: "[ssh] " + ErrSSHGroupDst.Error()},
			},
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

	// The SSH login of the same spelling comes first and is not a user.
	pol := `{
  "ssh": [{"action": "accept", "src": ["bob@"], "dst": ["bob@"], "users": ["alice@"]}],
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
		Line:    3, Column: 36,
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

			// CheckPolicy, which runs the tests against stand-ins, counts
			// the same.
			e = Explain([]byte(tt.pol), CheckPolicy([]byte(tt.pol)))
			require.Equal(t, tt.notRun, e.TestsNotRun, "CheckPolicy")
			require.Equal(t, tt.failed, e.FailedTestCount, "CheckPolicy")
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

// TestExplainPlacesEverySpelling: the decoder takes a field's name in any
// case and with '-' or '_' anywhere in it. Every path at which the report
// places what it finds by walking the text ([placedAt]) is placed under
// every such spelling of each field on the way, beside a use of the same
// name under another field; a test entry is placed, and counted when the
// tests did not run. A path added to placedAt without a case here fails.
func TestExplainPlacesEverySpelling(t *testing.T) {
	users := append(sshTestUsers(), types.User{ID: 9, Name: "alice"})

	spellings := func(name string) []string {
		return []string{
			name, strings.ToUpper(name), name[:1] + "_" + name[1:], name[:1] + "-" + name[1:],
			"_" + strings.ToUpper(name[:1]) + name[1:] + "-",
		}
	}

	// A document per path, or per kind and path, « before each place the
	// report must give; TOKEN is the name of the kind.
	documents := map[string]string{
		"acls/*/src/*":   `"acls":[{"action":"accept","dst":["*:*"],"src":[«"TOKEN"]}]`,
		"acls/*/dst/*":   `"acls":[{"action":"accept","src":["*"],"dst":[«"TOKEN:22"]}]`,
		"grants/*/src/*": `"grants":[{"ip":["*"],"dst":["*"],"src":[«"TOKEN"]}]`,
		"grants/*/dst/*": `"grants":[{"ip":["*"],"src":["*"],"dst":[«"TOKEN"]}]`,
		"ssh/*/src/*":    `"ssh":[{"action":"accept","dst":["autogroup:self"],"users":["root"],"src":[«"TOKEN"]}]`,
		"ssh/*/dst/*":    `"ssh":[{"action":"accept","src":["autogroup:member"],"users":["root"],"dst":[«"TOKEN"]}]`,
		// A user in an SSH destination needs itself as the source, named after.
		"user ssh/*/dst/*":         `"ssh":[{"action":"accept","users":["root"],"dst":[«"TOKEN"],"src":["TOKEN"]}]`,
		"nodeAttrs/*/target/*":     `"nodeAttrs":[{"target":[«"TOKEN"]}]`,
		"autoApprovers/routes/*/*": `"autoApprovers":{"routes":{"10.0.0.0/8":[«"TOKEN"]}}`,
		"autoApprovers/exitNode/*": `"autoApprovers":{"exitNode":[«"TOKEN"]}`,
		"tagOwners/*/*":            `"tagOwners":{"tag:a":[«"TOKEN"]}`,
		"groups/*/*":               `"groups":{"group:ops":[«"TOKEN"]}`,
		"tests/*": `"acls":[{"action":"accept","src":["bob@"],"dst":["*:22"]}],
"tests":[«{"src":"bob@","accept":["bob@:80"]},
«{"src":"bob@","accept":["bob@:81"]}]`,
		"sshTests/*": `"ssh":[{"action":"check","src":["bob@"],"dst":["bob@"],"users":["root"]}],
"sshTests":[«{"src":"bob@","dst":["bob@"],"deny":["root"]},
«{"src":"bob@","dst":["bob@"],"deny":["root"]}]`,
	}

	tokens := map[string]string{"host": "nohost", "tag": "tag:nope", "group": "group:nope", "user": "alice@"}

	// marked is doc without its marks, and where they were.
	marked := func(doc string) (string, [][2]int) {
		var places [][2]int

		for {
			i := strings.Index(doc, "«")
			if i < 0 {
				return doc, places
			}

			doc = doc[:i] + doc[i+len("«"):]
			line, col := lineColumn([]byte(doc), i)
			places = append(places, [2]int{line, col})
		}
	}

	sorted := func(p [][2]int) [][2]int {
		slices.SortFunc(p, func(a, b [2]int) int { return (a[0]-b[0])*1000 + a[1] - b[1] })

		return p
	}

	for kind, paths := range placedAt {
		for _, path := range paths {
			doc, ok := documents[kind+" "+path]
			if !ok {
				doc, ok = documents[path]
			}

			if !ok {
				t.Errorf("placedAt places %s at %s, which this test has no document for", kind, path)

				continue
			}

			token, named := tokens[kind]
			if named {
				// The other use, under a field of another name; a user is
				// placed once, where the policy first names it.
				anchor := `"acls":[{"action":"accept","dst":["*:*"],"src":[«"TOKEN"]}]`
				if strings.HasPrefix(path, "acls/") {
					anchor = `"grants":[{"ip":["*"],"dst":["*"],"src":[«"TOKEN"]}]`
				}

				if kind == "user" {
					anchor = strings.ReplaceAll(anchor, "«", "")
				}

				doc = strings.ReplaceAll(doc+",\n"+anchor, "TOKEN", token)
			}

			docs := []string{doc}

			for seg := range strings.SplitSeq(path, "/") {
				if seg == "*" {
					continue
				}

				var next []string

				for _, d := range docs {
					for _, spelled := range spellings(seg) {
						next = append(next, strings.ReplaceAll(d, `"`+seg+`":`, `"`+spelled+`":`))
					}
				}

				docs = next
			}

			for _, d := range docs {
				pol, want := marked("{\n" + d + "\n}")

				t.Run(kind+"/"+path+"/"+pol, func(t *testing.T) {
					err := ValidatePolicy([]byte(pol), users, sshTestNodes(users).ViewSlice())
					require.Error(t, err, pol)

					ex := Explain([]byte(pol), err)

					var got [][2]int

					if named {
						message := map[string]string{"user": `"alice@" matches more than one user`}[kind]
						if message == "" {
							message = fmt.Sprintf("unknown %s %q", kind, token)
						}

						for _, p := range ex.Errors {
							if strings.HasPrefix(p.Message, message) {
								got = append(got, [2]int{p.Line, p.Column})
							}
						}

						require.Equal(t, sorted(want), sorted(got), pol)

						return
					}

					for _, f := range ex.FailedTests {
						got = append(got, [2]int{f.Line, f.Column})
					}

					require.Equal(t, sorted(want), sorted(got), "the failed tests, at their entries: %s", pol)

					// Refused before the tests: each is counted as not run.
					refused := pol[:len(pol)-2] + `,"grants":[{"ip":["*"],"dst":["*"],"src":["tag:nope"]}]}`
					if strings.Contains(strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(pol)), `"grants"`) {
						refused = pol[:len(pol)-2] + `,"nodeAttrs":[{"target":["tag:nope"]}]}`
					}

					err = ValidatePolicy([]byte(refused), users, sshTestNodes(users).ViewSlice())
					require.Error(t, err, refused)
					require.Equal(t, len(want), Explain([]byte(refused), err).TestsNotRun, refused)
				})
			}
		}
	}
}

// TestExplainPlacesDuplicateKeys: every map of the policy, found by walking
// its type, and the objects of a capability's payload, which the policy
// does not type, with awkward keys given twice. Whenever the decoder finds
// a member given twice, by its own reading of keys (a prefix in two
// spellings is one key; letters that differ only by case are two), the
// problem is at the second, which starts the second line.
func TestExplainPlacesDuplicateKeys(t *testing.T) {
	// The members of each object, %s, in a whole policy; a key's prefix and
	// the value of each member.
	documents := map[string]struct{ doc, prefix, value string }{
		"groups":                         {`{"groups":{%s}}`, "group:", `[]`},
		"hosts":                          {`{"hosts":{%s}}`, "", `"1.2.3.4"`},
		"tagOwners":                      {`{"tagOwners":{%s}}`, "tag:", `[]`},
		"grants/*/app":                   {`{"grants":[{"src":["*"],"dst":["*"],"app":{%s}}]}`, "example.com/", `[]`},
		"grants/*/app/*/*":               {`{"grants":[{"src":["*"],"dst":["*"],"app":{"example.com/cap":[{%s}]}}]}`, "", `1`},
		"autoApprovers/routes":           {`{"autoApprovers":{"routes":{%s}}}`, "", `[]`},
		"derpMap/HomeParams/RegionScore": {`{"derpMap":{"HomeParams":{"RegionScore":{%s}}}}`, "", `1`},
		"derpMap/Regions":                {`{"derpMap":{"Regions":{%s}}}`, "", `null`},
	}

	// Pairs of keys: the same twice, awkward ones among them, letters that
	// differ only by case, and one value in two spellings.
	pairs := [][2]string{
		{"a", "a"},
		{"", ""},
		{" a b ", " a b "},
		{"a/b~c", "a/b~c"},
		{"Ab", "aB"},
		{"2001:db8::/32", "2001:0db8::/32"},
		{"10.0.0.0/8", "10.0.0.0/8"},
		{"1", "01"},
		{"1", "1"},
	}

	// The maps of the policy, by the JSON names of the fields on the way,
	// and the payload objects, which no type of the policy reads.
	paths := []string{"grants/*/app/*/*"}
	seen := map[reflect.Type]bool{}

	var walk func(rt reflect.Type, path []string)

	walk = func(rt reflect.Type, path []string) {
		for rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}

		switch rt.Kind() { //nolint:exhaustive // a scalar holds no map
		case reflect.Struct:
			if seen[rt] {
				return
			}

			seen[rt] = true

			for f := range rt.Fields() {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")

				if name == "" {
					name = f.Name
				}

				if f.IsExported() && name != "-" {
					walk(f.Type, append(slices.Clone(path), name))
				}
			}
		case reflect.Slice, reflect.Array:
			walk(rt.Elem(), append(slices.Clone(path), "*"))
		case reflect.Map:
			paths = append(paths, strings.Join(path, "/"))
			walk(rt.Elem(), append(slices.Clone(path), "*"))
		}
	}
	walk(reflect.TypeFor[Policy](), nil)

	for _, path := range paths {
		d, ok := documents[path]
		if !ok {
			t.Errorf("the policy has a map at %s, which this test has no document for", path)

			continue
		}

		duplicates := 0

		for _, pair := range pairs {
			first, err := json.Marshal(d.prefix + pair[0])
			require.NoError(t, err)
			second, err := json.Marshal(d.prefix + pair[1])
			require.NoError(t, err)

			pol := fmt.Sprintf(d.doc, string(first)+":"+d.value+",\n"+string(second)+":"+d.value)

			t.Run(path+"/"+pol, func(t *testing.T) {
				_, err := ParsePolicy([]byte(pol))
				if !errors.Is(err, jsontext.ErrDuplicateName) {
					// Refused for another reason, or two keys.
					return
				}

				duplicates++

				got := Explain([]byte(pol), err).Errors
				require.Len(t, got, 1, pol)
				require.Equal(t, [2]int{2, 1}, [2]int{got[0].Line, got[0].Column}, "%s: %s", pol, got[0].Message)
			})
		}

		require.NotZero(t, duplicates, "no pair is a duplicate at %s", path)
	}
}

// placeBuilder writes a policy and knows, by construction, where the one
// fault it plants starts: the test of the report needs no second locator.
type placeBuilder struct {
	r     *rand.Rand
	sb    strings.Builder
	fault int // the byte offset of the fault, -1 until it is written
}

// gap is what may stand between two tokens: nothing, white space or a
// comment.
func (g *placeBuilder) gap() {
	g.sb.WriteString([]string{"", " ", "\n", "\n  ", " /* a, \"b\": [ */ ", " // c: {\n"}[g.r.IntN(6)])
}

// spelled is name as the decoder takes it: any case, '-' and '_' anywhere.
func (g *placeBuilder) spelled(name string) string {
	switch g.r.IntN(4) {
	case 0:
		return strings.ToUpper(name)
	case 1:
		return name[:1] + "_" + name[1:]
	case 2:
		return "-" + name[:1] + "-" + name[1:]
	}

	return name
}

// member is one member of an object; fault marks its name, or its value.
type member struct {
	name       string
	value      func(*placeBuilder)
	faultName  bool
	faultValue bool
}

func raw(s string) func(*placeBuilder) { return func(g *placeBuilder) { g.sb.WriteString(s) } }

// meta is a member the decoder never sees, holding a name twice of its own.
func (g *placeBuilder) meta() member {
	return member{name: "#note" + strconv.Itoa(g.r.IntN(3)), value: raw([]string{`"x"`, `{"a":1,"a":2}`, `[{"b":{"c":1,"c":2}}]`, `{}`}[g.r.IntN(4)])}
}

// object writes members, metadata members among them when meta is set, in
// the order given, with a trailing comma at times.
func (g *placeBuilder) object(members []member, meta bool) {
	if meta {
		for range g.r.IntN(3) {
			i := g.r.IntN(len(members) + 1)
			members = slices.Insert(members, i, g.meta())
		}
	}

	g.sb.WriteByte('{')

	for i, m := range members {
		if i > 0 {
			g.sb.WriteByte(',')
		}

		g.gap()

		if m.faultName {
			g.fault = g.sb.Len()
		}

		g.sb.WriteString(strconv.Quote(m.name))
		g.gap()
		g.sb.WriteByte(':')
		g.gap()

		if m.faultValue {
			g.fault = g.sb.Len()
		}

		m.value(g)
		g.gap()
	}

	if len(members) > 0 && g.r.IntN(3) == 0 {
		g.sb.WriteByte(',')
	}

	g.sb.WriteByte('}')
}

// list writes each of items with write.
func (g *placeBuilder) list(n int, write func(i int)) {
	g.sb.WriteByte('[')

	for i := range n {
		if i > 0 {
			g.sb.WriteByte(',')
		}

		g.gap()
		write(i)
		g.gap()
	}

	g.sb.WriteByte(']')
}

// placeFaults are the faults the builder plants, each where the report must
// place it: a name given twice (at the second), a field the decoder does not
// know (at its value), a name not defined (at its use).
var placeFaults = []string{
	"twice at the top", "twice in an ACL", "twice in groups", "twice in hosts", "twice in tagOwners",
	"twice in routes", "twice in a capability", "unknown field", "unknown tag", "unknown host", "unknown group",
}

// build writes a policy with entries ordinary entries in each list and map
// and fault, and returns it with the place of the fault.
func (g *placeBuilder) build(entries int, fault string) []byte {
	g.sb.Reset()
	g.fault = -1

	is := func(f string) bool { return fault == f }

	acl := func(i int) {
		src, dst := `"tag:a0"`, `"h0:22"`

		switch {
		case i == entries-1 && is("unknown tag"):
			src = `"tag:nope"`
		case i == entries-1 && is("unknown group"):
			src = `"group:nope"`
		case i == entries-1 && is("unknown host"):
			dst = `"nohost:22"`
		}

		members := []member{
			{name: g.spelled("action"), value: raw(`"accept"`)},
			{name: g.spelled("src"), value: func(g *placeBuilder) {
				g.list(1, func(int) {
					if src != `"tag:a0"` {
						g.fault = g.sb.Len()
					}

					g.sb.WriteString(src)
				})
			}},
			{name: g.spelled("dst"), value: func(g *placeBuilder) {
				g.list(1, func(int) {
					if dst != `"h0:22"` {
						g.fault = g.sb.Len()
					}

					g.sb.WriteString(dst)
				})
			}},
		}

		if i == entries-1 && is("twice in an ACL") {
			members = append(members, member{name: g.spelled("src"), value: raw(`["*"]`), faultName: true})
		}

		if i == entries-1 && is("unknown field") {
			members = append(members, member{name: "bogus", value: raw(`1`), faultValue: true})
		}

		g.object(members, true)
	}

	// A map of entries keys, the last given twice when fault says so.
	keyed := func(key func(i int) string, value string, twice bool, second string) func(*placeBuilder) {
		return func(g *placeBuilder) {
			var members []member
			for i := range entries {
				members = append(members, member{name: key(i), value: raw(value)})
			}

			if twice {
				members = append(members, member{name: second, value: raw(value), faultName: true})
			}

			g.object(members, true)
		}
	}

	top := []member{
		{name: g.spelled("tagOwners"), value: keyed(func(i int) string { return "tag:" + string(rune('a'+i%26)) + strconv.Itoa(i/26) }, `[]`, is("twice in tagOwners"), "tag:a0")},
		{name: g.spelled("groups"), value: keyed(func(i int) string { return "group:g" + strconv.Itoa(i) }, `["alice@"]`, is("twice in groups"), "group:g0")},
		{name: g.spelled("hosts"), value: keyed(func(i int) string { return "h" + strconv.Itoa(i) }, `"10.0.0.1"`, is("twice in hosts"), "h0")},
		{name: g.spelled("acls"), value: func(g *placeBuilder) {
			g.list(entries, acl)
		}},
		{name: g.spelled("autoApprovers"), value: func(g *placeBuilder) {
			g.object([]member{{name: g.spelled("routes"), value: keyed(func(i int) string {
				return fmt.Sprintf("2001:db8:%x::/48", i)
			}, `["tag:a0"]`, is("twice in routes"), "2001:0db8:0::/48")}}, true)
		}},
		{name: g.spelled("grants"), value: func(g *placeBuilder) {
			g.list(1, func(int) {
				// The payload is no type of the policy, and the stripping
				// leaves it as written: no metadata members in it.
				g.object([]member{
					{name: "src", value: raw(`["*"]`)},
					{name: "dst", value: raw(`["*"]`)},
					{name: "app", value: func(g *placeBuilder) {
						g.object([]member{{name: "example.com/cap", value: func(g *placeBuilder) {
							g.list(1, func(int) {
								var members []member
								for i := range entries {
									members = append(members, member{name: "k" + strconv.Itoa(i), value: raw(`"tag:nope"`)})
								}

								if is("twice in a capability") {
									members = append(members, member{name: "k0", value: raw(`1`), faultName: true})
								}

								g.object(members, false)
							})
						}}}, false)
					}},
				}, true)
			})
		}},
	}

	g.r.Shuffle(len(top), func(i, j int) { top[i], top[j] = top[j], top[i] })

	if is("twice at the top") {
		// Again, after the first, in another spelling.
		first := g.r.IntN(len(top))
		again := top[first]
		again.name, again.value, again.faultName = g.spelled(strings.Trim(strings.ToLower(strings.NewReplacer("_", "", "-", "").Replace(again.name)), " ")), raw(`[]`), true

		if strings.Contains(strings.ToLower(again.name), "owner") || strings.Contains(strings.ToLower(again.name), "group") ||
			strings.Contains(strings.ToLower(again.name), "host") || strings.Contains(strings.ToLower(again.name), "approver") {
			again.value = raw(`{}`)
		}

		top = slices.Insert(top, first+1+g.r.IntN(len(top)-first), again)
	}

	g.object(top, true)

	return []byte(g.sb.String())
}

// TestExplainPlacesWhatTheBuilderPlanted builds policies mechanically: each
// fault the report places, at the end of lists and maps of a random length,
// among fields in random order and spelling, metadata members that hold
// names twice of their own, comments and trailing commas. The report must
// place the one problem where the builder put it.
func TestExplainPlacesWhatTheBuilderPlanted(t *testing.T) {
	for seed := range uint64(300) {
		g := &placeBuilder{r: rand.New(rand.NewPCG(seed, 0))} //nolint:gosec // reproducible test input

		for _, fault := range placeFaults {
			b := g.build(1+g.r.IntN(6), fault)
			require.GreaterOrEqual(t, g.fault, 0, "%s: no fault written", fault)

			_, err := ParsePolicy(b)
			require.Error(t, err, "%s: seed %d\n%s", fault, seed, b)

			line, col := lineColumn(b, g.fault)
			got := Explain(b, err).Errors

			require.Len(t, got, 1, "%s: seed %d\n%s\n%v", fault, seed, b, got)
			require.Equal(t, [2]int{line, col}, [2]int{got[0].Line, got[0].Column}, "%s (%s): seed %d\n%s", fault, got[0].Message, seed, b)
		}
	}
}

// TestExplainGrowsWithTheText: parsing and explaining a policy with one
// fault after n entries costs no more than in proportion to n, counted in
// allocations, which a loaded machine does not change.
func TestExplainGrowsWithTheText(t *testing.T) {
	for _, fault := range placeFaults {
		cost := func(n int) float64 {
			b := (&placeBuilder{r: rand.New(rand.NewPCG(1, 0))}).build(n, fault) //nolint:gosec // reproducible test input

			return testing.AllocsPerRun(5, func() {
				_, err := ParsePolicy(b)
				_ = Explain(b, err)
			})
		}

		small, large := cost(32), cost(256)
		require.Less(t, large/small, 8.0*1.5, "%s: %v allocations for 32 entries, %v for 256", fault, small, large)
	}
}

// TestExplainPlacesTheReviewersCases: the texts the outside reviews found
// placed wrong, each with « where the one problem is.
func TestExplainPlacesTheReviewersCases(t *testing.T) {
	for _, text := range []string{
		"{\n\"hosts\": {\n\"#editor\": \"192.0.2.1\",\n\"#editor\": \"192.0.2.2\",\n\"lab\": \"192.0.2.1\",\n«\"lab\": \"192.0.2.2\"\n}\n}",
		"{\n\"hosts\": {\"#editor\": \"192.0.2.1\", \"#editor\": \"192.0.2.2\"},\n\"acls\": [],\n«\"A_CLS\": []\n}",
		"{\n\"hosts\": {\n\"lab\": \"192.0.2.1\",\n«\"lab\": \"192.0.2.2\"\n}\n}",
		"{\"grants\":[{\"src\":[\"*\"],\"dst\":[\"*\"],\"app\":{\"example.com/cap\":[{\"#editor\":1,\n«\"#editor\":2}]}}]}",
		"{\"acls\":[{\"#comment\":\"business hours\",\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}],\n\"groups\":{},\n«\"acls\":[]}",
		"{\"acls\":[{\"action\":\"accept\",\"src\":[\"*\"],\"dst\":[\"*:*\"]}],\n\"groups\":{},\n«\"acls\":[]}",
		"{\"groups\":{\"#note\":\"hello\"},\n«\"groups\":{}}",
		"{\"groups\":{\"#note\":{\"x\":1,\"x\":2}},\n\"acls\":[],\n«\"A_CLS\":[]}",
		"{\"groups\":{\"#note\":{}},\n\"acls\":[],\n«\"A_CLS\":[]}",
		"{\"groups\":{\"#a\":[],\"#a\":[]},\n\"acls\":[],\n«\"A_CLS\":[]}",
		"{\"hosts\":{\"#memo\":\"1.2.3.4\",\n\"#memo\":\"1.2.3.4\",\n\"alpha\":\"1.2.3.4\",\n«\"alpha\":\"1.2.3.5\"}}",
		"{\"hosts\":{\"alpha\":\"1.2.3.4\",\n\"beta\":\"1.2.3.4\",\n«\"alpha\":\"1.2.3.5\"}}",
		"{\"#memo\":1,\n\"#memo\":2,\n\"acls\":[],\n«\"A_CLS\":[]}",
		"{\"groups\":{\"group:one\":[]},\n\"acls\":[],\n«\"A_CLS\":[{\"action\":\"accept\",\"action\":\"accept\"}]}",
		"{\"grants\":[{\"src\":[\"*\"],\"dst\":[\"*\"],\"app\":{\"example.com/cap\":[{\"\":1,\n«\"\":2}]}}]}",
		"{\"autoApprovers\":{\"routes\":{\"2001:db8::/32\":[],\n«\"2001:0db8::/32\":[]}}}",
		"{\"acls\":[{\"action\":\"accept\",\"src\":[\n«\" tag:nope \"],\"dst\":[\"*:*\"]}]}",
		"{\"sshTests\":[{\"src\":\"alice@\",\n«\"S_RC\":\"bob@\"}]}",
		"{\"#note\":\"abc\",\"S-SH_TESTS\":[{\"src\":\"a@\",\n«\"S_\\u0052C\":\"bob@\"}]}",
		"{\"acls\":[],\n\"sshTests\":[{\"src\":\"a@\",\n«\"S_RC\":\"bob@\"}]}",
		"{\"sshTests\":[{\"#note\":\"abc\",\"src\":\"a@\",\n«\"S_RC\":\"bob@\"}]}",
		"{\"sshTests\":[{\"src\":\"a@\",\"S_RC\":\"a@\",\n«\"src\":\"a@\"}]}",
	} {
		i := strings.Index(text, "«")
		b := []byte(text[:i] + text[i+len("«"):])
		line, col := lineColumn(b, i)

		_, err := ParsePolicy(b)
		require.Error(t, err, text)

		got := Explain(b, err).Errors
		require.Len(t, got, 1, text)
		require.Equal(t, [2]int{line, col}, [2]int{got[0].Line, got[0].Column}, "%s: %s", got[0].Message, text)
	}
}

// TestExplainPlacesTwiceInEveryObject: every object the policy's type can
// hold, at any depth, found by walking the type, with one of its fields
// given again in another spelling the decoder takes, and again after a
// metadata member that holds a name twice of its own. Some of these objects
// are decoded by a decode of their own (a test entry, an SSH test); the
// place is the second name in the whole text. A type whose text is not an
// object is named, with why, so that none is forgotten.
func TestExplainPlacesTwiceInEveryObject(t *testing.T) {
	// The members of each object, %s, in a whole policy; a field of it and
	// a value for that field.
	documents := map[string]struct{ doc, members, field, value string }{
		"":                          {`{%s}`, `"groups":{}`, "acls", `[]`},
		"acls/*":                    {`{"acls":[{%s}]}`, `"action":"accept","src":["*"],"dst":["*:*"]`, "proto", `"tcp"`},
		"grants/*":                  {`{"grants":[{%s}]}`, `"src":["*"],"dst":["*"],"ip":["*"]`, "via", `[]`},
		"nodeAttrs/*":               {`{"nodeAttrs":[{%s}]}`, `"target":["*"]`, "attr", `[]`},
		"autoApprovers":             {`{"autoApprovers":{%s}}`, `"routes":{}`, "exitNode", `[]`},
		"ssh/*":                     {`{"ssh":[{%s}]}`, `"action":"accept","src":["autogroup:member"],"dst":["autogroup:self"],"users":["root"]`, "acceptEnv", `[]`},
		"tests/*":                   {`{"tests":[{%s}]}`, `"src":"alice@","accept":["alice@:22"]`, "deny", `[]`},
		"sshTests/*":                {`{"sshTests":[{%s}]}`, `"src":"alice@","dst":["alice@"],"accept":["root"]`, "deny", `[]`},
		"derpMap":                   {`{"derpMap":{%s}}`, `"Regions":{}`, "OmitDefaultRegions", `true`},
		"derpMap/HomeParams":        {`{"derpMap":{"HomeParams":{%s}}}`, ``, "RegionScore", `{}`},
		"derpMap/Regions/*":         {`{"derpMap":{"Regions":{"900":{%s}}}}`, `"RegionID":900`, "RegionCode", `"x"`},
		"derpMap/Regions/*/Nodes/*": {`{"derpMap":{"Regions":{"900":{"RegionID":900,"Nodes":[{%s}]}}}}`, `"Name":"a"`, "HostName", `"a.example.com"`},
	}

	// Structs whose text is not an object: a string or a number, which
	// their own methods read.
	notObjects := map[reflect.Type]string{
		reflect.TypeFor[Prefix]():         "a prefix or an address, a string",
		reflect.TypeFor[AliasWithPorts](): "an alias and its ports, a string",
		reflect.TypeFor[ProtocolPort]():   "a protocol and its ports, a string",
		reflect.TypeFor[SSHCheckPeriod](): "a duration, a string",
		reflect.TypeFor[netip.Prefix]():   "a prefix, a string",
	}

	spellings := func(name string) []string {
		return []string{
			strings.ToUpper(name), name[:1] + "_" + name[1:], name[:1] + "-" + name[1:],
			"_" + strings.ToUpper(name[:1]) + name[1:] + "-",
		}
	}

	var paths []string

	seen := map[reflect.Type]bool{}

	var walk func(rt reflect.Type, path []string)

	walk = func(rt reflect.Type, path []string) {
		for rt.Kind() == reflect.Pointer {
			rt = rt.Elem()
		}

		switch rt.Kind() { //nolint:exhaustive // a scalar holds no object
		case reflect.Struct:
			if _, ok := notObjects[rt]; ok || seen[rt] {
				return
			}

			seen[rt] = true

			paths = append(paths, strings.Join(path, "/"))

			for f := range rt.Fields() {
				name, _, _ := strings.Cut(f.Tag.Get("json"), ",")
				if name == "" {
					name = f.Name
				}

				if f.IsExported() && name != "-" {
					walk(f.Type, append(slices.Clone(path), name))
				}
			}
		case reflect.Slice, reflect.Array, reflect.Map:
			walk(rt.Elem(), append(slices.Clone(path), "*"))
		}
	}
	walk(reflect.TypeFor[Policy](), nil)

	for _, path := range paths {
		d, ok := documents[path]
		if !ok {
			t.Errorf("the policy holds an object at %q, which this test has no document for", path)

			continue
		}

		for _, spelled := range spellings(d.field) {
			for _, meta := range []string{"", `"#note":{"a":1,"a":2},` + "\n"} {
				members := meta + d.members
				if d.members != "" {
					members += ","
				}

				members += fmt.Sprintf("%q:%s,\n«%q:%s", d.field, d.value, spelled, d.value)
				text := fmt.Sprintf(d.doc, members)
				i := strings.Index(text, "«")
				b := []byte(text[:i] + text[i+len("«"):])

				t.Run(path+"/"+string(b), func(t *testing.T) {
					_, err := ParsePolicy(b)
					require.ErrorIs(t, err, jsontext.ErrDuplicateName, "%s", b)

					line, col := lineColumn(b, i)
					got := Explain(b, err).Errors
					require.Len(t, got, 1, "%s", b)
					require.Equal(t, [2]int{line, col}, [2]int{got[0].Line, got[0].Column}, "%s: %s", got[0].Message, b)
				})
			}
		}
	}
}
