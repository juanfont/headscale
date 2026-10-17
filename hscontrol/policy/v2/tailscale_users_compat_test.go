// Compatibility tests for user tokens that name nobody: well-formed
// addresses with no user, a short name and a bare "@", at every policy
// site. Captures live in testdata/users_results/.
//
// SaaS logins are unique and fixed, so SaaS cannot show two users answering
// one token, or a user without an e-mail. Each capture is therefore also
// replayed under overlays: headscale-only users, each with one node, added
// on top of it. SaaS's own nodes must be unchanged by the overlay, and
// overlay nodes must get nothing. Every overlay loads at boot (one
// constructor call) and at runtime (users and nodes added to a running
// manager); each node check runs on every manager that loaded.
//
// Source format: github.com/juanfont/headscale/hscontrol/types/testcapture

package v2

import (
	"database/sql"
	"fmt"
	"maps"
	"net/http"
	"net/netip"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/testcapture"
	"github.com/stretchr/testify/require"
	"tailscale.com/net/tsaddr"
	"tailscale.com/tailcfg"
)

// userTokenOverlay is a set of headscale-only users replayed on top of a
// capture. Each user in add gets one node; replace swaps a capture user's
// row for the one another identity provider would store.
type userTokenOverlay struct {
	name    string
	add     types.Users
	replace map[string]types.User
}

func oidcUser(id uint, issuer, name, email string) types.User {
	return types.User{
		ID:                 id,
		Name:               name,
		Email:              email,
		Provider:           "oidc",
		ProviderIdentifier: sql.NullString{String: issuer + "/" + name, Valid: true},
	}
}

// userTokenOverlays come from the shapes headscale's user table allows and
// SaaS cannot have. The ambiguous ones match nobody by the #3160 rule
// (never pick one of two equal matches), not by SaaS evidence.
var userTokenOverlays = []userTokenOverlay{
	{name: ""},
	{
		name: "name-is-owner-email",
		add:  types.Users{oidcUser(101, "https://idp-a.example.net", "odin@example.com", "other@example.net")},
	},
	{
		name: "name-is-unknown-email",
		add:  types.Users{oidcUser(101, "https://idp-a.example.net", "ghost@example.com", "other@example.net")},
	},
	{
		// An unverified e-mail is not stored.
		name: "name-is-unknown-email-unverified",
		add:  types.Users{oidcUser(101, "https://idp-a.example.net", "ghost@example.com", "")},
	},
	{
		// Okta and Entra on default config store the address as the name only.
		name: "okta-name-only",
		replace: map[string]types.User{
			"odin": oidcUser(1, "https://idp-a.example.net", "odin@example.com", ""),
		},
	},
	{
		name: "duplicate-unknown-email",
		add: types.Users{
			oidcUser(101, "https://idp-a.example.net", "ghost", "ghost@example.com"),
			oidcUser(102, "https://idp-b.example.net", "ghost", "ghost@example.com"),
		},
	},
	{name: "no-email-one", add: types.Users{{ID: 101, Name: "svc-a"}}},
	{name: "no-email-two", add: types.Users{{ID: 101, Name: "svc-a"}, {ID: 102, Name: "svc-b"}}},
}

// userTokenSkipReasons lists checks where headscale differs from SaaS,
// keyed <test_id>[/<overlay>][/<node>]/<check>. HEADSCALE_SHORT_USERNAME
// and AMBIGUOUS_USER_WRITE are deliberate; USERNAME_ANSWERS_EMAIL_TOKEN is
// an open decision.
var userTokenSkipReasons = map[string]string{
	"users-short-name/okta-name-only/server/filter": shortUsernameRow,

	"users-bare-at-test-dst/breakdown":                         testUnknownAlias,
	"users-bare-at-test-dst/duplicate-unknown-email/breakdown": testUnknownAlias,
	"users-bare-at-test-dst/name-is-owner-email/breakdown":     testUnknownAlias,
	"users-bare-at-test-dst/name-is-unknown-email/breakdown":   testUnknownAlias,
	"users-bare-at-test-dst/no-email-two/breakdown":            testUnknownAlias,
	"users-bare-at-test-src/breakdown":                         testUnknownAlias,
	"users-bare-at-test-src/duplicate-unknown-email/breakdown": testUnknownAlias,
	"users-bare-at-test-src/name-is-owner-email/breakdown":     testUnknownAlias,
	"users-bare-at-test-src/name-is-unknown-email/breakdown":   testUnknownAlias,
	"users-bare-at-test-src/no-email-two/breakdown":            testUnknownAlias,

	// The evaluation error repeats the test's source unquoted, here a user's name.
	"users-bare-at-test-dst/name-is-owner-email/user-list": testUnknownAlias,

	"users-unknown-direct/duplicate-unknown-email/verdict": ambiguousWrite,
	"users-unknown-member/duplicate-unknown-email/verdict": ambiguousWrite,

	"users-unknown-direct/duplicate-unknown-email/user-list": ambiguityListsUsers,
	"users-unknown-member/duplicate-unknown-email/user-list": ambiguityListsUsers,

	"users-unknown-direct/name-is-unknown-email-unverified/overlay-1/filter":         usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email-unverified/overlay-1/route-approver": usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email-unverified/overlay-1/tag-owner":      usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email-unverified/prod/filter":              usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email/overlay-1/filter":                    usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email/overlay-1/route-approver":            usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email/overlay-1/tag-owner":                 usernameAnswersEmail,
	"users-unknown-direct/name-is-unknown-email/prod/filter":                         usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email-unverified/overlay-1/capmap":         usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email-unverified/overlay-1/filter":         usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email-unverified/prod/ssh":                 usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email-unverified/server/filter":            usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email-unverified/server/ssh":               usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email/overlay-1/capmap":                    usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email/overlay-1/filter":                    usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email/prod/ssh":                            usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email/server/filter":                       usernameAnswersEmail,
	"users-unknown-member/name-is-unknown-email/server/ssh":                          usernameAnswersEmail,

	"users-bare-at-dst/name-is-unknown-email-unverified/overlay-1/filter":         bareAtNoEmail,
	"users-bare-at-dst/no-email-one/overlay-1/filter":                             bareAtNoEmail,
	"users-bare-at-dst/no-email-two/user-list":                                    bareAtNoEmail,
	"users-bare-at-dst/no-email-two/verdict":                                      bareAtNoEmail,
	"users-bare-at-dst/okta-name-only/user-tid/filter":                            bareAtNoEmail,
	"users-bare-at-group/name-is-unknown-email-unverified/server/filter":          bareAtNoEmail,
	"users-bare-at-group/no-email-one/server/filter":                              bareAtNoEmail,
	"users-bare-at-group/no-email-two/user-list":                                  bareAtNoEmail,
	"users-bare-at-group/no-email-two/verdict":                                    bareAtNoEmail,
	"users-bare-at-group/okta-name-only/server/filter":                            bareAtNoEmail,
	"users-bare-at-nodeattrs/name-is-unknown-email-unverified/overlay-1/capmap":   bareAtNoEmail,
	"users-bare-at-nodeattrs/no-email-one/overlay-1/capmap":                       bareAtNoEmail,
	"users-bare-at-nodeattrs/no-email-two/user-list":                              bareAtNoEmail,
	"users-bare-at-nodeattrs/no-email-two/verdict":                                bareAtNoEmail,
	"users-bare-at-nodeattrs/okta-name-only/user-tid/capmap":                      bareAtNoEmail,
	"users-bare-at-src/name-is-unknown-email-unverified/server/filter":            bareAtNoEmail,
	"users-bare-at-src/no-email-one/server/filter":                                bareAtNoEmail,
	"users-bare-at-src/no-email-two/user-list":                                    bareAtNoEmail,
	"users-bare-at-src/no-email-two/verdict":                                      bareAtNoEmail,
	"users-bare-at-src/okta-name-only/server/filter":                              bareAtNoEmail,
	"users-bare-at-tagowner/name-is-unknown-email-unverified/overlay-1/tag-owner": bareAtNoEmail,
	"users-bare-at-tagowner/no-email-one/overlay-1/tag-owner":                     bareAtNoEmail,
	"users-bare-at-tagowner/no-email-two/user-list":                               bareAtNoEmail,
	"users-bare-at-tagowner/no-email-two/verdict":                                 bareAtNoEmail,
	"users-bare-at-test-src/no-email-two/user-list":                               bareAtNoEmail,
	"users-bare-at-test-src/okta-name-only/verdict":                               bareAtNoEmail,

	"users-short-name/server/filter": shortUsername,
}

const (
	shortUsername        = "HEADSCALE_SHORT_USERNAME: headscale lets odin@ name the user called odin; SaaS matches it to no one"
	shortUsernameRow     = "HEADSCALE_SHORT_USERNAME: a row storing the address as its name leaves odin@ nothing to match"
	ambiguousWrite       = "AMBIGUOUS_USER_WRITE: headscale refuses to store a policy whose user token matches two users (#3160)"
	ambiguityListsUsers  = "AMBIGUITY_LISTS_USERS: headscale's refusal of a token matching two users lists both users by ID and name"
	usernameAnswersEmail = "USERNAME_ANSWERS_EMAIL_TOKEN: a username shaped like an unclaimed address takes that address's rights"
	bareAtNoEmail        = `BARE_AT_NO_EMAIL: "@" matches the users without an e-mail; SaaS matches it to no one`
)

// TestUserTokenCompat replays every users capture as captured and under
// every overlay.
func TestUserTokenCompat(t *testing.T) {
	t.Parallel()

	files, err := filepath.Glob(filepath.Join("testdata", "users_results", "*.hujson"))
	require.NoError(t, err, "failed to glob test files")
	require.NotEmpty(t, files, "no users captures")

	for _, file := range files {
		c, err := testcapture.Read(file)
		require.NoError(t, err, "reading %s", file)

		t.Run(c.TestID, func(t *testing.T) {
			t.Parallel()

			requireCaptureUserOwnership(t, c)

			for _, o := range userTokenOverlays {
				name := o.name
				if name == "" {
					name = "as-captured"
				}

				t.Run(name, func(t *testing.T) {
					key := c.TestID + "/"
					if o.name != "" {
						key += o.name + "/"
					}

					runUserTokenCompat(t, c, o, key)
				})
			}
		})
	}
}

// requireCaptureUserOwnership fails a capture whose user-owned nodes are not
// shown as their topology user: the runner falls back to the admin's key
// when a user's key is missing, which would hand every node to one user.
func requireCaptureUserOwnership(t *testing.T, c *testcapture.Capture) {
	t.Helper()

	logins := make(map[string]string, len(c.Topology.Users))
	for _, u := range c.Topology.Users {
		logins[u.Name] = u.Email
	}

	for name, n := range c.Topology.Nodes {
		if len(n.Tags) > 0 {
			continue
		}

		capture, ok := c.Captures[name]
		require.Truef(t, ok && capture.Netmap != nil, "%s: no netmap", name)

		self := capture.Netmap.SelfNode
		profile, ok := capture.Netmap.UserProfiles[self.User()]
		require.Truef(t, ok, "%s: no profile for its own user", name)
		require.Equalf(t, logins[n.User], profile.LoginName(), "%s: owner", name)
	}
}

// userTokenUsersAndNodes returns the capture's users and nodes with the
// overlay applied, and the overlay's own nodes.
func userTokenUsersAndNodes(
	t *testing.T,
	c *testcapture.Capture,
	o userTokenOverlay,
) (types.Users, types.Nodes, types.Nodes) {
	t.Helper()

	users := setupACLCompatUsers()
	nodes := buildGrantsNodesFromCapture(users, c)

	// Stable IDs, so a node is the same node with and without the overlay.
	slices.SortFunc(nodes, func(a, b *types.Node) int { return strings.Compare(a.GivenName, b.GivenName) })

	for i, n := range nodes {
		n.ID = types.NodeID(i + 1) //nolint:gosec
	}

	// In place, so the nodes keep their owner under its new row.
	for i := range users {
		if u, ok := o.replace[users[i].Name]; ok {
			users[i] = u
		}
	}

	users = append(users, o.add...)

	// A range no capture uses, so overlay addresses never collide.
	v4 := netip.MustParseAddr("100.127.255.0")
	v6 := netip.MustParseAddr("fd7a:115c:a1e0:ffff::")

	overlay := make(types.Nodes, 0, len(o.add))

	for i := range o.add {
		v4, v6 = v4.Next(), v6.Next()

		for _, n := range nodes {
			require.Falsef(t, n.IPv4 != nil && *n.IPv4 == v4 || n.IPv6 != nil && *n.IPv6 == v6,
				"overlay address of %s is used by %s", o.add[i].Name, n.GivenName)
		}

		user := &users[len(users)-len(o.add)+i]
		overlay = append(overlay, &types.Node{
			ID:             types.NodeID(1000 + i), //nolint:gosec
			Hostname:       fmt.Sprintf("overlay-%d", i+1),
			GivenName:      fmt.Sprintf("overlay-%d", i+1),
			IPv4:           new(v4),
			IPv6:           new(v6),
			User:           user,
			UserID:         &user.ID,
			Hostinfo:       &tailcfg.Hostinfo{},
			ApprovedRoutes: []netip.Prefix{},
		})
	}

	return users, append(nodes, overlay...), overlay
}

// runUserTokenCompat runs one capture under one overlay.
func runUserTokenCompat(t *testing.T, c *testcapture.Capture, o userTokenOverlay, key string) {
	t.Helper()

	users, nodes, overlay := userTokenUsersAndNodes(t, c, o)
	saasUsers, saasNodes, _ := userTokenUsersAndNodes(t, c, userTokenOverlay{})
	policyJSON := []byte(c.Input.FullPolicy)

	pol, err := unmarshalPolicy(policyJSON)
	require.NoError(t, err)

	// Boot loads the stored policy with every user and node present.
	boot, bootErr := NewPolicyManager(policyJSON, users, nodes.ViewSlice())

	// At runtime the overlay's users log in and their nodes join a server
	// already running the policy.
	runtime, runtimeErr := NewPolicyManager(policyJSON, saasUsers, saasNodes.ViewSlice())
	if runtimeErr == nil {
		_, _, runtimeErr = runtime.SetUsers(users)
	}

	if runtimeErr == nil {
		_, runtimeErr = runtime.SetNodes(nodes.ViewSlice())
	}

	managers := []struct {
		name string
		pm   *PolicyManager
		err  error
	}{{"boot", boot, bootErr}, {"runtime", runtime, runtimeErr}}

	loaded := 0

	for _, m := range managers {
		compatCheck(t, userTokenSkipReasons, key+m.name, func() string {
			if m.err != nil {
				return m.err.Error()
			}

			return ""
		})

		if m.err == nil {
			loaded++
		}
	}

	// Under an overlay, SaaS nodes must keep what the capture alone gives.
	var unchanged *PolicyManager
	if o.name != "" {
		unchanged, err = NewPolicyManager(policyJSON, saasUsers, saasNodes.ViewSlice())
		require.NoError(t, err)
	}

	for _, node := range nodes {
		nodeKey := key + node.GivenName + "/"
		isOverlay := slices.Contains(overlay, node)

		checks := []string{"filter", "capmap", "ssh"}
		if isOverlay {
			checks = append(checks, "tag-owner", "route-approver")
		}

		// A refused policy leaves no node state to compare.
		if loaded == 0 || c.Input.APIResponseCode != http.StatusOK {
			for _, check := range checks {
				compatChecksNotRun(t, userTokenSkipReasons, nodeKey+check)
			}

			continue
		}

		t.Run(node.GivenName, func(t *testing.T) {
			capture, ok := c.Captures[node.GivenName]
			require.Truef(t, ok || isOverlay, "no capture for %s", node.GivenName)

			for _, check := range checks {
				compatCheck(t, userTokenSkipReasons, nodeKey+check, func() string {
					var diffs []string

					for _, m := range managers {
						if m.err != nil {
							continue
						}

						var diff string

						switch {
						case isOverlay:
							diff = userTokenOverlayMismatch(check, pol, m.pm, node)
						case unchanged != nil:
							diff = userTokenUnchangedMismatch(check, unchanged, m.pm, node)
						default:
							diff = userTokenCaptureMismatch(check, c, pol, m.pm, users, nodes, node, capture)
						}

						if diff != "" {
							diffs = append(diffs, m.name+": "+diff)
						}
					}

					return strings.Join(diffs, "\n")
				})
			}
		})
	}

	// The same bytes posted as a new policy.
	writeErr := runTesterCompatFor(t, c, userTokenSkipReasons, key, users, nodes)

	// A refusal may echo a token the policy wrote, never list a user.
	compatCheck(t, userTokenSkipReasons, key+"user-list", func() string {
		var leaked []string

		for _, err := range []error{bootErr, runtimeErr, writeErr} {
			if err == nil {
				continue
			}

			rest := quotedToken.ReplaceAllStringFunc(err.Error(), func(q string) string {
				if strings.Contains(c.Input.FullPolicy, q) {
					return ""
				}

				return q
			})

			for _, u := range o.add {
				if strings.Contains(rest, u.Name) {
					leaked = append(leaked, fmt.Sprintf("%s in %q", u.Name, err))
				}
			}
		}

		return strings.Join(leaked, "\n")
	})
}

// quotedToken matches a quoted string in an error, the form a refusal
// echoes a policy token in.
var quotedToken = regexp.MustCompile(`"[^"]*"`)

// userTokenCaptureMismatch compares one output of a SaaS node with its
// capture.
func userTokenCaptureMismatch(
	check string,
	c *testcapture.Capture,
	pol *Policy,
	pm *PolicyManager,
	users types.Users,
	nodes types.Nodes,
	node *types.Node,
	capture testcapture.Node,
) string {
	switch check {
	case "filter":
		got, err := pm.FilterForNode(node.View())
		if err != nil {
			return err.Error()
		}

		return cmp.Diff(capture.PacketFilterRules, got, append(cmpOptions(), cmpopts.EquateEmpty())...)
	case "capmap":
		tn, err := node.View().TailNode(0, noRoutes, nodeAttrsCompatConfig(c), pm.NodeCapMap(node.ID))
		if err != nil {
			return err.Error()
		}

		return cmp.Diff(
			stripUnmodelledTailnetStateCaps(capMapFromView(capture.Netmap.SelfNode.CapMap())),
			stripUnmodelledTailnetStateCaps(tn.CapMap),
			cmpopts.EquateEmpty(),
		)
	default:
		return sshRulesMismatch(pol, pm, users, nodes, node, capture)
	}
}

// userTokenUnchangedMismatch compares one output of a SaaS node under an
// overlay with the same node's output without it.
func userTokenUnchangedMismatch(check string, want, pm *PolicyManager, node *types.Node) string {
	switch check {
	case "filter":
		wantRules, err := want.FilterForNode(node.View())
		if err != nil {
			return err.Error()
		}

		got, err := pm.FilterForNode(node.View())
		if err != nil {
			return err.Error()
		}

		return cmp.Diff(wantRules, got, append(cmpOptions(), cmpopts.EquateEmpty())...)
	case "capmap":
		return cmp.Diff(want.NodeCapMap(node.ID), pm.NodeCapMap(node.ID), cmpopts.EquateEmpty())
	default:
		wantSSH, err := want.SSHPolicy("https://unused", node.View())
		if err != nil {
			return err.Error()
		}

		got, err := pm.SSHPolicy("https://unused", node.View())
		if err != nil {
			return err.Error()
		}

		return cmp.Diff(wantSSH, got, cmpopts.EquateEmpty())
	}
}

// userTokenOverlayMismatch reports what an overlay node got: it may reach
// nothing, carry no attr, accept no SSH, take no tag and approve no route
// the policy names.
func userTokenOverlayMismatch(check string, pol *Policy, pm *PolicyManager, node *types.Node) string {
	var got []string

	switch check {
	case "filter":
		rules, err := pm.FilterForNode(node.View())
		if err != nil {
			return err.Error()
		}

		for _, r := range rules {
			got = append(got, fmt.Sprint(r))
		}
	case "capmap":
		for attr := range pm.NodeCapMap(node.ID) {
			got = append(got, string(attr))
		}
	case "ssh":
		sshPol, err := pm.SSHPolicy("https://unused", node.View())
		if err != nil {
			return err.Error()
		}

		if sshPol != nil {
			for _, r := range sshPol.Rules {
				got = append(got, fmt.Sprint(*r))
			}
		}
	case "tag-owner":
		for tag := range pol.TagOwners {
			if pm.NodeCanHaveTag(node.View(), string(tag)) {
				got = append(got, string(tag))
			}
		}
	case "route-approver":
		for _, route := range append(slices.Collect(maps.Keys(pol.AutoApprovers.Routes)), tsaddr.AllIPv4()) {
			if pm.NodeCanApproveRoute(node.View(), route) {
				got = append(got, route.String())
			}
		}
	}

	if len(got) == 0 {
		return ""
	}

	slices.Sort(got)

	return fmt.Sprintf("overlay node got %s: %v", check, got)
}
