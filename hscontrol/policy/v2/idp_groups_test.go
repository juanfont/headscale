package v2

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// withGroups returns u as a member of the qualified identity-provider groups.
func withGroups(u types.User, groups ...string) types.User {
	u.Memberships = nil
	for _, g := range groups {
		u.Memberships = append(u.Memberships, types.UserGroup{
			UserID: u.ID,
			Source: types.GroupSourceOIDC,
			Group:  types.Group{Name: g},
		})
	}

	return u
}

func idpTestUsers() (types.User, types.User) {
	alice := types.User{ID: 1, Name: "alice", Email: "alice@example.com"}
	bob := types.User{ID: 2, Name: "bob", Email: "bob@example.com"}

	return alice, bob
}

func idpTestNodes(alice, bob types.User) types.Nodes {
	tagged := node("tagged", "100.64.0.3", "fd7a:115c:a1e0::3", alice)
	tagged.ID = 3
	tagged.Tags = []string{"tag:server"}
	tagged.User = nil
	tagged.UserID = nil

	a := node("alice", "100.64.0.1", "fd7a:115c:a1e0::1", alice)
	a.ID = 1
	b := node("bob", "100.64.0.2", "fd7a:115c:a1e0::2", bob)
	b.ID = 2

	return types.Nodes{a, b, tagged}
}

// filterSrcs returns the SrcIPs of every compiled filter rule.
func filterSrcs(t *testing.T, pm *PolicyManager) []string {
	t.Helper()

	filter, _ := pm.Filter()

	var srcs []string
	for _, rule := range filter {
		srcs = append(srcs, rule.SrcIPs...)
	}

	return srcs
}

func newIdPTestPM(t *testing.T, pol string, users types.Users, nodes types.Nodes) *PolicyManager {
	t.Helper()

	pm, err := NewPolicyManager([]byte(pol), users, nodes.ViewSlice())
	require.NoError(t, err)

	return pm
}

func idpPolicy(src string) string {
	return `{
	"tagOwners": {"tag:server": ["alice@example.com"]},
	"acls": [{"action": "accept", "src": ["` + src + `"], "dst": ["tag:server:22"]}]
}`
}

func TestIdPGroupResolvesMembersNodes(t *testing.T) {
	alice, bob := idpTestUsers()
	users := types.Users{withGroups(alice, "eng@example.com"), withGroups(bob, "ops@example.com")}
	nodes := idpTestNodes(alice, bob)

	pm := newIdPTestPM(t, idpPolicy("group:eng@example.com"), users, nodes)
	assert.Equal(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, filterSrcs(t, pm),
		"only alice's untagged node is in group:eng@example.com")

	// References are matched case-insensitively, as in Tailscale.
	pm = newIdPTestPM(t, idpPolicy("group:ENG@Example.com"), users, nodes)
	assert.Equal(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, filterSrcs(t, pm))
}

// TestIdPGroupFailsClosed checks that an identity-provider group nobody is a
// member of is valid policy but grants nothing.
func TestIdPGroupFailsClosed(t *testing.T) {
	alice, bob := idpTestUsers()
	nodes := idpTestNodes(alice, bob)

	pm := newIdPTestPM(t, idpPolicy("group:nobody@example.com"), types.Users{alice, bob}, nodes)
	assert.Empty(t, filterSrcs(t, pm))

	// A member of a same-named group in another domain is not a member.
	users := types.Users{withGroups(alice, "eng@other.example"), bob}
	pm = newIdPTestPM(t, idpPolicy("group:eng@example.com"), users, nodes)
	assert.Empty(t, filterSrcs(t, pm))
}

// TestIdPGroupCannotJoinPolicyGroups checks that identity-provider membership
// never adds members to a group the policy defines, whatever its name. This
// is what stops anyone who can name a group in the identity provider from
// joining policy groups used for tag ownership or route approval.
func TestIdPGroupCannotJoinPolicyGroups(t *testing.T) {
	alice, bob := idpTestUsers()
	nodes := idpTestNodes(alice, bob)
	users := types.Users{alice, withGroups(bob, "eng@example.com", "admins@example.com")}

	tests := []struct {
		name string
		pol  string
	}{
		{
			name: "plain policy group of the same name",
			pol: `{
				"groups": {"group:eng": ["alice@example.com"]},
				"tagOwners": {"tag:server": ["alice@example.com"]},
				"acls": [{"action": "accept", "src": ["group:eng"], "dst": ["tag:server:22"]}]
			}`,
		},
		{
			name: "policy group whose name contains @",
			pol: `{
				"groups": {"group:admins@example.com": ["alice@example.com"]},
				"tagOwners": {"tag:server": ["alice@example.com"]},
				"acls": [{"action": "accept", "src": ["group:admins@example.com"], "dst": ["tag:server:22"]}]
			}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pm := newIdPTestPM(t, tt.pol, users, nodes)
			assert.Equal(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, filterSrcs(t, pm),
				"only alice, the policy-defined member, may match")
		})
	}
}

func TestIdPGroupValidation(t *testing.T) {
	tests := []struct {
		name    string
		pol     string
		wantErr error
	}{
		{
			name: "idp group in acl, ssh, tagOwners and autoApprovers needs no definition",
			pol: `{
				"tagOwners": {"tag:server": ["group:eng@example.com"]},
				"autoApprovers": {"routes": {"10.0.0.0/8": ["group:eng@example.com"]}, "exitNode": ["group:eng@example.com"]},
				"acls": [{"action": "accept", "src": ["group:eng@example.com"], "dst": ["group:ops@example.com:*"]}],
				"ssh": [{"action": "accept", "src": ["group:eng@example.com"], "dst": ["tag:server"], "users": ["root"]}]
			}`,
		},
		{
			name:    "undefined plain group is still an error",
			pol:     `{"acls": [{"action": "accept", "src": ["group:typo"], "dst": ["*:*"]}]}`,
			wantErr: ErrGroupNotDefined,
		},
		{
			name:    "idp group without a name",
			pol:     `{"acls": [{"action": "accept", "src": ["group:@example.com"], "dst": ["*:*"]}]}`,
			wantErr: ErrInvalidIdPGroup,
		},
		{
			name:    "idp group without a domain",
			pol:     `{"acls": [{"action": "accept", "src": ["group:eng@"], "dst": ["*:*"]}]}`,
			wantErr: ErrInvalidIdPGroup,
		},
		{
			name:    "idp group with two @",
			pol:     `{"acls": [{"action": "accept", "src": ["group:eng@a@b"], "dst": ["*:*"]}]}`,
			wantErr: ErrInvalidIdPGroup,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewPolicyManager([]byte(tt.pol), nil, types.Nodes{}.ViewSlice())
			if tt.wantErr == nil {
				require.NoError(t, err)

				return
			}

			require.ErrorIs(t, err, tt.wantErr)
		})
	}
}

// TestIdPGroupMembershipChangeRecompiles checks the path an OIDC login takes:
// SetUsers with changed memberships must recompile the filter, both when a
// group is gained and when it is lost.
func TestIdPGroupMembershipChangeRecompiles(t *testing.T) {
	alice, bob := idpTestUsers()
	nodes := idpTestNodes(alice, bob)

	pm := newIdPTestPM(t, idpPolicy("group:eng@example.com"), types.Users{alice, bob}, nodes)
	require.Empty(t, filterSrcs(t, pm))

	changed, _, err := pm.SetUsers(types.Users{withGroups(alice, "eng@example.com"), bob})
	require.NoError(t, err)
	assert.True(t, changed, "gaining a group must change the policy")
	assert.Equal(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, filterSrcs(t, pm))

	changed, _, err = pm.SetUsers(types.Users{withGroups(alice, "eng@example.com"), bob})
	require.NoError(t, err)
	assert.False(t, changed, "unchanged memberships must not recompile")

	changed, _, err = pm.SetUsers(types.Users{alice, bob})
	require.NoError(t, err)
	assert.True(t, changed, "losing a group must change the policy")
	assert.Empty(t, filterSrcs(t, pm), "revoked membership must no longer grant access")
}

func TestIdPGroupTagOwnership(t *testing.T) {
	alice, bob := idpTestUsers()
	nodes := idpTestNodes(alice, bob)
	pol := `{
		"tagOwners": {"tag:server": ["group:eng@example.com"]},
		"acls": [{"action": "accept", "src": ["*"], "dst": ["*:*"]}]
	}`

	aliceEng := withGroups(alice, "eng@example.com")
	pm := newIdPTestPM(t, pol, types.Users{aliceEng, bob}, nodes)

	assert.True(t, pm.UserCanHaveTag(aliceEng.View(), "tag:server"))
	assert.False(t, pm.UserCanHaveTag(bob.View(), "tag:server"))

	// Ownership follows the policy manager's current users, not a stale copy
	// of the user: a view that still lists the group does not keep it.
	_, _, err := pm.SetUsers(types.Users{alice, bob})
	require.NoError(t, err)
	assert.False(t, pm.UserCanHaveTag(aliceEng.View(), "tag:server"))
}

// TestIdPGroupParsesAsGroup guards the parser order: group:<name>@<domain>
// contains '@' but must parse as a group, not a username, wherever a group
// may appear.
func TestIdPGroupParsesAsGroup(t *testing.T) {
	const ref = "group:eng@example.com"

	alias, err := parseAlias(ref)
	require.NoError(t, err)
	assert.IsType(t, new(Group), alias)

	owner, err := parseOwner(ref)
	require.NoError(t, err)
	assert.IsType(t, new(Group), owner)

	approver, err := parseAutoApprover(ref)
	require.NoError(t, err)
	assert.IsType(t, new(Group), approver)

	user, err := parseAlias("alice@example.com")
	require.NoError(t, err)
	assert.IsType(t, new(Username), user)
}

// TestIdPGroupReferenceFoldsOnlyASCII checks that a policy reference is case
// folded exactly like the names synced from the identity provider, so a
// Unicode lookalike cannot resolve to another group.
func TestIdPGroupReferenceFoldsOnlyASCII(t *testing.T) {
	alice, bob := idpTestUsers()
	nodes := idpTestNodes(alice, bob)

	// Bob's identity provider group uses the Kelvin sign, which full Unicode
	// case folding would turn into an ASCII 'k'.
	users := types.Users{withGroups(alice, "kube-admins@example.com"), withGroups(bob, "Kube-admins@example.com")}

	pm := newIdPTestPM(t, idpPolicy("group:Kube-Admins@example.com"), users, nodes)
	assert.Equal(t, []string{"100.64.0.1", "fd7a:115c:a1e0::1"}, filterSrcs(t, pm),
		"only alice's group matches the ASCII reference")
}
