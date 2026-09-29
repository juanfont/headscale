package types

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQualifyGroupName(t *testing.T) {
	tests := []struct {
		name    string
		group   string
		domain  string
		want    string
		wantErr error
	}{
		{name: "plain", group: "engineering", domain: "example.com", want: "engineering@example.com"},
		{name: "lowercases name and domain", group: "Platform-Team", domain: "Example.COM", want: "platform-team@example.com"},
		{name: "trims whitespace", group: "  ops  ", domain: " example.com ", want: "ops@example.com"},
		{name: "keeps spaces inside", group: "All Employees", domain: "example.com", want: "all employees@example.com"},
		{name: "entra object id", group: "3AC067A2-F424-87B0-14A3-926482D83980", domain: "example.com", want: "3ac067a2-f424-87b0-14a3-926482d83980@example.com"},
		{name: "keycloak path", group: "/engineering/backend", domain: "example.com", want: "/engineering/backend@example.com"},
		{name: "only ascii is case folded", group: "\u212Aube-Admins", domain: "example.com", want: "\u212Aube-admins@example.com"},
		{name: "non-ascii letters kept", group: "Équipe", domain: "example.com", want: "Équipe@example.com"},
		{name: "empty name", group: "  ", domain: "example.com", wantErr: ErrGroupNameEmpty},
		{name: "already qualified with domain", group: "Eng@Example.com", domain: "example.com", want: "eng@example.com"},
		{name: "qualified with another domain", group: "eng@corp.example", domain: "example.com", wantErr: ErrGroupNameContainsAt},
		{name: "name with at", group: "eng@corp", domain: "example.com", wantErr: ErrGroupNameContainsAt},
		{name: "only the domain", group: "@example.com", domain: "example.com", wantErr: ErrGroupNameEmpty},
		{name: "empty domain", group: "eng", domain: "", wantErr: ErrGroupDomainMissing},
		{name: "domain with at", group: "eng", domain: "a@b", wantErr: ErrGroupDomainContainsAt},
		{name: "too long", group: strings.Repeat("a", 250), domain: "example.com", wantErr: ErrGroupNameTooLong},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := QualifyGroupName(tt.group, tt.domain)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestUserGroupNames(t *testing.T) {
	eng := Group{ID: 1, Name: "eng@example.com"}
	ops := Group{ID: 2, Name: "ops@example.com"}

	u := User{Memberships: []UserGroup{
		{GroupID: ops.ID, Source: GroupSourceOIDC, Group: ops},
		{GroupID: eng.ID, Source: GroupSourceOIDC, Group: eng},
		// The same group asserted by a second source is reported once.
		{GroupID: eng.ID, Source: "other", Group: eng},
	}}

	assert.Equal(t, []string{"eng@example.com", "ops@example.com"}, u.GroupNames())
	assert.Equal(t, u.GroupNames(), u.View().GroupNames())
	assert.True(t, u.InGroup("eng@example.com"))
	assert.False(t, u.InGroup("hr@example.com"))
	assert.False(t, (&User{}).InGroup("eng@example.com"))
	assert.Nil(t, (&User{}).GroupNames())
	assert.Nil(t, UserView{}.GroupNames())
}

func TestUserPolicyEqualGroups(t *testing.T) {
	base := User{ID: 1, Name: "alice"}
	withEng := base
	withEng.Memberships = []UserGroup{{Group: Group{Name: "eng@example.com"}}}

	assert.True(t, base.PolicyEqual(&base))
	assert.False(t, base.PolicyEqual(&withEng), "gaining a group must change policy resolution")
	assert.False(t, withEng.PolicyEqual(&base), "losing a group must change policy resolution")

	// Membership order and source do not affect policy resolution.
	a := User{ID: 1, Memberships: []UserGroup{
		{Group: Group{Name: "a@x"}}, {Group: Group{Name: "b@x"}},
	}}
	b := User{ID: 1, Memberships: []UserGroup{
		{Group: Group{Name: "b@x"}, Source: "other"}, {Group: Group{Name: "a@x"}},
	}}
	assert.True(t, a.PolicyEqual(&b))
}

func TestUserCloneDeepCopiesMemberships(t *testing.T) {
	u := &User{Memberships: []UserGroup{{Group: Group{Name: "eng@example.com"}}}}
	c := u.Clone()
	c.Memberships[0].Group.Name = "changed"

	assert.Equal(t, "eng@example.com", u.Memberships[0].Group.Name)
}

func TestGroupsFromClaims(t *testing.T) {
	claims := map[string]any{
		"groups":                     []any{"eng", "ops", 7, nil},
		"single":                     "admins",
		"https://example.com/groups": []any{"auth0-group"},
		"cognito:groups":             []any{"cognito-group"},
		"realm_access":               map[string]any{"roles": []any{"kc-role"}},
		"realm_access.roles":         []any{"literal-wins"},
		"resource_access":            map[string]any{"headscale": map[string]any{"roles": []any{"client-role"}}},
		"empty":                      []any{},
		"null":                       nil,
		"number":                     42,
	}

	tests := []struct {
		claim     string
		want      []string
		wantFound bool
	}{
		{claim: "groups", want: []string{"eng", "ops"}, wantFound: true},
		{claim: "single", want: []string{"admins"}, wantFound: true},
		{claim: "https://example.com/groups", want: []string{"auth0-group"}, wantFound: true},
		{claim: "cognito:groups", want: []string{"cognito-group"}, wantFound: true},
		{claim: "realm_access.roles", want: []string{"literal-wins"}, wantFound: true},
		{claim: "resource_access.headscale.roles", want: []string{"client-role"}, wantFound: true},
		{claim: "empty", want: []string{}, wantFound: true},
		{claim: "null", want: nil, wantFound: true},
		{claim: "number", want: nil, wantFound: true},
		{claim: "missing", want: nil, wantFound: false},
		{claim: "realm_access.missing", want: nil, wantFound: false},
		{claim: "single.nested", want: nil, wantFound: false},
	}

	for _, tt := range tests {
		t.Run(tt.claim, func(t *testing.T) {
			got, found := GroupsFromClaims(claims, tt.claim)
			assert.Equal(t, tt.want, got)
			assert.Equal(t, tt.wantFound, found)
		})
	}

	// Keycloak nests roles under an object; without the literal key the path
	// is followed.
	delete(claims, "realm_access.roles")
	got, found := GroupsFromClaims(claims, "realm_access.roles")
	assert.True(t, found)
	assert.Equal(t, []string{"kc-role"}, got)
}
