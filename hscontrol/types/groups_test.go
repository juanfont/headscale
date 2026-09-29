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
		{name: "name with at", group: "eng@corp", domain: "example.com", wantErr: ErrGroupNameContainsAt},
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
