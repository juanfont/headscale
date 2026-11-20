package command

import (
	"slices"
	"testing"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestResolve holds the rules of a target, on users: an exact ID wins, the
// other fields are searched together, a user that matches in two fields
// counts once, and more than one match lists the candidates.
func TestResolve(t *testing.T) {
	t.Parallel()

	users := []clientv0.User{
		{Id: "3", Name: "alice", Email: "alice@example.com", Provider: "local"},
		{Id: "8", Name: "debtquity", Provider: "local"},
		{Id: "9", Name: "debtquity", Email: "d@example.com", Provider: "oidc", ProviderId: "https://idp/9"},
		{Id: "12", Name: "3", Provider: "local"},
		{Id: "13", Name: "", Email: "", Provider: "oidc", ProviderId: "sub-13"},
	}

	find2 := func(rows []clientv0.User, word string) (string, error) {
		u, err := resolve(rows, word, word, "user", userCandidates(),
			func(u clientv0.User) string { return u.Id },
			func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
		)

		return u.Id, err
	}

	find := func(word string) (string, error) {
		u, err := resolve(users, word, word, "user", userCandidates(),
			func(u clientv0.User) string { return u.Id },
			func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
		)

		return u.Id, err
	}

	for word, want := range map[string]string{
		"3":                 "3",
		"alice":             "3",
		"alice@example.com": "3",
		"d@example.com":     "9",
		"https://idp/9":     "9",
		"sub-13":            "13",
		"12":                "12",
	} {
		got, err := find(word)
		require.NoError(t, err, word)
		require.Equal(t, want, got, word)
	}

	_, err := find("debtquity")
	require.EqualError(t, err, `"debtquity" matches 2 users. Use the ID to select one:

  ID  NAME       EMAIL          PROVIDER
  8   debtquity  -              local
  9   debtquity  d@example.com  oidc`)

	for _, word := range []string{"nope", "", "alic", "ALICE"} {
		_, err := find(word)
		require.EqualError(t, err, "no user matches "+`"`+word+`".`, word)
	}

	// A word that is a provider identifier says so in the list.
	_, err = find2(append(slices.Clone(users), clientv0.User{Id: "14", Name: "sub-13", Provider: "local"}), "sub-13")
	require.EqualError(t, err, `"sub-13" matches 2 users. Use the ID to select one:

  ID  NAME    EMAIL  PROVIDER  PROVIDER ID
  13  -       -      oidc      sub-13
  14  sub-13  -      local     -`)

	both := append(slices.Clone(users), clientv0.User{Id: "20", Name: "x@y.z", Email: "x@y.z"})
	u, err := resolve(both, "x@y.z", "x@y.z", "user", userCandidates(),
		func(u clientv0.User) string { return u.Id },
		func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
	)
	require.NoError(t, err, "a user that matches in two fields counts once")
	require.Equal(t, "20", u.Id)
}

// TestCandidatesChecked: the columns of a lookup's candidates are checked
// when any tree is built, not when a word first matches two rows.
func TestCandidatesChecked(t *testing.T) {
	t.Parallel()

	for _, e := range entities() {
		require.NoError(t, e.check(), e.kind)
	}
}

// TestMatchAuthKey: a key is found by ID, else by prefix, also when typed
// masked or whole; no message repeats a secret.
func TestMatchAuthKey(t *testing.T) {
	t.Parallel()

	alice := nullable.NewNullableWithValue(clientv0.Owner{User: nullable.NewNullableWithValue(clientv0.OwnerUser{Id: "3", LoginName: "alice"})})
	ci := nullable.NewNullableWithValue(clientv0.Owner{Tags: []string{"tag:ci"}, User: nullable.NewNullNullable[clientv0.OwnerUser]()})
	keys := []clientv0.AuthKey{
		{Id: "7", Prefix: "ab12cd", Owner: alice, State: "valid"},
		{Id: "9", Prefix: "7", Owner: ci, State: "revoked"},
		{Id: "10", Prefix: "legacy-0f1e2d", Owner: ci, State: "valid"},
		// Two keys with one prefix: a server cannot store them, the rule
		// lists them all the same.
		{Id: "11", Prefix: "dup123", Owner: alice, State: "valid"},
		{Id: "12", Prefix: "dup123", Owner: ci, State: "expired"},
	}

	for word, want := range map[string]string{
		"7":                            "7",
		"ab12cd":                       "7",
		"hskey-auth-ab12cd-***":        "7",
		"9":                            "9",
		"hskey-auth-legacy-0f1e2d-***": "10",
	} {
		w, err := credentialWord(authKeyTyped(), word)
		require.NoError(t, err, word)

		k, err := matchAuthKey(keys, w, word)
		require.NoError(t, err, word)
		require.Equal(t, want, k.Id, word)
	}

	// A whole key is refused, also one whose secret holds a dash, as keys
	// of 0.28 and 0.29 can, and in any case; the prefix is said, the
	// secret not.
	for word, want := range map[string]string{
		"hskey-auth-ab12cd345678-0123456789abcd": " Its prefix is ab12cd345678.",
		"hskey-auth-ab12cd345678-01234-6789abcd": " Its prefix is ab12cd345678.",
		"HSKEY-AUTH-ab12cd345678-0123456789abcd": " Its prefix is ab12cd345678.",
		"hskey-auht-ab12cd345678-0123456789abcd": "",
		"hskey-api-ab12cd345678-0123456789abcd":  "",
		"hskey-auth-short":                       "",
	} {
		_, err := credentialWord(authKeyTyped(), word)
		require.EqualError(t, err, "a key is named by its ID or its prefix, never by the whole key."+want, word)
	}

	_, err := matchAuthKey(keys, "ffffff", "ffffff")
	require.EqualError(t, err, `no auth key matches "ffffff".`)

	// A secret typed in the masked form is a part that holds the secret:
	// the message quotes the word as typed, which the edge masks.
	w, err := credentialWord(authKeyTyped(), "hskey-auth-ab12cd345678-s3cret-***")
	require.NoError(t, err)

	_, err = matchAuthKey(keys, w, "hskey-auth-ab12cd345678-s3cret-***")
	require.EqualError(t, err, `no auth key matches "hskey-auth-ab12cd345678-s3cret-***".`)
	require.Equal(t, `no auth key matches "hskey-auth-***".`, masked(err.Error()))

	_, err = matchAuthKey(keys, "dup123", "dup123")
	require.EqualError(t, err, `"dup123" matches 2 auth keys. Use the ID to select one:

  ID  PREFIX  OWNER   STATE
  11  dup123  alice   valid
  12  dup123  tag:ci  expired`)
}

// TestCredentialWord: a key reads its masked form, and every kind refuses
// its whole secret, saying the part that names it; another kind's secret
// is refused without it.
func TestCredentialWord(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		k           typed
		masked, got string
		whole, want string
	}{
		{authKeyTyped(), "hskey-auth-ab12cd-***", "ab12cd", "hskey-auth-ab12cd345678-s3cret", "a key is named by its ID or its prefix, never by the whole key. Its prefix is ab12cd345678."},
		{apiKeyTyped(), "hskey-api-tr81ys-***", "tr81ys", "hskey-api-tr81ys345678-s3cret", "a key is named by its ID or its prefix, never by the whole key. Its prefix is tr81ys345678."},
		{oauthClientTyped(), "c9f2aa000000", "c9f2aa000000", "HSKEY-CLIENT-c9f2aa000000-s3cret", "an OAuth client is named by its ID, never by its secret. Its ID is c9f2aa000000."},
		// No output prints a client in the masked form with its ID, so it
		// names none.
		{oauthClientTyped(), "c9f2aa000000", "c9f2aa000000", "hskey-client-c9f2aa000000-***", "an OAuth client is named by its ID, never by its secret. Its ID is c9f2aa000000."},
		{apiKeyTyped(), "7", "7", "hskey-auth-tr81ys345678-s3cret", "a key is named by its ID or its prefix, never by the whole key."},
		{oauthClientTyped(), "c9f2aa000000", "c9f2aa000000", "hskey-api-c9f2aa000000-s3cret", "an OAuth client is named by its ID, never by its secret."},
	} {
		got, err := credentialWord(tt.k, tt.masked)
		require.NoError(t, err, tt.masked)
		require.Equal(t, tt.got, got, tt.masked)

		_, err = credentialWord(tt.k, tt.whole)
		require.EqualError(t, err, tt.want, tt.whole)
	}
}
