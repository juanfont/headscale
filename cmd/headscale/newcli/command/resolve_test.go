package command

import (
	"slices"
	"testing"
	"time"

	lib "github.com/juanfont/headscale/cmdline/command"
	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
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
		{
			Id:         "9",
			Name:       "debtquity",
			Email:      "d@example.com",
			Provider:   "oidc",
			ProviderId: "https://idp/9",
		},
		{Id: "12", Name: "3", Provider: "local"},
		{Id: "13", Name: "", Email: "", Provider: "oidc", ProviderId: "sub-13"},
	}

	find2 := func(rows []clientv0.User, word string) (string, error) {
		u, err := lib.Resolve(
			rows,
			word,
			word,
			"user",
			userCandidates(),
			func(u clientv0.User) string { return u.Id },
			func(u clientv0.User) []string { return []string{u.Email, u.Name, u.ProviderId} },
		)

		return u.Id, err
	}

	find := func(word string) (string, error) {
		u, err := lib.Resolve(
			users,
			word,
			word,
			"user",
			userCandidates(),
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
	_, err = find2(
		append(
			slices.Clone(users),
			clientv0.User{Id: "14", Name: "sub-13", Provider: "local"},
		),
		"sub-13",
	)
	require.EqualError(t, err, `"sub-13" matches 2 users. Use the ID to select one:

  ID  NAME    EMAIL  PROVIDER  PROVIDER ID
  13  -       -      oidc      sub-13
  14  sub-13  -      local     -`)

	both := append(
		slices.Clone(users),
		clientv0.User{Id: "20", Name: "x@y.z", Email: "x@y.z"},
	)
	u, err := lib.Resolve(
		both,
		"x@y.z",
		"x@y.z",
		"user",
		userCandidates(),
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

	// Any tree checks them.
	_, err := Build("prog", "P", New(Spec[NoInput, NoOutput]{
		Name: "say", Short: "S", Long: "S.", Example: []string{"prog say"}, Local: true,
		Run:  noop[NoInput, NoOutput],
		Done: func(NoInput, NoOutput, time.Time) string { return "" },
	}))
	require.NoError(t, err)
}
