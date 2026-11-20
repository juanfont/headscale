package command

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestExpiry: an expiry reads a time, a date, a duration from now and the
// words its command declares; a word it does not declare and a duration of
// zero are mistakes of the line.
func TestExpiry(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 11, 20, 9, 0, 0, 0, time.UTC)

	for text, want := range map[string]time.Time{
		"2999-08-27T10:00:00Z": time.Date(2999, 8, 27, 10, 0, 0, 0, time.UTC),
		"2999-08-27":           time.Date(2999, 8, 27, 0, 0, 0, 0, time.UTC),
		"90d":                  now.Add(90 * 24 * time.Hour),
	} {
		var e Expiry[NowNever]
		require.NoError(t, e.UnmarshalText([]byte(text)))
		require.Equal(t, want, e.At(now), text)
		require.Empty(t, e.Word(), text)
	}

	for _, word := range []string{"now", "never"} {
		var e Expiry[NowNever]
		require.NoError(t, e.UnmarshalText([]byte(word)))
		require.Equal(t, word, e.Word())
		require.True(t, e.At(now).IsZero())
	}

	var node Expiry[NowNever]
	require.EqualError(t, node.UnmarshalText([]byte("soon")), "it is a time, a date, a duration such as 90d, now or never")
	require.EqualError(t, node.UnmarshalText([]byte("0s")), "a duration from now is longer than 0")
	require.EqualError(t, node.UnmarshalText([]byte("300y")), "a duration from now is at most 292y; a later time is written as a date, such as 2999-08-27")
	require.NoError(t, node.UnmarshalText([]byte("292y")))
	require.Equal(t, now.Add(292*365*24*time.Hour), node.At(now))

	var key Expiry[NoWords]
	require.EqualError(t, key.UnmarshalText([]byte("never")), "it is a time, a date or a duration such as 90d")
	require.EqualError(t, key.UnmarshalText([]byte("now")), "it is a time, a date or a duration such as 90d")
	require.NoError(t, key.UnmarshalText([]byte("1h")))
}

// TestOwned: an owner reads as every message writes it.
func TestOwned(t *testing.T) {
	t.Parallel()

	user := clientv0.Owner{User: nullable.NewNullableWithValue(clientv0.OwnerUser{Id: "3", LoginName: "alice"})}
	tags := clientv0.Owner{Tags: []string{"tag:ci", "tag:b\nx"}, User: nullable.NewNullNullable[clientv0.OwnerUser]()}

	require.Equal(t, "owned by User 3 (alice)", Owned(nullable.NewNullableWithValue(user)))
	require.Equal(t, `tagged tag:ci, tag:b\x0ax`, Owned(nullable.NewNullableWithValue(tags)))
	require.Equal(t, "with no owner", Owned(nullable.NewNullNullable[clientv0.Owner]()))

	name, tagged := OwnerName(nullable.NewNullableWithValue(user))
	require.Equal(t, "User 3 (alice)", name)
	require.False(t, tagged)

	name, tagged = OwnerName(nullable.NewNullableWithValue(tags))
	require.Equal(t, `tag:ci, tag:b\x0ax`, name)
	require.True(t, tagged)

	name, _ = OwnerName(nullable.NewNullNullable[clientv0.Owner]())
	require.Empty(t, name)
}

type ownerIn struct {
	Owner Owner `arg:"owner"`
}

// TestOwner: an owner is a user, looked up as a target is, or tags; its
// form is checked before any call.
func TestOwner(t *testing.T) {
	t.Parallel()

	var (
		mu    sync.Mutex
		asked int
	)

	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		mu.Lock()
		asked++
		mu.Unlock()

		w.Header().Set("Headscale-Version", "dev")
		_, _ = w.Write([]byte(`{"users": [{"id": "3", "name": "alice", "loginName": "alice"}, {"id": "4", "name": "bob", "loginName": "bob"}]}`))
	}))
	t.Cleanup(s.Close)

	tree, err := Build("prog", "A program", New(Spec[ownerIn, NoOutput]{
		Name: "make", Short: "S", Long: "S.", Example: []string{"prog make alice"},
		Run: noop[ownerIn, NoOutput],
		Done: func(in ownerIn, _ NoOutput, _ time.Time) string {
			if u, ok := in.Owner.User(); ok {
				return "user " + u.Id
			}

			return "tags " + strings.Join(in.Owner.Tags(), " ")
		},
	}))
	require.NoError(t, err)

	file := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(file, nil, 0o600))

	for _, tt := range []struct {
		line, stdout, stderr string
		calls                int
	}{
		{line: "make alice", stdout: "user 3\n", calls: 1},
		{line: "make 4", stdout: "user 4\n", calls: 1},
		{line: "make tag:ci,tag:build", stdout: "tags tag:ci tag:build\n"},
		{line: "make alcie", stderr: "Error: no user matches \"alcie\".\n", calls: 1},
		{line: "make alice,tag:ci", stderr: "Error: a key is owned by one user or by tags, not both.\n"},
		{line: "make alice,bob", stderr: "Error: a key is owned by one user. Got 2: alice, bob.\n"},
		{line: "make tag:ci,,tag:b", stderr: "Error: the owner list has an empty item.\n"},
		{line: "make ''", stderr: "Error: an empty word names no owner.\n"},
	} {
		mu.Lock()
		asked = 0
		mu.Unlock()

		var stdout, stderr bytes.Buffer

		Run(tree, words(tt.line), Env{
			Stdout: &stdout, Stderr: &stderr,
			Environ: []string{"HEADSCALE_CONFIG=" + file, "HEADSCALE_CLI_ADDRESS=" + s.URL, "HEADSCALE_CLI_API_KEY=key"},
		})
		require.Equal(t, tt.stdout, stdout.String(), tt.line)
		require.Equal(t, tt.stderr, stderr.String(), tt.line)

		mu.Lock()
		require.Equal(t, tt.calls, asked, tt.line)
		mu.Unlock()
	}
}
