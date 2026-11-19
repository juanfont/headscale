package apiv0

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCutPage(t *testing.T) {
	id := func(n uint64) uint64 { return n }
	q := PageQuery{PageSize: 2}

	var (
		walked []uint64
		pages  int
	)

	for {
		pg, err := openPage[uint64](q, "things", "a")
		require.NoError(t, err)

		// All rows, as a list in memory passes them: cutPage skips the
		// rows before the page.
		rows, next := cutPage(pg, []uint64{1, 2, 3, 5, 8}, id)
		walked = append(walked, rows...)
		pages++

		if next == "" {
			break
		}

		q.PageToken = next
	}

	require.Equal(t, []uint64{1, 2, 3, 5, 8}, walked)
	require.Equal(t, 3, pages)

	pg, err := openPage[uint64](PageQuery{PageSize: 2}, "things")
	require.NoError(t, err)

	rows, next := cutPage(pg, []uint64{1, 2}, id)
	require.Equal(t, []uint64{1, 2}, rows)
	require.Empty(t, next, "a page that holds the last row has no token")

	rows, next = cutPage(pg, nil, id)
	require.Empty(t, rows)
	require.Empty(t, next)
}

// TestCutPageByName walks a list keyed by a name, as tags are, byte by
// byte.
func TestCutPageByName(t *testing.T) {
	name := func(s string) string { return s }
	all := []string{"tag:a", "tag:b", "tag:c"}
	q := PageQuery{PageSize: 2}

	pg, err := openPage[string](q, "tags")
	require.NoError(t, err)

	rows, next := cutPage(pg, all, name)
	require.Equal(t, []string{"tag:a", "tag:b"}, rows)

	q.PageToken = next
	pg, err = openPage[string](q, "tags")
	require.NoError(t, err)

	rows, next = cutPage(pg, all, name)
	require.Equal(t, []string{"tag:c"}, rows)
	require.Empty(t, next)

	_, err = openPage[uint64](q, "tags")
	require.Error(t, err, "a token keyed by a name is not read as an ID")
}

// TestPageTokenRefused: every token the server did not make for this list
// and these filters, in this process, is invalid_page_token.
func TestPageTokenRefused(t *testing.T) {
	pg, err := openPage[uint64](PageQuery{PageSize: 1}, "users", "alice", "")
	require.NoError(t, err)

	_, good := cutPage(pg, []uint64{3, 4}, func(n uint64) uint64 { return n })
	require.NotEmpty(t, good)

	payload, sig, _ := strings.Cut(good, ".")
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	require.NoError(t, err)

	// Signed with the right key, but not a token of this format.
	signed := func(payload string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + base64.RawURLEncoding.EncodeToString(pageMAC([]byte(payload)))
	}

	forged := strings.Replace(string(raw), `"a":"3"`, `"a":"1"`, 1)
	require.NotEqual(t, string(raw), forged)

	for _, tt := range []struct {
		name    string
		token   string
		list    string
		filters []string
	}{
		{"another list", good, "nodes", []string{"alice", ""}},
		{"other filters", good, "users", []string{"bob", ""}},
		{"filters moved between fields", good, "users", []string{"", "alice"}},
		{"changed payload, old signature", base64.RawURLEncoding.EncodeToString([]byte(forged)) + "." + sig, "users", []string{"alice", ""}},
		{"no signature", payload, "users", []string{"alice", ""}},
		{"not base64", "!!!.???", "users", []string{"alice", ""}},
		{"too long", strings.Repeat("a", maxPageToken+1), "users", []string{"alice", ""}},
		{"other format version", signed(strings.Replace(string(raw), `"v":1`, `"v":2`, 1)), "users", []string{"alice", ""}},
		{"unknown member", signed(strings.Replace(string(raw), `{`, `{"x":1,`, 1)), "users", []string{"alice", ""}},
		{"after of the wrong type", signed(strings.Replace(string(raw), `"a":"3"`, `"a":3`, 1)), "users", []string{"alice", ""}},
		{"after that is not an ID", signed(strings.Replace(string(raw), `"a":"3"`, `"a":"3 OR 1=1"`, 1)), "users", []string{"alice", ""}},
		{"two values", signed(string(raw) + string(raw)), "users", []string{"alice", ""}},
	} {
		t.Run(tt.name, func(t *testing.T) {
			_, err := openPage[uint64](PageQuery{PageSize: 1, PageToken: tt.token}, tt.list, tt.filters...)

			p, ok := err.(*Problem) //nolint:errorlint // openPage returns the problem itself
			require.True(t, ok, "%v", err)
			require.Equal(t, CodeInvalidPageToken, p.Code)
		})
	}

	t.Run("a token from before a restart", func(t *testing.T) {
		old := pageKey
		pageKey = []byte("another process")

		t.Cleanup(func() { pageKey = old })

		_, err := openPage[uint64](PageQuery{PageSize: 1, PageToken: good}, "users", "alice", "")
		require.Error(t, err)
	})

	t.Run("the good token", func(t *testing.T) {
		pg, err := openPage[uint64](PageQuery{PageSize: 1, PageToken: good}, "users", "alice", "")
		require.NoError(t, err)
		require.Equal(t, uint64(3), pg.after)
	})
}
