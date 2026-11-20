package command

import (
	"testing"
	"time"

	clientv0 "github.com/juanfont/headscale/gen/client/headscale/v0"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// timeOnly is an expiry that takes no word, as a key's does.
type timeOnly struct{}

func (timeOnly) Words() []string { return nil }

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

	var key Expiry[timeOnly]
	require.EqualError(t, key.UnmarshalText([]byte("never")), "it is a time, a date or a duration such as 90d")
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
}
