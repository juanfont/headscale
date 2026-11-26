package command

import (
	"testing"
	"time"

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
	require.EqualError(
		t,
		node.UnmarshalText([]byte("soon")),
		"it is a time, a date, a duration such as 90d, now or never",
	)
	require.EqualError(
		t,
		node.UnmarshalText([]byte("0s")),
		"a duration from now is longer than 0",
	)
	require.EqualError(
		t,
		node.UnmarshalText([]byte("300y")),
		"a duration from now is at most 292y; a later time is written as a date, such as 2999-08-27",
	)
	require.NoError(t, node.UnmarshalText([]byte("292y")))
	require.Equal(t, now.Add(292*365*24*time.Hour), node.At(now))

	var key Expiry[NoWords]
	require.EqualError(
		t,
		key.UnmarshalText([]byte("never")),
		"a key must have an expiry: a time, a date or a duration such as 90d.",
	)
	require.EqualError(
		t,
		key.UnmarshalText([]byte("now")),
		"a key must have an expiry: a time, a date or a duration such as 90d.",
	)
	require.EqualError(
		t,
		key.UnmarshalText([]byte("soon")),
		"it is a time, a date or a duration such as 90d",
	)
	require.NoError(t, key.UnmarshalText([]byte("1h")))
}
