package command

import (
	"testing"
	"time"

	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

// TestEnded: every sentence of the end of a credential, for a credential
// that was valid and for one revoked already.
func TestEnded(t *testing.T) {
	t.Parallel()

	now := time.Date(2999, 1, 10, 12, 0, 0, 0, time.UTC)
	at := func(d time.Duration) nullable.Nullable[time.Time] { return nullable.NewNullableWithValue(now.Add(d)) }
	day := 24 * time.Hour

	valid := Ended{
		ID:      "2",
		Name:    "API key 2 (tr81ys)",
		Revoked: nullable.NewNullNullable[time.Time](),
	}
	revoked := Ended{ID: "2", Name: "API key 2 (tr81ys)", Revoked: at(-day)}
	read := func(removal nullable.Nullable[time.Time]) Ended {
		return Ended{ID: "2", Revoked: at(0), Removal: removal}
	}

	for _, tt := range []struct {
		name          string
		before, after Ended
		want          string
	}{
		{"removed", valid, read(at(7 * day)), "API key 2 (tr81ys) is revoked. Its record is removed in 7d."},
		{"kept", valid, read(nullable.NewNullNullable[time.Time]()), "API key 2 (tr81ys) is revoked. Its record is kept."},
		{"due", valid, read(at(0)), "API key 2 (tr81ys) is revoked. Its record is due for removal."},
		{"not read", valid, Ended{}, "API key 2 (tr81ys) is revoked."},
		{"revoked already, removed", revoked, read(at(6 * day)), "API key 2 (tr81ys) was revoked already. Its record is removed in 6d."},
		{"revoked already, kept", revoked, read(nullable.NewNullNullable[time.Time]()), "API key 2 (tr81ys) was revoked already. Its record is kept."},
		{"revoked already, due", revoked, read(at(-time.Hour)), "API key 2 (tr81ys) was revoked already. Its record is due for removal."},
		{"revoked already, not read", revoked, Ended{}, "API key 2 (tr81ys) was revoked already."},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, ended(tt.before, tt.after, now))
		})
	}
}
