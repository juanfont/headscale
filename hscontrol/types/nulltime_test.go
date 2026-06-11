package types

import (
	"database/sql/driver"
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNullTime_Value(t *testing.T) {
	t.Run("zero returns nil for SQL NULL", func(t *testing.T) {
		v, err := NullTime{}.Value()
		require.NoError(t, err)
		assert.Nil(t, v)
	})

	t.Run("non-zero returns underlying time.Time", func(t *testing.T) {
		now := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
		v, err := NullTime(now).Value()
		require.NoError(t, err)

		gotTime, ok := v.(time.Time)
		require.True(t, ok, "expected time.Time, got %T", v)
		assert.True(t, gotTime.Equal(now))
	})
}

func TestNullTime_Scan(t *testing.T) {
	tests := []struct {
		name     string
		input    any
		wantZero bool
		wantTime time.Time
	}{
		{
			name:     "nil produces zero",
			input:    nil,
			wantZero: true,
		},
		{
			name:     "zero time.Time produces zero",
			input:    time.Time{},
			wantZero: true,
		},
		{
			name:     "year-1 string (legacy SQLite row) produces zero",
			input:    "0001-01-01 00:00:00+00:00",
			wantZero: true,
		},
		{
			name:     "year-1 time.Time (legacy Postgres row) produces zero",
			input:    time.Date(1, 1, 1, 0, 0, 0, 0, time.UTC),
			wantZero: true,
		},
		{
			name:     "valid time.Time round-trips",
			input:    time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
			wantZero: false,
			wantTime: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		},
		{
			name:     "valid string round-trips",
			input:    "2026-05-29 12:00:00+00:00",
			wantZero: false,
			wantTime: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nt NullTime
			require.NoError(t, nt.Scan(tt.input))

			if tt.wantZero {
				assert.True(t, nt.IsZero(), "expected zero NullTime, got %v", nt.Time())
				return
			}

			assert.False(t, nt.IsZero())
			assert.True(t, nt.Time().Equal(tt.wantTime),
				"expected %v, got %v", tt.wantTime, nt.Time())
		})
	}
}

func TestNullTime_MarshalJSON(t *testing.T) {
	t.Run("zero marshals as null", func(t *testing.T) {
		b, err := json.Marshal(NullTime{})
		require.NoError(t, err)
		assert.Equal(t, "null", string(b))
	})

	t.Run("non-zero marshals as RFC3339 string", func(t *testing.T) {
		ts := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
		b, err := json.Marshal(NullTime(ts))
		require.NoError(t, err)
		assert.Equal(t, `"2026-05-29T12:00:00Z"`, string(b))
	})

	t.Run("zero NullTime inside a struct marshals as null field", func(t *testing.T) {
		// Mirrors the headplane consumer scenario: JSON-encoded Node
		// with zero Expiry should expose "expiry":null, not the year-1
		// string.
		s := struct {
			Expiry NullTime `json:"expiry"`
		}{}
		b, err := json.Marshal(s)
		require.NoError(t, err)
		assert.JSONEq(t, `{"expiry":null}`, string(b))
	})
}

func TestNullTime_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name     string
		jsonIn   string
		wantZero bool
		wantTime time.Time
	}{
		{
			name:     "literal null produces zero",
			jsonIn:   "null",
			wantZero: true,
		},
		{
			name:     "legacy year-1 string produces zero (backward compat)",
			jsonIn:   `"0001-01-01T00:00:00Z"`,
			wantZero: true,
		},
		{
			name:     "valid RFC3339 round-trips",
			jsonIn:   `"2026-05-29T12:00:00Z"`,
			wantZero: false,
			wantTime: time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nt NullTime
			require.NoError(t, json.Unmarshal([]byte(tt.jsonIn), &nt))

			if tt.wantZero {
				assert.True(t, nt.IsZero())
				return
			}

			assert.False(t, nt.IsZero())
			assert.True(t, nt.Time().Equal(tt.wantTime))
		})
	}

	t.Run("malformed JSON returns error", func(t *testing.T) {
		var nt NullTime
		err := json.Unmarshal([]byte(`"not-a-time"`), &nt)
		require.Error(t, err)
	})
}

func TestNullTime_RoundTrip_DB(t *testing.T) {
	// Value → Scan must preserve a non-zero time and collapse zero/NULL.
	t.Run("non-zero", func(t *testing.T) {
		original := NullTime(time.Date(2026, 5, 29, 12, 34, 56, 0, time.UTC))

		v, err := original.Value()
		require.NoError(t, err)
		require.NotNil(t, v)

		var roundTripped NullTime
		require.NoError(t, roundTripped.Scan(v))
		assert.True(t, roundTripped.Time().Equal(original.Time()))
	})

	t.Run("zero → nil → zero", func(t *testing.T) {
		v, err := NullTime{}.Value()
		require.NoError(t, err)
		require.Nil(t, v)

		var roundTripped NullTime
		require.NoError(t, roundTripped.Scan(v))
		assert.True(t, roundTripped.IsZero())
	})
}

func TestNullTime_RoundTrip_JSON(t *testing.T) {
	t.Run("non-zero", func(t *testing.T) {
		original := NullTime(time.Date(2026, 5, 29, 12, 34, 56, 0, time.UTC))

		b, err := json.Marshal(original)
		require.NoError(t, err)

		var roundTripped NullTime
		require.NoError(t, json.Unmarshal(b, &roundTripped))
		assert.True(t, roundTripped.Time().Equal(original.Time()))
	})

	t.Run("zero round-trips through null", func(t *testing.T) {
		b, err := json.Marshal(NullTime{})
		require.NoError(t, err)
		assert.Equal(t, "null", string(b))

		var roundTripped NullTime
		require.NoError(t, json.Unmarshal(b, &roundTripped))
		assert.True(t, roundTripped.IsZero())
	})
}

func TestNullTime_Helpers(t *testing.T) {
	t.Run("NullTimeFrom is the identity wrt. zero", func(t *testing.T) {
		assert.True(t, NullTimeFrom(time.Time{}).IsZero())
	})

	t.Run("NullTimeFrom preserves non-zero", func(t *testing.T) {
		ts := time.Date(2026, 5, 29, 12, 0, 0, 0, time.UTC)
		assert.True(t, NullTimeFrom(ts).Time().Equal(ts))
	})

	t.Run("Time on zero returns the zero time.Time", func(t *testing.T) {
		assert.True(t, NullTime{}.Time().IsZero())
	})
}

// TestNullTime_DriverValuerInterface confirms NullTime satisfies the
// database/sql driver.Valuer contract at compile time.
func TestNullTime_DriverValuerInterface(t *testing.T) {
	var _ driver.Valuer = NullTime{}
}
