package types

import (
	"bytes"
	"database/sql"
	"database/sql/driver"
	"fmt"
	"time"
)

// NullTime is a [time.Time] that maps the zero value to SQL NULL on the
// database side and JSON null on the wire. Use it instead of [*time.Time]
// for nullable timestamp columns so a non-nil pointer to a zero time stops
// being representable.
//
// The bug class fixed here: GORM persists a non-nil [*time.Time] pointing
// at a zero [time.Time] as the literal timestamp '0001-01-01 00:00:00'
// rather than NULL, and the JSON encoder emits "0001-01-01T00:00:00Z"
// rather than null. Consumers that test for NULL or null then see the
// wrong state. See #3201 for the full history.
type NullTime time.Time

// Value implements [driver.Valuer]. A zero NullTime returns (nil, nil),
// which GORM and database/sql translate to a SQL NULL.
func (t NullTime) Value() (driver.Value, error) {
	if time.Time(t).IsZero() {
		return nil, nil
	}

	return time.Time(t), nil
}

// scanTimeFormats are the timestamp string formats SQLite and Postgres
// drivers may surface via [sql.Scanner]. mattn/go-sqlite3 and pgx
// normally return [time.Time] directly, but GORM-with-string-scanning
// and older drivers can hand us strings — accept the common shapes
// rather than fail.
var scanTimeFormats = []string{
	"2006-01-02 15:04:05.999999999-07:00",
	"2006-01-02 15:04:05-07:00",
	"2006-01-02 15:04:05.999999999",
	"2006-01-02 15:04:05",
	"2006-01-02T15:04:05.999999999Z07:00",
	time.RFC3339Nano,
	time.RFC3339,
}

// Scan implements [sql.Scanner]. SQL NULL, a nil driver value, and any
// year-1 timestamp (the legacy '0001-01-01' rows from pre-fix headscale
// versions) all collapse to a zero NullTime.
func (t *NullTime) Scan(v any) error {
	if v == nil {
		*t = NullTime{}
		return nil
	}

	switch src := v.(type) {
	case time.Time:
		if src.IsZero() {
			*t = NullTime{}
			return nil
		}

		*t = NullTime(src)

		return nil
	case []byte:
		return t.Scan(string(src))
	case string:
		for _, f := range scanTimeFormats {
			if parsed, err := time.Parse(f, src); err == nil {
				if parsed.IsZero() {
					*t = NullTime{}
				} else {
					*t = NullTime(parsed)
				}

				return nil
			}
		}

		return fmt.Errorf("scanning NullTime: unrecognised string format %q", src)
	}

	var nt sql.NullTime
	if err := nt.Scan(v); err != nil {
		return fmt.Errorf("scanning NullTime: %w", err)
	}

	if !nt.Valid || nt.Time.IsZero() {
		*t = NullTime{}
		return nil
	}

	*t = NullTime(nt.Time)

	return nil
}

// MarshalJSON implements [json.Marshaler]. A zero NullTime marshals as
// the JSON literal null.
func (t NullTime) MarshalJSON() ([]byte, error) {
	if time.Time(t).IsZero() {
		return []byte("null"), nil
	}

	return time.Time(t).MarshalJSON()
}

// UnmarshalJSON implements [json.Unmarshaler]. The JSON literal null and
// a year-1 RFC3339 timestamp ("0001-01-01T00:00:00Z") both collapse to a
// zero NullTime. The year-1 case keeps wire-compat with headplane builds
// or stored payloads written by pre-fix headscale.
func (t *NullTime) UnmarshalJSON(b []byte) error {
	if bytes.Equal(b, []byte("null")) {
		*t = NullTime{}
		return nil
	}

	var parsed time.Time
	if err := parsed.UnmarshalJSON(b); err != nil {
		return fmt.Errorf("unmarshaling NullTime: %w", err)
	}

	if parsed.IsZero() {
		*t = NullTime{}
		return nil
	}

	*t = NullTime(parsed)

	return nil
}

// IsZero reports whether t represents the unset (NULL) state.
func (t NullTime) IsZero() bool { return time.Time(t).IsZero() }

// Time returns the underlying [time.Time]. The zero NullTime returns the
// zero [time.Time], which is the documented sentinel for "no expiry" in
// upstream [tailcfg.Node.KeyExpiry] and friends.
func (t NullTime) Time() time.Time { return time.Time(t) }

// NullTimeFrom constructs a NullTime from a [time.Time]. A zero input
// produces a zero NullTime (i.e. NullTimeFrom is the identity wrt. zero
// values); callers can use it instead of the bare conversion when intent
// matters at the call site.
func NullTimeFrom(t time.Time) NullTime { return NullTime(t) }
