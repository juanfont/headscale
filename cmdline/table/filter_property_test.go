package table

import (
	"errors"
	"math"
	"strconv"
	"testing"
	"time"

	"github.com/oapi-codegen/nullable"
	"pgregory.net/rapid"
)

// Bound: distances end at MaxInt64; the far case past it is
// TestRelativeDurationFar's (last-seen only).
func TestRapidRelativeTimeFilter(t *testing.T) {
	t.Parallel()

	rapid.Check(t, func(t *rapid.T) {
		// Leave one nanosecond on either side of the cutoff for strict comparisons.
		limit := rapid.Int64Range(1, math.MaxInt64-1).
			Draw(t, "limit")
			// zero is refused (TestZeroDurationFilter)
		step := rapid.Int64Range(-1, 1).Draw(t, "step")

		offset := limit + step
		if rapid.Bool().Draw(t, "opposite side of now") {
			offset = -offset
		}

		distance := max(int64(0), offset)
		r := row{
			Seen:   now.Add(-time.Duration(offset)),
			Expiry: nullable.NewNullableWithValue(now.Add(time.Duration(offset))),
		}

		for _, col := range []string{"last-seen", "expiry"} {
			for _, op := range []string{"<", ">"} {
				expr := col + op + time.Duration(limit).String()

				f, err := listCols.ParseFilter(expr)
				if err != nil {
					fatalf(t, "%v", err)
				}

				got, err := f.Match(r, now)
				if err != nil {
					fatalf(t, "%v", err)
				}

				want := distance < limit
				if op == ">" {
					want = distance > limit
				}

				if got != want {
					t.Logf(
						"%s, signed distance %d, want %t, got %t",
						expr,
						offset,
						want,
						got,
					)
					fatalf(
						t,
						"relative time comparison disagrees with clamped distance",
					)
				}
			}
		}
	})
}

// Bound: fractions are always .0, so dropping a nonzero fraction passes.
func TestRapidDurationBoundary(t *testing.T) {
	type unit struct {
		word     string
		size     uint64
		fraction bool
	}

	units := []unit{
		{"ns", uint64(time.Nanosecond), true},
		{"us", uint64(time.Microsecond), true},
		{"µs", uint64(time.Microsecond), true},
		{"μs", uint64(time.Microsecond), true},
		{"ms", uint64(time.Millisecond), true},
		{"s", uint64(time.Second), true},
		{"m", uint64(time.Minute), true},
		{"h", uint64(time.Hour), true},
		{"d", uint64(24 * time.Hour), false},
		{"w", uint64(7 * 24 * time.Hour), false},
		{"y", uint64(365 * 24 * time.Hour), false},
	}

	var inRange, overLimit, fractional, compound int

	rapid.Check(t, func(rt *rapid.T) {
		u := rapid.SampledFrom(units).Draw(rt, "unit")
		limit := uint64(math.MaxInt64) / u.size
		n := limit - 2 + rapid.Uint64Range(0, 4).Draw(rt, "magnitude near limit")

		number := strconv.FormatUint(n, 10)
		if u.fraction && rapid.Bool().Draw(rt, "equivalent fractional spelling") {
			number += ".0"
			fractional++
		}

		check := func(word string) {
			rt.Helper()

			d, _, span, err := ReadTime(word)
			if n > limit {
				overLimit++

				if !errors.Is(err, ErrTooLong) {
					rt.Logf("%q: got duration %v and error %v", word, d, err)
					rt.Fatal("duration overflow lost its error identity")
				}
			} else if err != nil || !span || d < 0 || uint64(d) != n*u.size {
				rt.Logf("%q: got duration %v span=%t error=%v", word, d, span, err)
				rt.Fatal("representable duration changed")
			} else {
				inRange++
			}

			_, _, _, invalid := ReadTime(word + "?")
			if invalid == nil || errors.Is(invalid, ErrTooLong) {
				fatalf(rt, "%q: malformed duration classified as %v", word+"?", invalid)
			}
		}
		check(number + u.word)

		if u.fraction {
			left := rapid.Uint64Range(0, n).Draw(rt, "first component")
			head := strconv.FormatUint(left, 10) + u.word
			tail := strconv.FormatUint((n-left)*u.size, 10) + "ns"
			check(head + tail)

			compound++
		}
	})
	t.Logf(
		"model classes representable=%d overflow=%d fractional-spellings=%d compound-spellings=%d",
		inRange,
		overLimit,
		fractional,
		compound,
	)
}
