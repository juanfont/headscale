package table

import (
	"math"
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
