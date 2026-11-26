package config

import (
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

// Bound: components are unsigned integer nanoseconds, and every range error
// counts as a refusal.
func TestRapidDurationSum(t *testing.T) {
	t.Parallel()

	component := rapid.OneOf(
		rapid.SampledFrom([]uint64{0, 1, math.MaxInt64, 1 << 63, 1<<63 + 1}),
		rapid.Uint64(),
	)

	rapid.Check(t, func(t *rapid.T) {
		values := rapid.SliceOfN(component, 1, 5).Draw(t, "nanoseconds")
		negative := rapid.Bool().Draw(t, "negative")

		var (
			total, part big.Int
			word        strings.Builder
		)
		if negative {
			word.WriteByte('-')
		}

		for _, value := range values {
			total.Add(&total, part.SetUint64(value))
			word.WriteString(strconv.FormatUint(value, 10))
			word.WriteString("ns")
		}

		if negative {
			total.Neg(&total)
		}

		got, err := ParseDuration(word.String())
		if total.IsInt64() {
			if err != nil || int64(got) != total.Int64() {
				fatalf(t, "representable sum %s: got %v, err %v", &total, got, err)
			}
		} else if err == nil {
			t.Logf("%s parsed as %v", word.String(), got)
			t.Fatal("out-of-range component sum was accepted")
		}
	})
}

// fatalf fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
