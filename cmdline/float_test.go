package cmdline

import (
	"context"
	"errors"
	"math"
	"math/big"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline/argtest"
	"pgregory.net/rapid"
)

// Round exact fractions directly to the destination width to catch double rounding.
func TestRapidFloatWidths(t *testing.T) {
	type input struct {
		Narrow float32 `flag:"narrow"`
		Wide   float64 `flag:"wide"`
	}

	calls := 0

	var value input

	tree, err := New(Command[input]{Name: "tool", Run: func(_ context.Context, in input) error { calls++; value = in; return nil }})
	if err != nil {
		t.Fatal(err)
	}

	for _, family := range []string{"midpoint", "limits", "zero", "syntax", "special", "edge-zero", "edge-normal", "edge-overflow"} {
		t.Run(family, func(t *testing.T) {
			var ties, below, above, narrow, wide int

			rapid.Check(t, func(rt *rapid.T) {
				flag := "wide"
				bits := 53

				if rapid.Bool().Draw(rt, "float32") {
					flag = "narrow"
					bits = 24
					narrow++
				} else {
					wide++
				}

				inputCase := drawFloatCase(rt, family, bits)
				if family == "midpoint" || strings.HasPrefix(family, "edge-") {
					switch inputCase.midpointSide {
					case -1:
						below++
					case 0:
						ties++
					case 1:
						above++
					}
				}

				calls = 0
				argv := argtest.Option(rt, "--"+flag, inputCase.word)
				line, parseErr := tree.Parse(argv)
				runErr := line.Run(rt.Context())

				if inputCase.err != nil {
					usage, ok := errors.AsType[*UsageError](parseErr)
					if !ok || usage.Kind != BadValue || usage.Flag != flag || usage.Value != inputCase.word || !errors.Is(parseErr, inputCase.err) || !errors.Is(runErr, parseErr) || calls != 0 {
						rt.Fatalf("%s %q: parse=%v run=%v calls=%d want %v", flag, inputCase.word, parseErr, runErr, calls, inputCase.err)
					}

					return
				}

				if parseErr != nil || runErr != nil || calls != 1 {
					rt.Fatalf("%s %q: parse=%v run=%v calls=%d", flag, inputCase.word, parseErr, runErr, calls)
				}

				got := value.Wide
				if bits == 24 {
					got = float64(value.Narrow)
				}

				if math.IsNaN(inputCase.value) && math.IsNaN(got) {
					return
				}

				if math.Float64bits(got) != math.Float64bits(inputCase.value) {
					rt.Fatalf("%s %q: got %x, want %x", flag, inputCase.word, math.Float64bits(got), math.Float64bits(inputCase.value))
				}
			})
			t.Logf("model classes float32=%d float64=%d exact-midpoint=%d below-midpoint=%d above-midpoint=%d", narrow, wide, ties, below, above)
		})
	}
}

type floatCase struct {
	word         string
	value        float64
	err          error
	midpointSide int
}

func drawFloatCase(rt *rapid.T, family string, bits int) floatCase {
	var (
		literal string
		want    float64
		reason  error
		side    int
	)

	rt.Helper()

	if strings.HasPrefix(family, "edge-") {
		return drawFloatBoundary(rt, family, bits)
	}

	var rat *big.Rat

	switch family {
	case "midpoint":
		base := uint64(1) << (bits - 1)
		sig := base + rapid.Uint64Range(0, base-1).Draw(rt, "significand")
		e := rapid.IntRange(-8, 8).Draw(rt, "binary exponent")
		offset := rapid.IntRange(-1, 1).Draw(rt, "side")
		// The one-bit offset sits below binary64 precision on both sides of a binary32 tie.
		num := new(big.Int).SetUint64(2*sig + 1)
		num.Lsh(num, 60)
		den := new(big.Int).Lsh(big.NewInt(1), uint(bits+60-e))
		boundary := new(big.Rat).SetFrac(num, den)
		num.Add(num, big.NewInt(int64(offset)))

		rat = new(big.Rat).SetFrac(num, den)
		if rapid.Bool().Draw(rt, "negative") {
			rat.Neg(rat)
			boundary.Neg(boundary)
		}

		digits := rapid.SampledFrom([]int{16, 8, 32, den.BitLen() - 1}).Draw(rt, "decimal places")
		literal = rat.FloatString(digits)
		// The printed decimal may differ from the exact fraction used to generate it.
		rat.SetString(literal)
		side = rat.Cmp(boundary)
	case "limits":
		exponent := rapid.SampledFrom([]int{-325, -324, -323, -47, -46, -45, -44, 37, 38, 39, 307, 308, 309}).Draw(rt, "decimal exponent")

		literal = strconv.Itoa(rapid.IntRange(1, 9).Draw(rt, "coefficient")) + "e" + strconv.Itoa(exponent)
		if rapid.Bool().Draw(rt, "negative") {
			literal = "-" + literal
		}

		var ok bool

		rat, ok = new(big.Rat).SetString(literal)
		if !ok {
			rt.Fatal("invalid decimal generated")
		}
	case "zero":
		literal = rapid.SampledFrom([]string{"0", "-0", "+0", "-0.0", "-0e99", "0.0000"}).Draw(rt, "zero spelling")
		if strings.HasPrefix(literal, "-") {
			want = math.Copysign(0, -1)
		}
	case "syntax":
		literal = rapid.SampledFrom([]string{"", "1..0", "1e", "--1", "1,2", "1_", "-NaN"}).Draw(rt, "invalid spelling")
		reason = strconv.ErrSyntax
	case "special":
		literal = rapid.SampledFrom([]string{"NaN", "nan", "-Inf", "+Inf", "Infinity", "-Infinity"}).Draw(rt, "special value")
		switch strings.ToLower(literal) {
		case "nan":
			want = math.NaN()
		case "-inf", "-infinity":
			want = math.Inf(-1)
		default:
			want = math.Inf(1)
		}
	}

	if rat != nil {
		if bits == 24 {
			v, _ := rat.Float32()
			want = float64(v)
		} else {
			want, _ = rat.Float64()
		}

		if math.IsInf(want, 0) {
			reason = strconv.ErrRange
		}
	}

	return floatCase{word: literal, value: want, err: reason, midpointSide: side}
}

func drawFloatBoundary(rt *rapid.T, family string, bits int) floatCase {
	rt.Helper()

	// lo is the lower significand; exponent gives one unit in its last place.
	var lo uint64

	maxExponent := 1024
	if bits == 24 {
		maxExponent = 128
	}

	exponent := 3 - maxExponent - bits

	boundary := strings.TrimPrefix(family, "edge-")
	switch boundary {
	case "normal":
		lo = 1<<(bits-1) - 1
	case "overflow":
		lo = 1<<bits - 1
		exponent = maxExponent - bits
	}

	side := rapid.IntRange(-1, 1).Draw(rt, "quarter step")
	numerator := (lo << 2) + uint64(2+side) //nolint:gosec // side lies between -1 and 1.
	power := exponent - 2

	word := "0x" + strconv.FormatUint(numerator, 16) + "p" + strconv.Itoa(power)
	if rapid.Bool().Draw(rt, "decimal") {
		num := new(big.Int).SetUint64(numerator)

		den := big.NewInt(1)
		if power < 0 {
			den.Lsh(den, uint(-power))
		} else {
			num.Lsh(num, uint(power))
		}

		word = new(big.Rat).SetFrac(num, den).FloatString(max(0, -power))
	}

	mantissa := lo
	if side > 0 || (side == 0 && lo&1 != 0) {
		mantissa++
	}

	want := math.Ldexp(float64(mantissa), exponent)

	if rapid.Bool().Draw(rt, "negative") {
		word = "-" + word
		want = -want
	}

	if boundary == "overflow" && mantissa != lo {
		return floatCase{word: word, err: strconv.ErrRange, midpointSide: side}
	}

	return floatCase{word: word, value: want, midpointSide: side}
}
