package table

import (
	"fmt"
	"math"
	"math/big"
	"strconv"
	"testing"
	"time"

	"pgregory.net/rapid"
)

type wholeNumberRow[N int64 | uint64] struct {
	Count *N `json:"count"`
	Label int
}

func TestRapidIntegerColumn(t *testing.T) {
	signed := rapid.OneOf(rapid.SampledFrom([]int64{0, 1, -1, 1 << 53, -1 << 53, math.MaxInt64 - 2, math.MinInt64}), rapid.Int64Range(math.MinInt64, math.MaxInt64-2))
	unsigned := rapid.OneOf(rapid.SampledFrom([]uint64{0, 1, 1 << 53, 1 << 63, math.MaxUint64 - 2}), rapid.Uint64Range(0, math.MaxUint64-2))

	for _, op := range []string{"sort", "decimal", "hex", "zero-exponent"} {
		t.Run("signed-"+op, func(t *testing.T) { checkWholeNumbers(t, signed, op) })
		t.Run("unsigned-"+op, func(t *testing.T) { checkWholeNumbers(t, unsigned, op) })
	}
}

func checkWholeNumbers[N int64 | uint64](t *testing.T, values *rapid.Generator[N], operation string) {
	t.Helper()

	cols := Columns[wholeNumberRow[N]]{{Name: "count", Field: "count"}}
	at := time.Time{}

	rapid.Check(t, func(rt *rapid.T) {
		var base N
		if operation != "zero-exponent" {
			base = values.Draw(rt, "lower value")
		}

		a, b := base, base+1
		if operation == "sort" {
			rows := []wholeNumberRow[N]{{Count: &b, Label: 1}, {Count: nil, Label: 2}, {Count: &a, Label: 3}, {Count: &a, Label: 4}}
			key := "count"
			expected := []int{3, 4, 1, 2}

			if rapid.Bool().Draw(rt, "descending") {
				key = "-count"
				expected = []int{1, 3, 4, 2}
			}

			cols.Sort(rows, key, at)

			for i, row := range rows {
				if row.Label != expected[i] {
					rt.Fatalf("%s starting at %v: position %d got label %d want %d", key, a, i, row.Label, expected[i])
				}
			}

			return
		}

		side := rapid.IntRange(-1, 1).Draw(rt, "side of integer")

		var word string

		if operation == "zero-exponent" {
			a = 0

			exp := rapid.SampledFrom([]string{"400", "4000", "2147483650", "99999999999"}).Draw(rt, "exponent")
			if rapid.Bool().Draw(rt, "hexadecimal") {
				word = "0x" + strconv.Itoa(absDigit(side)) + "p-" + exp
			} else {
				word = strconv.Itoa(absDigit(side)) + "e-" + exp
			}

			if side < 0 {
				word = "-" + word
			}
		} else {
			digits := rapid.SampledFrom([]int{1, 8, 18, 32, 330}).Draw(rt, "places")

			radix := 10
			if operation == "hex" {
				radix = 2
			}

			den := new(big.Int).Exp(big.NewInt(int64(radix)), big.NewInt(int64(digits)), nil)

			integer, ok := new(big.Int).SetString(fmt.Sprint(a), 10)
			if !ok {
				rt.Fatal("integer did not have a decimal representation")
			}

			num := new(big.Int).Mul(integer, den)
			num.Add(num, big.NewInt(int64(side)))

			if radix == 10 {
				word = new(big.Rat).SetFrac(num, den).FloatString(digits)
			} else {
				sign := num.Sign()

				word = "0x" + num.Abs(num).Text(16) + "p-" + strconv.Itoa(digits)
				if sign < 0 {
					word = "-" + word
				}
			}
		}

		for _, op := range []string{"=", "<", ">"} {
			want := (op == "=" && side == 0) || (op == "<" && side > 0) || (op == ">" && side < 0)

			filter, err := cols.ParseFilter("count" + op + word)
			if err != nil {
				rt.Fatal(err)
			}

			got, err := filter.Match(wholeNumberRow[N]{Count: &a}, at)
			if err != nil || got != want {
				rt.Fatalf("count=%v, count%s%s matched=%t err=%v want=%t", a, op, word, got, err, want)
			}
		}
	})
}

func absDigit(v int) int {
	if v < 0 {
		return -v
	}

	return v
}
