package table

import (
	"slices"
	"strconv"
	"testing"

	"pgregory.net/rapid"
)

// Bound: every valid version spells 1.9.0 or 1.10.0, so a comparator that
// drops the patch passes.
func TestRapidVersionOrder(t *testing.T) {
	versions := [][]string{
		{"1.9", "v1.9.0", "1.9-dev"},
		{"1.10", "v1.10.0", "1.10-build"},
		{"", "unknown"},
	}

	rapid.Check(t, func(rt *rapid.T) {
		ranks := rapid.SliceOfN(rapid.IntRange(0, len(versions)-1), 0, 48).
			Draw(rt, "release ranks")
		byRank := make([][]string, len(versions))

		rows := make([]row, len(ranks))
		for i, rank := range ranks {
			id := strconv.Itoa(i)
			rows[i] = row{
				ID:      id,
				Version: rapid.SampledFrom(versions[rank]).Draw(rt, "spelling"),
			}
			byRank[rank] = append(byRank[rank], id)
		}

		for _, key := range []string{"version", "-version"} {
			got := slices.Clone(rows)
			listCols.Sort(got, key, now)

			first, second := 0, 1
			if key == "-version" {
				first, second = second, first
			}

			want := slices.Concat(byRank[first], byRank[second], byRank[2])
			if !slices.Equal(ids(got), want) {
				fatalf(rt, "%s of %v: got IDs %v, want %v", key, ranks, ids(got), want)
			}
		}
	})
}
