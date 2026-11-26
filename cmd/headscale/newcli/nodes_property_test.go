package newcli

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline/argtest"
	"pgregory.net/rapid"
)

type queryNode struct{ ID, Name, Hostname, OS string }

func (n queryNode) value(column string) string {
	switch column {
	case "name":
		return n.Name
	case "hostname":
		return n.Hostname
	case "os":
		return n.OS
	default:
		panic("unknown model column " + column)
	}
}

// Bound: every drawn OS substring is a prefix, and wire values shared by
// both reads pass.
func TestRapidNodeQuery(t *testing.T) {
	f := newFixture(t, false)
	fleet(t, f)
	control := f.run(t, cliCase{args: "nodes list -o json", pageSize: 10})

	var page struct{ Nodes []queryNode }
	if control.code != 0 || len(control.answers[nodesPath]) != 1 ||
		json.Unmarshal(control.answers[nodesPath][0], &page) != nil ||
		len(page.Nodes) != 5 {
		t.Fatalf(
			"fleet control: exit=%d pages=%d stderr=%q",
			control.code,
			len(control.answers[nodesPath]),
			control.stderr,
		)
	}

	columns := rapid.SampledFrom([]string{"name", "hostname", "os"})

	var none, single, multiple, tied, crossedPages int

	rapid.Check(t, func(rt *rapid.T) {
		want := slices.Clone(page.Nodes)

		count := rapid.IntRange(0, 2).Draw(rt, "predicates")

		filters := make([]string, 0, count)
		for range count {
			column := columns.Draw(rt, "filter column")
			row := rapid.SampledFrom(page.Nodes).Draw(rt, "reference row")
			value := row.value(column)

			op := rapid.SampledFrom([]string{"=", ":"}).Draw(rt, "operator")
			if op == ":" {
				value = value[:rapid.IntRange(1, len(value)).Draw(rt, "prefix length")]
			}

			if rapid.Bool().Draw(rt, "absent value") {
				value += "-absent"
			}

			filters = append(filters, column+op+value)
			want = slices.DeleteFunc(want, func(n queryNode) bool {
				text := n.value(column)
				if op == ":" {
					return !strings.Contains(text, value)
				}

				return text != value
			})
		}

		if len(filters) == 2 && rapid.Bool().Draw(rt, "combine filters") {
			filters = []string{strings.Join(filters, ",")}
		}

		order := columns.Draw(rt, "sort column")
		reverse := rapid.Bool().Draw(rt, "descending")

		slices.SortStableFunc(want, func(a, b queryNode) int {
			if reverse {
				a, b = b, a
			}

			return strings.Compare(a.value(order), b.value(order))
		})

		key := order
		if reverse {
			key = "-" + key
		}

		leaf := rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "leaf")

		options := make([][]string, 0, 2+len(filters))

		options = append(
			options,
			[]string{"-o", "json"},
			argtest.Option(rt, "--sort", key),
		)
		for _, filter := range filters {
			options = append(options, argtest.Option(rt, "--filter", filter))
		}

		args := append(
			[]string{"nodes", leaf},
			argtest.Interleave(rt, nil, options...)...)
		size := rapid.IntRange(1, len(page.Nodes)+1).Draw(rt, "page size")
		r := f.run(t, cliCase{args: strings.Join(args, " "), pageSize: size})

		var got []queryNode
		if r.code != 0 || r.stderr != "" ||
			json.Unmarshal([]byte(r.stdout), &got) != nil ||
			got == nil ||
			!slices.Equal(got, want) {
			fatalf(
				rt,
				"argv=%q pageSize=%d exit=%d stderr=%q rows=%v want=%v",
				args,
				size,
				r.code,
				r.stderr,
				got,
				want,
			)
		}

		wire := make([]queryNode, 0, len(page.Nodes))

		for i, body := range r.answers[nodesPath] {
			var result struct{ Nodes []queryNode }
			if json.Unmarshal(body, &result) != nil || len(result.Nodes) == 0 ||
				len(result.Nodes) > size {
				fatalf(rt, "page %d: invalid rows for size %d", i, size)
			}

			wire = append(wire, result.Nodes...)
		}

		if !slices.Equal(wire, page.Nodes) {
			fatalf(rt, "argv=%q API walk=%v want=%v", args, wire, page.Nodes)
		}

		switch len(want) {
		case 0:
			none++
		case 1:
			single++
		default:
			multiple++
		}

		for i := 1; i < len(want); i++ {
			if want[i-1].value(order) == want[i].value(order) {
				tied++
				break
			}
		}

		if len(r.answers[nodesPath]) > 1 {
			crossedPages++
		}
	})
	t.Logf(
		"model classes empty-queries=%d single-row=%d multiple-rows=%d tied-sort=%d paginated=%d",
		none,
		single,
		multiple,
		tied,
		crossedPages,
	)
}
