package table

import (
	"bytes"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

func TestRender(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, Render(&b, rows(), cols.Pick(nil), now, nil))

	want := `ID  NAME     OWNER              IP                   ONLINE  LAST SEEN  EXPIRY
12  mynode   alice              100.64.0.1, fd7a::1  yes     now        in 89d
13  builder  tag:ci, tag:build  100.64.0.2           no      3d ago     never
`
	if diff := cmp.Diff(want, b.String()); diff != "" {
		t.Errorf("table (-want +got):\n%s", diff)
	}
}

// TestAligned: a column is as wide as its widest cell on the screen, a
// wide character taking two; only padding is left out at the end of a
// line, never what a cell holds.
func TestAligned(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, aligned(&b, [][]string{
		{"NAME", "OWNER", "NOTE"},
		{"🚀web", "alice", ""},
		{"\u65e5\u672c", "", "x  "},
		{"é", "bob", ""},
	}))
	require.Equal(
		t,
		"NAME   OWNER  NOTE\n🚀web  alice\n\u65e5\u672c          x  \né      bob\n",
		b.String(),
	)
	require.Equal(t, 5, width("🚀web"))
	require.Equal(t, 1, width("e\u0301"))
}

// TestScreen: on a terminal, a stacked list takes a line per entry, a cut
// list shows what fits and counts the rest, a wide character takes two
// cells, and colour marks the header, a cell with nothing and an expiry
// that has passed.
func TestScreen(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "id", Field: "id", Default: true},
		{Name: "name", Field: "name", Default: true},
		{
			Name:    "routes",
			Field:   "enabledRoutes",
			List:    Stacked,
			Fold:    Exit(),
			Default: true,
		},
		{Name: "nodes", Field: "nodes", List: Cut, Default: true},
	}
	require.NoError(t, cs.Check())

	nodes := make([]ref, 12)
	for i := range nodes {
		nodes[i] = ref{ID: strconv.Itoa(i), Name: "node" + strconv.Itoa(i)}
	}

	rs := []row{
		{
			ID:     "12",
			Name:   "mynode",
			Routes: []string{"10.0.0.0/8", "192.168.0.0/24"},
			Nodes:  nodes[:1],
		},
		{
			ID:     "14",
			Name:   "gateway🚀",
			Routes: []string{"0.0.0.0/0", "::/0"},
			Nodes:  nodes,
		},
		{ID: "15", Name: "x"},
	}

	show := func(width int, colour bool) string {
		var b bytes.Buffer
		require.NoError(
			t,
			Render(&b, rs, cs, now, &Screen{Width: width, Colour: colour}),
		)

		return b.String()
	}

	require.Equal(t, `ID  NAME       ROUTES          NODES
12  mynode     10.0.0.0/8      node0
               192.168.0.0/24
14  gateway🚀  exit            node0, node1, node2, node3, node4, node5, node6, node7, node8, node9, node10, node11
15  x
`, show(0, false), "no width cuts nothing")

	require.Equal(t, `ID  NAME       ROUTES          NODES
12  mynode     10.0.0.0/8      node0
               192.168.0.0/24
14  gateway🚀  exit            node0, node1, node2 … (+9)
15  x
`, show(60, false), "the cut list gives way first")

	require.Equal(t, `ID  NAME  ROUTES          NODES
12  myn…  10.0.0.0/8      node0
          192.168.0.0/24
14  gat…  exit            node0 … (+11)
15  x
`, show(28, false), "then the name, down to its header; an ID, a route and a list's first entry stay whole, and the line runs over")

	require.Equal(t, "\x1b[1mID\x1b[0m  \x1b[1mEXPIRY\x1b[0m  \x1b[1mHINT\x1b[0m\n"+
		"1   \x1b[31m2d ago\x1b[0m  \x1b[2m-\x1b[0m\n"+
		"2   in 2d   h\n", func() string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, []row{
			{ID: "1", Expiry: nullable.NewNullableWithValue(now.Add(-48 * time.Hour))},
			{
				ID:     "2",
				Expiry: nullable.NewNullableWithValue(now.Add(48 * time.Hour)),
				Inner: &struct {
					Hint string `json:"hint"`
				}{"h"},
			},
		}, Columns[row]{cols[0], cols[6], cols[8]}, now, &Screen{Colour: true}))

		return b.String()
	}())
}

// TestJoiningEdges pins the limit stated at width: a text that begins with
// a mark joining the space before it, or ends with a prepend character
// joining the space after it, is shown as it is, and each such join puts
// its row off by the library's count; the joins add up. Nothing changes the text to avoid it,
// so the screen, a pipe and every sort see the same bytes.
func TestJoiningEdges(t *testing.T) {
	t.Parallel()

	render := func(rs []row, cs Columns[row], screen *Screen) string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, rs, cs, now, screen))

		return b.String()
	}

	for _, tt := range []struct {
		name string
		cs   Columns[row]
		row  int // the row's width as the library counts it; the header's otherwise
		head int
	}{
		{"abcdefghijkl", Columns[row]{cols[0], cols[1]}, 16, 8},
		{"\uFE0Fabcdefghijkl", Columns[row]{cols[0], cols[1]}, 17, 8}, // its join takes the row to 17 on 16
		{"\u0301abcdefghijkl", Columns[row]{cols[0], cols[1]}, 16, 8},
		{"\u200Dabcdefghijkl", Columns[row]{cols[0], cols[1]}, 16, 8},
		{"abcdefghijk\u0600", Columns[row]{cols[1], cols[0]}, 13, 15}, // joins the padding after it: the ID left of its header
	} {
		rs := []row{{ID: "1", Name: tt.name}}
		screen := render(rs, tt.cs, &Screen{Width: 16})
		require.Equal(
			t,
			render(rs, tt.cs, nil),
			screen,
			"%q: the screen and a pipe write the same",
			tt.name,
		)
		require.Equal(
			t,
			tt.name,
			Visible(tt.name, ""),
			"%q: the text is not changed",
			tt.name,
		)

		lines := strings.Split(strings.TrimSuffix(screen, "\n"), "\n")
		require.Equal(
			t,
			[]int{tt.head, tt.row},
			[]int{width(lines[0]), width(lines[1])},
			"%q",
			tt.name,
		)
	}

	// Exact bytes, so a mark stripped, added or moved fails: a pipe, a
	// screen with room, and one narrow enough to cut the list.
	list := []ref{
		{ID: "1", Name: "alpha"},
		{ID: "2", Name: "\u0301bravo"},
		{ID: "3", Name: "\uFE0Fcharlie"},
		{ID: "4", Name: "delta"},
	}
	cs := Columns[row]{
		cols[0],
		{Name: "nodes", Field: "nodes", List: Cut, Default: true},
	}
	rs := []row{{ID: "1", Nodes: list}}
	whole := "ID  NODES\n1   alpha, \u0301bravo, \uFE0Fcharlie, delta\n"
	require.Equal(t, whole, render(rs, cs, nil), "a pipe")
	require.Equal(t, whole, render(rs, cs, &Screen{Width: 80}), "a screen with room")
	require.Equal(
		t,
		"ID  NODES\n1   alpha, \u0301bravo … (+2)\n",
		render(rs, cs, &Screen{Width: 26}),
		"a screen that cuts",
	)

	require.Equal(
		t,
		"aa, \uFE0Fabcdefghi",
		FitList([]string{"aa", "\uFE0Fabcdefghi"}, 13),
		"its join takes it to 14 on 13",
	)
	require.Equal(
		t,
		"aa, \u0301abcdefghi",
		FitList([]string{"aa", "\u0301abcdefghi"}, 13),
	)

	// Joins add up: three entries that each join the space before them
	// take a list measured at 10 to 13.
	joining := []string{"\uFE0Fa", "\uFE0Fa", "\uFE0Fa", "\uFE0Fa"}
	require.Equal(t, strings.Join(joining, ", "), FitList(joining, 10))
	require.Equal(t, 13, width(FitList(joining, 10)))
}

func TestHangulCell(t *testing.T) {
	t.Parallel()

	const decomposed = "\u1100\u1161"
	require.Equal(t, width("가"), width(decomposed))
	require.Equal(t, decomposed+"…", fit(decomposed+"ab", 3))
}

func TestEmojiPresentation(t *testing.T) {
	t.Parallel()
	require.Equal(t, 1, width("🖥"))
	require.Equal(t, 2, width("🖥️"))
	require.Equal(t, "🖥x", fit("🖥x", 2))
	require.Equal(t, "…", fit("🖥️x", 2))
}

func TestFit(t *testing.T) {
	t.Parallel()

	require.Equal(t, "abc", fit("abc", 3))
	require.Equal(t, "ab…", fit("abcd", 3))
	require.Equal(t, "🚀…", fit("🚀🚀", 3), "a wide character is two cells")
	require.Equal(t, "aa … (+2)", FitList([]string{"aa", "bb", "cccc"}, 11))
	require.Equal(t, "… (+3)", FitList([]string{"aaaa", "b", "c"}, 6))
	require.Equal(t, "(+…", FitList([]string{"aaaa", "b", "c"}, 3))
}

// TestFitListLinear: a long list is cut in one pass; a join per cut made
// tens of megabytes for one cell of two thousand entries.
func TestFitListLinear(t *testing.T) {
	entries := make([]string, 2000)
	for i := range entries {
		entries[i] = fmt.Sprintf("node-%04d", i)
	}

	require.Equal(t, "node-0000 … (+1999)", FitList(entries, 24))
	require.LessOrEqual(
		t,
		testing.AllocsPerRun(10, func() { FitList(entries, 24) }),
		8.0,
	)

	for i := range entries {
		entries[i] = "\u0301" + entries[i]
	}

	require.LessOrEqual(
		t,
		testing.AllocsPerRun(10, func() { FitList(entries, 24) }),
		8.0,
		"entries that begin with a mark cost no more",
	)
}

// TestCutOrder: a table wider than the screen gives way in one order. A
// list loses whole entries first, then text is cut, the name and the owner
// last; an ID, a time and a bool are never cut.
func TestCutOrder(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "id", Field: "id", Default: true},
		{Name: "name", Field: "name", Default: true},
		{Name: "owner", Field: "owner", Default: true},
		{Name: "ip", Field: "addresses", Default: true},
		{Name: "hint", Field: "inner.hint", Default: true},
		{Name: "online", Field: "online", Default: true},
		{Name: "expiry", Field: "expiry", Default: true},
	}

	rs := rows()
	rs[0].ID, rs[0].Name = "123456", "a-rather-long-node-name"
	rs[1].Inner = &struct {
		Hint string `json:"hint"`
	}{"a hint of some length"}

	show := func(width int) string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, rs, cs, now, &Screen{Width: width}))

		return b.String()
	}

	for _, tt := range []struct {
		width int
		want  string
	}{
		{0, `ID      NAME                     OWNER              IP                   HINT                   ONLINE  EXPIRY
123456  a-rather-long-node-name  alice              100.64.0.1, fd7a::1  -                      yes     in 89d
13      builder                  tag:ci, tag:build  100.64.0.2           a hint of some length  no      never
`},
		// The list gives way first, then the text down to its header, and
		// only then the name.
		{90, `ID      NAME                    OWNER              IP                 HINT  ONLINE  EXPIRY
123456  a-rather-long-node-na…  alice              100.64.0.1 … (+1)  -     yes     in 89d
13      builder                 tag:ci, tag:build  100.64.0.2         a h…  no      never
`},
		// The owner's tags give way by whole tags, as a list does.
		{70, `ID      NAME    OWNER          IP                 HINT  ONLINE  EXPIRY
123456  a-rat…  alice          100.64.0.1 … (+1)  -     yes     in 89d
13      build…  tag:ci … (+1)  100.64.0.2         a h…  no      never
`},
		// Past every floor the line runs over: an ID and a time stay whole.
		{40, `ID      NAME  OWNER          IP                 HINT  ONLINE  EXPIRY
123456  a-r…  alice          100.64.0.1 … (+1)  -     yes     in 89d
13      bui…  tag:ci … (+1)  100.64.0.2         a h…  no      never
`},
	} {
		require.Equal(t, tt.want, show(tt.width), "width %d", tt.width)
	}
}
