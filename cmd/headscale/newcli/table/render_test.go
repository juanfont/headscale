package table

import (
	"bytes"
	"strconv"
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
	require.Equal(t, "NAME   OWNER  NOTE\n🚀web  alice\n\u65e5\u672c          x  \né      bob\n", b.String())
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
		{Name: "routes", Field: "enabledRoutes", List: Stacked, Fold: Exit(), Default: true},
		{Name: "nodes", Field: "nodes", List: Cut, Default: true},
	}
	require.NoError(t, cs.Check())

	nodes := make([]ref, 12)
	for i := range nodes {
		nodes[i] = ref{ID: strconv.Itoa(i), Name: "node" + strconv.Itoa(i)}
	}

	rs := []row{
		{ID: "12", Name: "mynode", Routes: []string{"10.0.0.0/8", "192.168.0.0/24"}, Nodes: nodes[:1]},
		{ID: "14", Name: "gateway🚀", Routes: []string{"0.0.0.0/0", "::/0"}, Nodes: nodes},
		{ID: "15", Name: "x"},
	}

	show := func(width int, colour bool) string {
		var b bytes.Buffer
		require.NoError(t, Render(&b, rs, cs, now, &Screen{Width: width, Colour: colour}))

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
			{ID: "2", Expiry: nullable.NewNullableWithValue(now.Add(48 * time.Hour)), Inner: &struct {
				Hint string `json:"hint"`
			}{"h"}},
		}, Columns[row]{cols[0], cols[6], cols[8]}, now, &Screen{Colour: true}))

		return b.String()
	}())
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
