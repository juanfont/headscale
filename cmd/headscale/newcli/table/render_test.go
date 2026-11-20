package table

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestRender(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, Render(&b, rows(), cols.Pick(nil), now))

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
