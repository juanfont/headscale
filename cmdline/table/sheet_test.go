package table

import (
	"bytes"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/stretchr/testify/require"
)

func TestSheet(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		row  row
		want string
	}{
		{
			name: "user owner",
			row:  rows()[0],
			want: `ID:         12
Name:       mynode
Owner:      User 3 (alice)
IP:         100.64.0.1, fd7a::1
Online:     yes
Last seen:  now (2026-11-10 09:14 UTC)
Expiry:     in 89d (2027-02-07 10:14 UTC)
Count:      0
Hint:       -
`,
		},
		{
			name: "a null field has its line",
			row:  rows()[1],
			want: `ID:         13
Name:       builder
Owner:      tag:ci, tag:build
IP:         100.64.0.2
Online:     no
Last seen:  3d ago (2026-11-07 09:13 UTC)
Expiry:     never
Count:      0
Hint:       -
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var b bytes.Buffer
			require.NoError(t, Sheet(&b, tt.row, cols, nil, now))

			if diff := cmp.Diff(tt.want, b.String()); diff != "" {
				t.Errorf("sheet (-want +got):\n%s", diff)
			}
		})
	}
}

// TestSheetBlock: a block follows the lines, its keys in order and made
// visible; an empty map has none. A block has a title and a field of its
// own.
func TestSheetBlock(t *testing.T) {
	t.Parallel()

	blocks := Blocks[row]{{Title: "Attributes", Field: "attributes"}}
	require.NoError(t, blocks.Check())
	require.EqualError(
		t,
		Blocks[row]{{Title: "X", Field: "name"}}.Check(),
		`block "X": field "name": string is no map with text keys`,
	)
	require.EqualError(
		t,
		Blocks[row]{{Title: "X", Field: "nope"}}.Check(),
		`block "X": unknown field "nope" in table.row`,
	)
	require.EqualError(
		t,
		Blocks[row]{{Field: "attributes"}}.Check(),
		`field "attributes": a block with no title`,
	)
	require.EqualError(
		t,
		Blocks[row]{
			{Title: "A", Field: "attributes"},
			{Title: "A", Field: "nope"},
		}.Check(),
		`block "A" is the title of two blocks`,
	)
	require.EqualError(
		t,
		Blocks[row]{
			{Title: "A", Field: "attributes"},
			{Title: "B", Field: "attributes"},
		}.Check(),
		`block "B": field "attributes" is the field of two blocks`,
	)

	var b bytes.Buffer
	require.NoError(
		t,
		Sheet(
			&b,
			row{
				ID: "1",
				Attrs: map[string]string{
					"ip:publicAddress": "203.0.113.7",
					"b\nx":             "v\x1b",
				},
			},
			cols[:1],
			blocks,
			now,
		),
	)
	require.Equal(
		t,
		"ID:  1\n\nAttributes:\n  b\\x0ax             v\\x1b\n  ip:publicAddress   203.0.113.7\n",
		b.String(),
	)

	b.Reset()
	require.NoError(t, Sheet(&b, row{ID: "1"}, cols[:1], blocks, now))
	require.Equal(t, "ID:  1\n", b.String())
}
