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
			require.NoError(t, Sheet(&b, tt.row, cols, now))

			if diff := cmp.Diff(tt.want, b.String()); diff != "" {
				t.Errorf("sheet (-want +got):\n%s", diff)
			}
		})
	}
}
