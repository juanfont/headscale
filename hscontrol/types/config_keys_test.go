package types

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tailscale/hujson"
)

func TestKeyPosition(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		path      []string
		line, col int
		ok        bool
	}{
		{"yaml nested", "a: 1\nserver:\n  Foo: 2\n", []string{"server", "foo"}, 3, 3, true},
		{"json", "{\n  \"a\": 1,\n  \"b\": {\n    \"c\": 2\n  }\n}\n", []string{"b", "c"}, 4, 5, true},
		{"duplicate parent", `{"dns":{"magic_dns":true},"dns":{"magic_dsn":true}}`, []string{"dns", "magic_dsn"}, 1, 34, true},
		{"duplicate leaf", "{\n\"a\": 1,\n\"a\": 2\n}", []string{"a"}, 3, 1, true},
		{"missing", "a: 1\n", []string{"a", "b"}, 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, col, ok := keyPosition([]byte(tt.src), tt.path)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.line, line)
			assert.Equal(t, tt.col, col)
		})
	}

	t.Run("hujson comments", func(t *testing.T) {
		src := "{\n  // c\n  /* d */\n  \"a\": 1,\n  \"b\": 2, // x\n}\n"

		b, err := hujson.Standardize([]byte(src))
		require.NoError(t, err)

		line, _, ok := keyPosition(b, []string{"b"})
		assert.True(t, ok)
		assert.Equal(t, 5, line)
	})
}
