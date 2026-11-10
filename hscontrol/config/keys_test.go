package config

import (
	"strings"
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
			line, col, ok := keyPosition(keyTree([]byte(tt.src)), tt.path)
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.line, line)
			assert.Equal(t, tt.col, col)
		})
	}

	t.Run("hujson comments", func(t *testing.T) {
		src := "{\n  // c\n  /* d */\n  \"a\": 1,\n  \"b\": 2, // x\n}\n"

		b, err := hujson.Standardize([]byte(src))
		require.NoError(t, err)

		line, _, ok := keyPosition(keyTree(b), []string{"b"})
		assert.True(t, ok)
		assert.Equal(t, 5, line)
	})
}

func TestDottedPosition(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		path      string
		line, col int
		ok        bool
	}{
		{"nested", "dns:\n  magic_dsn: true\n", "dns.magic_dsn", 2, 3, true},
		{"dotted", "a: 1\ndns.magic_dsn: true\n", "dns.magic_dsn", 2, 1, true},
		{"mixed", "dns:\n  extra.x: 1\n", "dns.extra.x", 2, 3, true},
		// The surviving dns lacks the key; the shadowed one's copy was
		// never loaded, so the dotted spelling is the one that set it.
		{
			"shadowed duplicate parent",
			"{\n\"dns.magic_dsn\": 1,\n\"dns\": {\"magic_dsn\": 1},\n\"dns\": {\"x\": 1}\n}",
			"dns.magic_dsn", 2, 1, true,
		},
		{"only in shadowed parent", `{"dns":{"magic_dsn":1},"dns":{"x":1}}`, "dns.magic_dsn", 0, 0, false},
		{"missing", "a: 1\n", "a.b", 0, 0, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			line, col, ok := dottedPosition(keyTree([]byte(tt.src)), strings.Split(tt.path, "."))
			assert.Equal(t, tt.ok, ok)
			assert.Equal(t, tt.line, line)
			assert.Equal(t, tt.col, col)
		})
	}
}

// TestRemovedKeysAgainstSchema: a removed key is not a key, and what
// replaces it is.
func TestRemovedKeysAgainstSchema(t *testing.T) {
	leaf, branch := configKeySets()

	for _, r := range removedKeys {
		assert.Falsef(t, leaf[r.Old] || branch[r.Old], "removed key %s is a key", r.Old)

		for k := range strings.FieldsSeq(r.New) {
			assert.Truef(t, leaf[k] || branch[k], "%s replaces %s but is no key", k, r.Old)
		}
	}
}
