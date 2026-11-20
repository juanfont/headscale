package main

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestParseListener(t *testing.T) {
	t.Parallel()

	l, err := parseListener("443", "")
	require.NoError(t, err)
	assert.Equal(t, listener{port: 443, addr: ":443"}, l)

	l, err = parseListener("8443", "192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, listener{port: 8443, addr: "192.0.2.1:8443"}, l)

	l, err = parseListener("443=127.0.0.1:8443", "192.0.2.1")
	require.NoError(t, err)
	assert.Equal(t, listener{port: 443, addr: "127.0.0.1:8443"}, l)

	for _, bad := range []string{"", "0", "65536", "https", "x=127.0.0.1:1"} {
		_, err := parseListener(bad, "")
		assert.Error(t, err, bad)
	}
}
