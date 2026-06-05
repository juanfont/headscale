package util

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestEncodeRandomURLSafeChecksErrorFirst ensures the URL-safe random string
// encoder returns ("", err) on an RNG failure instead of slicing the empty
// base64 of nil bytes and panicking.
func TestEncodeRandomURLSafeChecksErrorFirst(t *testing.T) {
	require.NotPanics(t, func() {
		s, err := encodeRandomURLSafe(nil, 32, assert.AnError)
		assert.Empty(t, s)
		require.Error(t, err)
	})

	s, err := encodeRandomURLSafe(bytes.Repeat([]byte{0x1}, 32), 32, nil)
	require.NoError(t, err)
	assert.Len(t, s, 32)
}
