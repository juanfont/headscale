package hscontrol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestGetCookieNameShortValue ensures a value shorter than the prefix length
// (e.g. a malformed nonce from a misbehaving IdP) does not panic with
// slice-out-of-range; it uses the available bytes instead.
func TestGetCookieNameShortValue(t *testing.T) {
	require.NotPanics(t, func() {
		assert.Equal(t, "nonce_ab", getCookieName("nonce", "ab"))
	})

	assert.Equal(t, "nonce_abcdef", getCookieName("nonce", "abcdef"))
	assert.Equal(t, "nonce_abcdef", getCookieName("nonce", "abcdefghij"))
}
