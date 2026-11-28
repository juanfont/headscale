package hscontrol

import (
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
)

func TestAuthProviderWebAuthURL(t *testing.T) {
	const server = "https://hs.example.com"
	authID, err := types.AuthIDFromString("hskey-authreq-0123456789abcdef01234567")
	assert.NoError(t, err)

	t.Run("default pages on server", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "")
		assert.Equal(t, server+"/auth/"+authID.String(), a.AuthURL(authID))
		assert.Equal(t, server+"/register/"+authID.String(), a.RegisterURL(authID))
	})

	t.Run("external page carries hskey", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/hs-register.html")
		want := "https://api.example.com/hs-register.html?hskey=" + authID.String()
		assert.Equal(t, want, a.AuthURL(authID))
		assert.Equal(t, want, a.RegisterURL(authID))
	})

	t.Run("existing query string gets ampersand", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?mode=hs")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?mode=hs&hskey="+authID.String(), got)
	})

	t.Run("trailing question mark trimmed", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String(), got)
	})
}
