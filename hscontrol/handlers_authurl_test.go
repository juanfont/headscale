package hscontrol

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"

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
	})

	t.Run("existing query string gets ampersand", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?mode=hs")
		got := a.AuthURL(authID)
		// Encode() sorts params; order is semantically irrelevant.
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String()+"&mode=hs", got)
	})

	t.Run("trailing question mark trimmed", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String(), got)
	})

	t.Run("fragment stays after the query", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/register#login")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/register?hskey="+authID.String()+"#login", got)
	})

	t.Run("query and fragment together", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?mode=hs#login")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String()+"&mode=hs#login", got)
	})

	t.Run("configured hskey is replaced", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/p?hskey=old")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String(), got)
	})

	t.Run("non-http value behaves as unset", func(t *testing.T) {
		// config.Validate rejects these at startup; the provider stays
		// safe even if handed one directly.
		for _, bad := range []string{"javascript:alert(1)", "/relative/path", "not a url"} {
			a := NewAuthProviderWeb(server, bad)
			assert.Equal(t, server+"/auth/"+authID.String(), a.AuthURL(authID))
		}
	})

	t.Run("surrounding whitespace trimmed", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "  https://api.example.com/p  ")
		got := a.AuthURL(authID)
		assert.Equal(t, "https://api.example.com/p?hskey="+authID.String(), got)
	})
}

func TestAuthProviderWebRegisterRedirect(t *testing.T) {
	const server = "https://hs.example.com"
	authID, err := types.AuthIDFromString("hskey-authreq-0123456789abcdef01234567")
	assert.NoError(t, err)

	request := func() *http.Request {
		rc := chi.NewRouteContext()
		rc.URLParams.Add("auth_id", authID.String())
		req := httptest.NewRequest(http.MethodGet, "/register/"+authID.String(), nil)
		return req.WithContext(context.WithValue(req.Context(), chi.RouteCtxKey, rc))
	}

	t.Run("browser hits redirect to external page", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "https://api.example.com/hs-register.html")
		w := httptest.NewRecorder()
		a.RegisterHandler(w, request())
		assert.Equal(t, http.StatusFound, w.Code)
		assert.Equal(t,
			"https://api.example.com/hs-register.html?hskey="+authID.String(),
			w.Header().Get("Location"))
	})

	t.Run("no external page keeps built-in page", func(t *testing.T) {
		a := NewAuthProviderWeb(server, "")
		w := httptest.NewRecorder()
		a.RegisterHandler(w, request())
		assert.Equal(t, http.StatusOK, w.Code)
		assert.Contains(t, w.Body.String(), authID.String())
	})
}
