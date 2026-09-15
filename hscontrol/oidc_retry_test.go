package hscontrol

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/oauth2-proxy/mockoidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOIDCRetryFallsBackThenSwitchesOver(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	idp, err := mockoidc.NewServer(nil)
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC: types.OIDCConfig{
			OnlyStartIfOIDCIsAvailable: false,
			RetryInterval:              50 * time.Millisecond,
			Issuer:                     "http://" + addr + "/oidc",
			ClientID:                   idp.ClientID,
			ClientSecret:               idp.ClientSecret,
			Scope:                      []string{"openid", "profile", "email"},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	t.Cleanup(func() {
		if app.oidcRetryCancel != nil {
			app.oidcRetryCancel()
		}
	})

	_, isWeb := app.getAuthProvider().(*AuthProviderWeb)
	assert.True(t, isWeb)

	router := app.createRouter(nil, nil)

	// In fallback mode, /oidc/callback returns 404
	w := httptest.NewRecorder()
	req := httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback", nil)
	router.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNotFound, w.Code)

	newLn, err := net.Listen("tcp", addr)
	require.NoError(t, err)

	err = idp.Start(newLn, nil)
	require.NoError(t, err)

	t.Cleanup(func() {
		_ = idp.Shutdown()
	})

	assert.Eventually(t, func() bool {
		_, isOIDC := app.getAuthProvider().(*AuthProviderOIDC)

		return isOIDC
	}, 5*time.Second, 20*time.Millisecond)

	// After switchover, /oidc/callback is handled (not 404)
	w = httptest.NewRecorder()
	req = httptest.NewRequestWithContext(t.Context(), http.MethodGet, "/oidc/callback", nil)
	router.ServeHTTP(w, req)
	assert.NotEqual(t, http.StatusNotFound, w.Code)
}

func TestOIDCRetryDisabledByDefault(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	addr := ln.Addr().String()
	require.NoError(t, ln.Close())

	idp, err := mockoidc.NewServer(nil)
	require.NoError(t, err)

	tmpDir := t.TempDir()

	cfg := types.Config{
		ServerURL:           "http://localhost:8080",
		NoisePrivateKeyPath: tmpDir + "/noise_private.key",
		Database: types.DatabaseConfig{
			Type: "sqlite3",
			Sqlite: types.SqliteConfig{
				Path: tmpDir + "/headscale_test.db",
			},
		},
		OIDC: types.OIDCConfig{
			OnlyStartIfOIDCIsAvailable: false,
			RetryInterval:              0, // Retry disabled
			Issuer:                     "http://" + addr + "/oidc",
			ClientID:                   idp.ClientID,
			ClientSecret:               idp.ClientSecret,
			Scope:                      []string{"openid", "profile", "email"},
		},
		Policy: types.PolicyConfig{
			Mode: types.PolicyModeDB,
		},
		Tuning: types.Tuning{
			BatchChangeDelay: 100 * time.Millisecond,
			BatcherWorkers:   1,
		},
	}

	app, err := NewHeadscale(&cfg)
	require.NoError(t, err)

	_, isWeb := app.getAuthProvider().(*AuthProviderWeb)
	assert.True(t, isWeb)
	assert.Nil(t, app.oidcRetryCancel)
}
