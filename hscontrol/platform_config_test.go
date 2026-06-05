package hscontrol

import (
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApplePlatformConfig_ServesProfilesViaChiRouter is the regression
// guard for issue juanfont/headscale#3296.
//
// The Apple profile download endpoints (`/apple/macos-app-store`,
// `/apple/macos-standalone`, `/apple/ios`) are registered on the chi
// router (see hscontrol/app.go: `r.Get("/apple/{platform}", ...)`).
// Before the fix, `ApplePlatformConfig` extracted the `{platform}` URL
// parameter via `mux.Vars(req)` from gorilla/mux; because the request
// never passed through a gorilla router, the lookup always missed and
// every download returned HTTP 400 `no platform specified`.
//
// This test mounts the route on a chi router exactly as production
// does so the assertion exercises the real router + handler wiring,
// not a hand-crafted chi context. It fails if the handler ever again
// reads URL parameters via an API the production router does not
// populate.
func TestApplePlatformConfig_ServesProfilesViaChiRouter(t *testing.T) {
	t.Parallel()

	h := &Headscale{
		cfg: &types.Config{
			ServerURL: "https://headscale.example.com",
		},
	}

	// Mirror the production mount in hscontrol/app.go so this test
	// covers the actual router + handler wiring, not a hand-crafted
	// chi context.
	r := chi.NewRouter()
	r.Get("/apple/{platform}", h.ApplePlatformConfig)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	platforms := []string{"macos-app-store", "macos-standalone", "ios"}
	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			t.Parallel()

			//nolint:noctx // test fixture
			resp, err := http.Get(srv.URL + "/apple/" + platform)
			require.NoError(t, err)
			t.Cleanup(func() { resp.Body.Close() })

			bodyBytes, _ := io.ReadAll(resp.Body)
			body := string(bodyBytes)

			assert.Equal(t, http.StatusOK, resp.StatusCode,
				"expected 200 for /apple/%s, got %d: %s",
				platform, resp.StatusCode, body)
			assert.Equal(t,
				"application/x-apple-aspen-config; charset=utf-8",
				resp.Header.Get("Content-Type"),
				"profile must be served as an Apple aspen config")
			assert.Contains(t, body,
				"https://headscale.example.com",
				"rendered profile must embed the configured ServerURL")
		})
	}
}

// TestApplePlatformConfig_RejectsUnknownPlatform locks the contract for
// the `default:` branch of `ApplePlatformConfig`: an otherwise-valid
// request whose `{platform}` segment is none of the three known values
// must return HTTP 400 with the documented message. This catches both
// silent fallthrough (e.g. a future template registered under a new
// name without adding a case) and accidental message drift.
func TestApplePlatformConfig_RejectsUnknownPlatform(t *testing.T) {
	t.Parallel()

	h := &Headscale{
		cfg: &types.Config{
			ServerURL: "https://headscale.example.com",
		},
	}

	r := chi.NewRouter()
	r.Get("/apple/{platform}", h.ApplePlatformConfig)

	srv := httptest.NewServer(r)
	t.Cleanup(srv.Close)

	//nolint:noctx // test fixture
	resp, err := http.Get(srv.URL + "/apple/windows-phone")
	require.NoError(t, err)
	t.Cleanup(func() { resp.Body.Close() })

	bodyBytes, _ := io.ReadAll(resp.Body)
	body := string(bodyBytes)

	assert.Equal(t, http.StatusBadRequest, resp.StatusCode,
		"unknown platform must be rejected with 400")
	assert.Contains(t, body,
		"platform must be ios, macos-app-store or macos-standalone",
		"error body must list the supported platforms")
}
