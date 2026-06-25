package hscontrol

import (
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/google/go-cmp/cmp"
	apiv2 "github.com/juanfont/headscale/hscontrol/api/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// settingsAPIWithConfig registers the v2 API over a Backend carrying cfg and a
// zero State — the settings GET reads only b.Cfg, so the other handlers (which
// would need State) are simply never hit.
func settingsAPIWithConfig(t *testing.T, cfg *types.Config) humatest.TestAPI {
	t.Helper()

	_, api := humatest.New(t, apiv2.Config())
	apiv2.Register(api, apiv2.Backend{Cfg: cfg})

	return api
}

func getSettings(t *testing.T, api humatest.TestAPI) apiv2.TailnetSettings {
	t.Helper()

	resp := api.Get("/api/v2/tailnet/-/settings")
	require.Equalf(t, http.StatusOK, resp.Code, "body: %s", resp.Body)

	var s apiv2.TailnetSettings
	require.NoError(t, json.Unmarshal(resp.Body.Bytes(), &s))

	return s
}

// TestAPIv2SettingsComputedFields validates the GET mapping for each field that
// is computed from config — the branches the default-config roundtrip never
// exercises. Expectations live in struct fields, not name branches.
func TestAPIv2SettingsComputedFields(t *testing.T) {
	tests := []struct {
		name                string
		cfg                 types.Config
		wantHTTPS           bool
		wantKeyDurationDays int
		wantACLsExtManaged  bool
	}{
		{
			name: "defaults",
			cfg:  types.Config{},
		},
		{
			name:      "https via cert path",
			cfg:       types.Config{TLS: types.TLSConfig{CertPath: "/x/cert.pem"}},
			wantHTTPS: true,
		},
		{
			name: "https via letsencrypt",
			cfg: types.Config{
				TLS: types.TLSConfig{LetsEncrypt: types.LetsEncryptConfig{Hostname: "hs.example.com"}},
			},
			wantHTTPS: true,
		},
		{
			name:                "key duration 7d",
			cfg:                 types.Config{Node: types.NodeConfig{Expiry: 7 * 24 * time.Hour}},
			wantKeyDurationDays: 7,
		},
		{
			name:                "key duration 90d",
			cfg:                 types.Config{Node: types.NodeConfig{Expiry: 90 * 24 * time.Hour}},
			wantKeyDurationDays: 90,
		},
		{
			name:                "key duration truncates",
			cfg:                 types.Config{Node: types.NodeConfig{Expiry: 36 * time.Hour}},
			wantKeyDurationDays: 1,
		},
		{
			name:               "acls externally managed in file mode",
			cfg:                types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile}},
			wantACLsExtManaged: true,
		},
		{
			name: "acls db mode",
			cfg:  types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeDB}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := getSettings(t, settingsAPIWithConfig(t, &tt.cfg))

			assert.Equal(t, tt.wantHTTPS, s.HTTPSEnabled)
			assert.Equal(t, tt.wantKeyDurationDays, s.DevicesKeyDurationDays)
			assert.Equal(t, tt.wantACLsExtManaged, s.ACLsExternallyManagedOn)
			assert.Equal(t, "none", s.UsersRoleAllowedToJoinExternalTailnets)
		})
	}
}

// TestAPIv2SettingsConstantOffFields pins the hardcoded-off fields:
// even with every config knob set, they must not pick up signal.
func TestAPIv2SettingsConstantOffFields(t *testing.T) {
	cfg := types.Config{
		TLS:    types.TLSConfig{CertPath: "/x/cert.pem"},
		Node:   types.NodeConfig{Expiry: 90 * 24 * time.Hour},
		Policy: types.PolicyConfig{Mode: types.PolicyModeFile},
	}

	s := getSettings(t, settingsAPIWithConfig(t, &cfg))

	// Only the four computed fields reflect cfg; everything else stays off.
	want := apiv2.TailnetSettings{
		ACLsExternallyManagedOn:                true,
		DevicesKeyDurationDays:                 90,
		HTTPSEnabled:                           true,
		UsersRoleAllowedToJoinExternalTailnets: "none",
	}
	if diff := cmp.Diff(want, s); diff != "" {
		t.Errorf("settings mismatch (-want +got):\n%s", diff)
	}
}

// TestAPIv2SettingsPatchUnsupported confirms writes are rejected and inert.
func TestAPIv2SettingsPatchUnsupported(t *testing.T) {
	app := createTestApp(t)
	api := registerAPIV2(t, app)

	patch := api.Patch("/api/v2/tailnet/-/settings", map[string]any{"devicesApprovalOn": true})
	assert.Equal(t, http.StatusNotImplemented, patch.Code)
	assert.Contains(t, patch.Body.String(), `"message"`)

	// The rejected PATCH did not mutate anything.
	assert.False(t, getSettings(t, api).DevicesApprovalOn)
}

// TestAPIv2SettingsNonDefaultTailnet404 — the tailnet check runs before the
// 501, so a bad tailnet is 404 on both verbs.
func TestAPIv2SettingsNonDefaultTailnet404(t *testing.T) {
	api := settingsAPIWithConfig(t, &types.Config{})

	assert.Equal(t, http.StatusNotFound, api.Get("/api/v2/tailnet/example.com/settings").Code)
	assert.Equal(t, http.StatusNotFound,
		api.Patch("/api/v2/tailnet/example.com/settings", map[string]any{}).Code)
}
