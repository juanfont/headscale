package config

import (
	"cmp"
	"context"
	"maps"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// fileFormats are the formats a configuration can be written in.
var fileFormats = []string{".yaml", ".json", ".hujson"}

// fakeProvider is a Go-only DNS provider.
type fakeProvider struct{ Token string }

func (fakeProvider) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func (fakeProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// TestMarshalRedacts: what Marshal prints holds no credential, in any
// format: a literal secret, a DNS provider setting of any shape, URL
// userinfo, in URL and plain string keys alike, and nothing set only from
// Go. The running values keep theirs.
func TestMarshalRedacts(t *testing.T) {
	tests := []struct {
		name     string
		provider map[string]any
		hidden   []string
		shown    []string
	}{
		{
			name:     "string token",
			provider: map[string]any{"name": "cloudflare", "api_token": "marker-api-token"},
			hidden:   []string{"marker-api-token"},
			shown:    []string{"cloudflare"},
		},
		{
			name:     "numeric token",
			provider: map[string]any{"name": "cloudflare", "api_token": 123456},
			hidden:   []string{"123456"},
			shown:    []string{"cloudflare"},
		},
		{
			name: "nested registration",
			provider: map[string]any{"name": "acmedns", "config": map[string]any{
				"laptop.example.com": map[string]any{
					"username":   "marker-user",
					"password":   "marker-registration-password",
					"subdomain":  "marker-subdomain",
					"server_url": "https://auth.acme-dns.io",
				},
			}},
			hidden: []string{"marker-user", "marker-registration-password", "marker-subdomain"},
			shown:  []string{"acmedns"},
		},
		{
			name:     "file reference",
			provider: map[string]any{"name": "cloudflare", "api_token": "file:/run/credentials/cloudflare"}, //nolint:gosec // a file reference, not a credential
			shown:    []string{"cloudflare", "file:/run/credentials/cloudflare"},
		},
	}

	for _, tt := range tests {
		for _, ext := range fileFormats {
			t.Run(tt.name+ext, func(t *testing.T) {
				cfg := Default()
				cfg.ServerURL = "https://marker-server-user:marker-server-pass@headscale.example.com" //nolint:gosec // test markers, not credentials
				cfg.CLI.Address = "https://marker-cli-user@cli.example.com"
				cfg.DNSConfig.Nameservers.Global = []string{"1.1.1.1", "https://marker-dns-user:marker-dns-pass@dns.example.com/dns-query"}
				cfg.DNSConfig.Nameservers.Split = map[string][]string{"corp.example.com": {"https://marker-split-user@dns.example.com/q"}}
				cfg.OIDC.ClientSecret = "marker-oidc-secret"
				cfg.OIDC.Issuer = "https://marker-issuer-user:marker-issuer-pass@idp.example.com"
				cfg.Database.Postgres.Pass = "marker-pg-pass"
				cfg.CLI.APIKey = "file:/run/credentials/cli_key"
				cfg.TLS.ACME.URL = "https://marker-acme-user@acme.example.com/dir"
				cfg.DERP.URLs = []types.HTTPURL{"https://marker-derp-user:marker-derp-pass@derp.example.com/map"}
				cfg.DERP.DERPMap = &tailcfg.DERPMap{Regions: map[tailcfg.DERPRegionID]*tailcfg.DERPRegion{
					900: {RegionID: 900, RegionName: "marker-derpmap"},
				}}
				cfg.DNSConfig.Challenge.ProviderSettings = maps.Clone(tt.provider)
				cfg.DNSConfig.Challenge.Provider = fakeProvider{Token: "marker-go-provider"} //nolint:gosec // a test marker, not a credential

				out, err := Marshal(&cfg, ext)
				require.NoError(t, err)

				for _, h := range append([]string{
					"marker-oidc-secret", "marker-issuer-user", "marker-issuer-pass", "marker-pg-pass",
					"marker-acme-user", "marker-derp-user", "marker-derp-pass",
					"marker-derpmap", "marker-go-provider",
					"marker-server-user", "marker-server-pass", "marker-cli-user",
					"marker-dns-user", "marker-dns-pass", "marker-split-user",
				}, tt.hidden...) {
					assert.NotContains(t, string(out), h)
				}

				for _, s := range append([]string{
					"file:/run/credentials/cli_key", "idp.example.com", "derp.example.com",
					"https://headscale.example.com", "https://cli.example.com", "1.1.1.1",
					"https://dns.example.com/dns-query", "https://dns.example.com/q",
				}, tt.shown...) {
					assert.Contains(t, string(out), s)
				}

				assert.Contains(t, cfg.ServerURL, "marker-server-pass")
				assert.Contains(t, cfg.CLI.Address, "marker-cli-user")
				assert.Contains(t, cfg.DNSConfig.Nameservers.Global[1], "marker-dns-pass")
				assert.Contains(t, cfg.DNSConfig.Nameservers.Split["corp.example.com"][0], "marker-split-user")
			})
		}
	}
}

// TestMarshalRedactsServerURL: server_url is a string, not an HTTPURL, but
// its userinfo is as secret; a value whose userinfo cannot be told from the
// rest is withheld whole. The raw map, as the round trip writes it, keeps
// the value.
func TestMarshalRedactsServerURL(t *testing.T) {
	for _, tt := range []struct {
		serverURL string
		shown     string // "" when withheld
	}{
		{serverURL: "https://headscale.example.com", shown: "https://headscale.example.com"},
		{serverURL: "https://marker-user:marker-pass@headscale.example.com", shown: "https://headscale.example.com"}, //nolint:gosec // test markers, not credentials
		{serverURL: "https://marker-user@headscale.example.com", shown: "https://headscale.example.com"},
		{serverURL: "https://marker-user:marker-pass@headscale.example.com/%zz"}, //nolint:gosec // test markers, not credentials
		{serverURL: "https://alice:marker-pass?@headscale.example.com"},
		{serverURL: "https://alice:marker-pass#@headscale.example.com"},
		{serverURL: "https://alice:marker-pass@headscale.example.com:port"},
		{serverURL: "https:/alice:marker-pass@headscale.example.com"},
	} {
		for _, ext := range fileFormats {
			t.Run(tt.serverURL+ext, func(t *testing.T) {
				cfg := Default()
				cfg.ServerURL = tt.serverURL

				out, err := Marshal(&cfg, ext)
				require.NoError(t, err)
				assert.NotContains(t, string(out), "marker")

				assert.Contains(t, string(out), tt.shown)
				assert.Equal(t, cmp.Or(tt.shown, "<redacted>"), plainMap(&cfg, true)["server_url"])
				assert.Equal(t, tt.serverURL, plainMap(&cfg, false)["server_url"])
				assert.Equal(t, tt.serverURL, cfg.ServerURL)
			})
		}
	}
}
