package dns

import (
	"os"
	"path/filepath"
	"testing"

	gigahost "github.com/kradalby/libdns-gigahost"
	"github.com/libdns/cloudflare"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/powerdns"
	"github.com/libdns/rfc2136"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func noEnv(string) (any, bool) { return nil, false }

func TestNewProvider(t *testing.T) {
	secret := filepath.Join(t.TempDir(), "token")
	require.NoError(t, os.WriteFile(secret, []byte("from-file\n"), 0o600))

	tests := []struct {
		name     string
		provider string
		settings map[string]any
		want     Provider
		wantErr  error
	}{
		{
			name:     "cloudflare from settings",
			provider: "cloudflare",
			settings: map[string]any{"name": "cloudflare", "api_token": "tok"},
			want:     &cloudflare.Provider{APIToken: "tok"},
		},
		{
			name:     "name is case insensitive",
			provider: "CloudFlare",
			settings: map[string]any{"api_token": "tok"},
			want:     &cloudflare.Provider{APIToken: "tok"},
		},
		{
			name:     "rfc2136",
			provider: "rfc2136",
			settings: map[string]any{
				"server":   "ns1.example.com:53",
				"key_name": "headscale",
				"key_alg":  "hmac-sha256",
				"key":      "c2VjcmV0",
			},
			want: &rfc2136.Provider{
				Server:  "ns1.example.com:53",
				KeyName: "headscale",
				KeyAlg:  "hmac-sha256",
				Key:     "c2VjcmV0",
			},
		},
		{
			name:     "secret from path",
			provider: "cloudflare",
			settings: map[string]any{"api_token_path": secret},
			want:     &cloudflare.Provider{APIToken: "from-file"},
		},
		{
			name:     "value and path both set",
			provider: "cloudflare",
			settings: map[string]any{"api_token": "tok", "api_token_path": secret},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unreadable path",
			provider: "cloudflare",
			settings: map[string]any{"api_token_path": filepath.Join(t.TempDir(), "missing")},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unknown key",
			provider: "cloudflare",
			settings: map[string]any{"auth_token": "tok"},
			wantErr:  ErrProviderConfig,
		},
		{
			name:     "unknown provider",
			provider: "route53",
			wantErr:  ErrUnknownProvider,
		},
		{
			name:     "gigahost",
			provider: "gigahost",
			settings: map[string]any{"api_key_path": secret},
			want:     &gigahost.Provider{APIKey: "from-file"},
		},
		{
			name:     "hetzner",
			provider: "hetzner",
			settings: map[string]any{"api_token_path": secret},
			want:     &hetzner.Provider{APIToken: "from-file"},
		},
		{
			name:     "powerdns",
			provider: "powerdns",
			settings: map[string]any{"server_url": "https://pdns.example.com", "api_token": "tok"},
			want:     &powerdns.Provider{ServerURL: "https://pdns.example.com", APIToken: "tok"},
		},
		{
			name:     "only a name",
			provider: "gigahost",
			settings: map[string]any{"name": "gigahost"},
			wantErr:  ErrProviderConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := NewProvider(tt.provider, tt.settings, noEnv)
			if tt.wantErr != nil {
				require.ErrorIs(t, err, tt.wantErr)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}
