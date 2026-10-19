package dns

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	gigahost "github.com/kradalby/libdns-gigahost"
	"github.com/libdns/acmedns"
	"github.com/libdns/cloudflare"
	"github.com/libdns/hetzner/v2"
	"github.com/libdns/libdns"
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
			name:     "acmedns",
			provider: "acmedns",
			settings: map[string]any{
				"username":      "user",
				"password_path": secret,
				"subdomain":     "reg",
				"server_url":    "https://auth.acme-dns.io",
			},
			want: &acmeDNS{
				Username:  "user",
				Password:  "from-file",
				Subdomain: "reg",
				ServerURL: "https://auth.acme-dns.io",
				served:    map[string][2]acmeDNSValue{},
			},
		},
		{
			name:     "acmedns per domain",
			provider: "acmedns",
			settings: map[string]any{"config": map[string]any{
				"node.ts.example.com": map[string]any{
					"username":   "user",
					"password":   "pass",
					"subdomain":  "reg",
					"server_url": "https://auth.acme-dns.io",
				},
			}},
			want: &acmeDNS{
				Configs: map[string]acmedns.DomainConfig{
					"node.ts.example.com": {
						Username:  "user",
						Password:  "pass",
						Subdomain: "reg",
						ServerURL: "https://auth.acme-dns.io",
					},
				},
				served: map[string][2]acmeDNSValue{},
			},
		},
		{
			name:     "acmedns server_url without scheme",
			provider: "acmedns",
			settings: map[string]any{
				"username":   "user",
				"password":   "pass",
				"subdomain":  "reg",
				"server_url": "auth.acme-dns.io",
			},
			wantErr: ErrProviderConfig,
		},
		{
			name:     "acmedns without subdomain",
			provider: "acmedns",
			settings: map[string]any{
				"username":   "user",
				"password":   "pass",
				"server_url": "https://auth.acme-dns.io",
			},
			wantErr: ErrProviderConfig,
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

// fakeAcmeDNS is an acme-dns server with one registration, reg. It has two
// rows, and an update overwrites the one stamped with the earlier second.
// acme-dns overwrites either on a tie; the fake picks the one written
// later, which a writer assuming first in, first out gets wrong.
type fakeAcmeDNS struct {
	*httptest.Server

	mu     sync.Mutex
	writes int
	rows   [2]fakeAcmeDNSRow
}

type fakeAcmeDNSRow struct {
	txt   string
	stamp int64 // acme-dns's LastUpdate, in whole seconds
	write int   // the order of writes, which acme-dns does not keep
}

func newFakeAcmeDNS(t *testing.T) *fakeAcmeDNS {
	t.Helper()

	f := &fakeAcmeDNS{}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var update struct{ Subdomain, Txt string }

		err := json.NewDecoder(r.Body).Decode(&update)
		if r.URL.Path != "/update" || err != nil || update.Subdomain != "reg" || r.Header.Get("X-Api-User") != "user" {
			w.WriteHeader(http.StatusUnauthorized)

			return
		}

		f.mu.Lock()
		defer f.mu.Unlock()

		i := 0
		if f.rows[1].stamp < f.rows[0].stamp ||
			(f.rows[1].stamp == f.rows[0].stamp && f.rows[1].write > f.rows[0].write) {
			i = 1
		}

		f.writes++
		f.rows[i] = fakeAcmeDNSRow{txt: update.Txt, stamp: time.Now().Unix(), write: f.writes}
	}))
	t.Cleanup(f.Close)

	return f
}

func (f *fakeAcmeDNS) registration() map[string]any {
	return map[string]any{
		"username":   "user",
		"password":   "pass",
		"subdomain":  "reg",
		"server_url": f.URL,
	}
}

func (f *fakeAcmeDNS) serving() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	var txts []string

	for _, row := range f.rows {
		if row.txt != "" {
			txts = append(txts, row.txt)
		}
	}

	return txts
}

func acmeTXT(node, value string) []libdns.Record {
	return []libdns.Record{libdns.TXT{Name: "_acme-challenge." + node, Text: value}}
}

// A registration serves the two values written last, and deleting is a
// no-op: an update overwrites the older value even if a CA may still be
// validating it, however many values were deleted. Two updates within one
// second carry the same stamp, leaving acme-dns free to overwrite either:
// after a then b, with a freed, c could overwrite b.
func TestAcmeDNSRefusesEviction(t *testing.T) {
	t.Parallel()

	srv := newFakeAcmeDNS(t)

	p, err := NewProvider("acmedns", srv.registration(), noEnv)
	require.NoError(t, err)

	ctx := context.Background()

	a, err := p.AppendRecords(ctx, testZone, acmeTXT("a", "value-a"))
	require.NoError(t, err)
	require.Len(t, a, 1, "certmagic needs the appended record back")

	b, err := p.AppendRecords(ctx, testZone, acmeTXT("b", "value-b"))
	require.NoError(t, err)

	_, err = p.AppendRecords(ctx, testZone, acmeTXT("c", "value-c"))
	require.ErrorIs(t, err, ErrTooManyChallenges)

	// The newer value is free, but an update overwrites the older one.
	_, err = p.DeleteRecords(ctx, testZone, b)
	require.NoError(t, err)

	_, err = p.AppendRecords(ctx, testZone, acmeTXT("c", "value-c"))
	require.ErrorIs(t, err, ErrTooManyChallenges)
	assert.ElementsMatch(t, []string{"value-a", "value-b"}, srv.serving(), "a refused value reached acme-dns")

	_, err = p.DeleteRecords(ctx, testZone, a)
	require.NoError(t, err)

	c, err := p.AppendRecords(ctx, testZone, acmeTXT("c", "value-c"))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"value-b", "value-c"}, srv.serving())

	// b is free and now the older value; overwriting it leaves c alone.
	_, err = p.AppendRecords(ctx, testZone, acmeTXT("d", "value-d"))
	require.NoError(t, err)
	assert.ElementsMatch(t, []string{"value-c", "value-d"}, srv.serving())

	// Giving up while waiting to space updates writes nothing.
	_, err = p.DeleteRecords(ctx, testZone, c)
	require.NoError(t, err)

	cancelled, cancel := context.WithCancel(ctx)
	cancel()

	_, err = p.AppendRecords(cancelled, testZone, acmeTXT("e", "value-e"))
	require.ErrorIs(t, err, context.Canceled)
	assert.ElementsMatch(t, []string{"value-c", "value-d"}, srv.serving())
}
