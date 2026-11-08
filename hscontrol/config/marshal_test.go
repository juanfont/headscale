package config

import (
	"cmp"
	"context"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"testing"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/knadh/koanf/providers/confmap"
	"github.com/knadh/koanf/v2"
	"github.com/libdns/libdns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/tailcfg"
)

// fileFormats are the formats a configuration can be written in.
var fileFormats = []string{".yaml", ".json", ".hujson"}

// roundTrip writes cfg as a file of ext, secrets as written, and loads it
// back without environment.
func roundTrip(tb testing.TB, cfg *types.Config, ext string) (*types.Config, error) {
	tb.Helper()

	parser, err := configParser(ext)
	require.NoError(tb, err)

	out, err := parser.Marshal(plainMap(cfg, false))
	require.NoError(tb, err)

	path := filepath.Join(tb.TempDir(), "config"+ext)
	require.NoError(tb, os.WriteFile(path, out, 0o600))

	l, err := Load(path, true, nil)

	return l.Config, err
}

// roundTripOpts compare a Config with the one its file loads to.
var roundTripOpts = gocmp.Options{
	cmpopts.EquateEmpty(),
	cmpopts.EquateComparable(netip.Prefix{}),
	cmpopts.IgnoreFields(types.Config{}, "ConfigDir"),
	cmpopts.IgnoreUnexported(types.Config{}),
}

// TestRoundTrip: a configuration written by Marshal's map, in any format,
// loads back to itself.
func TestRoundTrip(t *testing.T) {
	unsetHeadscaleEnv(t)

	rows := append([]compatRow{{name: "default"}}, compatRows(t)...)

	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			var cfg *types.Config

			if row.name == "default" {
				d := Default()
				cfg = &d
			} else {
				l, err := Load(stageCompat(t, row.file, row.envFile), false, os.Environ())
				if err != nil {
					t.Skipf("does not load: %v", err)
				}

				cfg = l.Config
			}

			for _, ext := range fileFormats {
				t.Run(ext, func(t *testing.T) {
					got, err := roundTrip(t, cfg, ext)
					require.NoError(t, err)

					if diff := gocmp.Diff(cfg, got, roundTripOpts); diff != "" {
						t.Errorf("round trip (-written +loaded):\n%s", diff)
					}
				})
			}
		})
	}
}

// roundTripValues are inputs at the edges of what a file or variable can
// hold. FuzzLoad seeds from them too.
var roundTripValues = []struct {
	name    string
	file    string
	env     []string
	want    func(*types.Config) any // what it loads to, compared with wantVal
	wantVal any
}{
	{
		name:    "provider integer beyond 64 bits signed",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      api_token: 18446744073709551615\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "api_token": "18446744073709551615"},
	},
	{
		name:    "provider integer beyond float precision",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      api_token: 9007199254740993\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "api_token": "9007199254740993"},
	},
	{
		name: "provider scalars",
		file: "dns:\n  challenge:\n    provider:\n      name: 1\n      a: true\n      b: 1.5\n      c: [1, false]\n      d: {e: 2}\n",
		want: providerSettings,
		wantVal: map[string]any{
			"name": "1", "a": "true", "b": "1.5",
			"c": []any{"1", "false"}, "d": map[string]any{"e": "2"},
		},
	},
	{
		name:    "provider nulls",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      x: [null]\n      y: null\n      z: {a: null}\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "x": []any{}, "z": map[string]any{}},
	},
	{
		name:    "provider nan",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      api_token: .nan\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "api_token": "NaN"},
	},
	{
		name:    "provider inf",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      config:\n        a: [-.inf]\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "config": map[string]any{"a": []any{"-Inf"}}},
	},
	// Parsers read unquoted dates and times as time types, which load as
	// their text.
	{
		name:    "provider yaml timestamps",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      d: 2026-11-08\n      t: 2026-11-08T10:00:00.5+01:00\n      l: [2026-11-08]\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "d": "2026-11-08T00:00:00Z", "t": "2026-11-08T10:00:00.5+01:00", "l": []any{"2026-11-08T00:00:00Z"}},
	},
	{
		name:    "provider yaml timestamp with a 24 hour offset",
		file:    "dns:\n  challenge:\n    provider:\n      name: cloudflare\n      t: 2026-11-08T10:00:00+24:00\n",
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "t": "2026-11-08T10:00:00+24:00"},
	},
	{
		name:    "list null",
		file:    "dns:\n  nameservers:\n    global: [null, 1.1.1.1]\n",
		want:    globalNameservers,
		wantVal: []string{"1.1.1.1"},
	},
	{
		name:    "env split null",
		env:     []string{`HEADSCALE_DNS_NAMESERVERS_SPLIT={"a.example.com":null,"b.example.com":["10.0.0.1",null]}`},
		want:    func(c *types.Config) any { return c.DNSConfig.Nameservers.Split },
		wantVal: map[string][]string{"b.example.com": {"10.0.0.1"}},
	},
	{
		name:    "env provider null",
		env:     []string{`HEADSCALE_DNS_CHALLENGE_PROVIDER={"name":"cloudflare","api_token":null,"x":[null,1],"y":{"z":null}}`},
		want:    providerSettings,
		wantVal: map[string]any{"name": "cloudflare", "x": []any{"1"}, "y": map[string]any{}},
	},
	{
		name:    "env list null",
		env:     []string{`HEADSCALE_DNS_NAMESERVERS_GLOBAL=["1.1.1.1",null]`},
		want:    globalNameservers,
		wantVal: []string{"1.1.1.1"},
	},
}

func providerSettings(c *types.Config) any { return c.DNSConfig.Challenge.ProviderSettings }

func globalNameservers(c *types.Config) any { return c.DNSConfig.Nameservers.Global }

// TestRoundTripValues: values at the edges load exactly.
func TestRoundTripValues(t *testing.T) {
	for _, tt := range roundTripValues {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yaml")
			require.NoError(t, os.WriteFile(path, []byte(tt.file), 0o600))

			l, err := Load(path, true, tt.env)
			require.NoError(t, err)

			if tt.want != nil {
				assert.Equal(t, tt.wantVal, tt.want(l.Config))
			}

			for _, ext := range fileFormats {
				got, err := roundTrip(t, l.Config, ext)
				require.NoError(t, err, ext)

				if diff := gocmp.Diff(l.Config, got, roundTripOpts); diff != "" {
					t.Errorf("%s round trip (-written +loaded):\n%s", ext, diff)
				}
			}
		})
	}
}

// TestMarshalNullablePrefix: a nil prefix is written as an explicit unset,
// which wins over a layer below that sets it.
func TestMarshalNullablePrefix(t *testing.T) {
	cfg := Default()
	require.Nil(t, cfg.Prefixes.V4)

	yamlOut, err := Marshal(&cfg, ".yaml")
	require.NoError(t, err)
	assert.Contains(t, string(yamlOut), `v4: ""`)

	for _, ext := range fileFormats {
		t.Run(ext, func(t *testing.T) {
			out, err := Marshal(&cfg, ext)
			require.NoError(t, err)

			path := filepath.Join(t.TempDir(), "config"+ext)
			require.NoError(t, os.WriteFile(path, out, 0o600))

			below := Default()
			v4 := netip.MustParsePrefix("100.64.0.0/10")
			below.Prefixes.V4 = &v4

			s := &configSource{k: koanf.New("."), file: path, envVars: map[string]string{}}
			require.NoError(t, s.k.Load(confmap.Provider(plainMap(&below, false), ""), nil))
			require.NoError(t, s.loadFile())

			got, err := s.decode()
			require.NoError(t, err)
			assert.Nil(t, got.Prefixes.V4)
		})
	}
}

// TestMarshalDurations: durations print without trailing zero units.
func TestMarshalDurations(t *testing.T) {
	cfg := Default()

	out, err := Marshal(&cfg, ".yaml")
	require.NoError(t, err)
	assert.Contains(t, string(out), "update_frequency: 3h\n")
	assert.Contains(t, string(out), "revoked_retention: 168h\n")
}

// fakeProvider is a Go-only DNS provider.
type fakeProvider struct{ Token string }

func (fakeProvider) AppendRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

func (fakeProvider) DeleteRecords(context.Context, string, []libdns.Record) ([]libdns.Record, error) {
	return nil, nil
}

// redactTests hold a credential in every key that can: dns.challenge.provider
// in each shape, the rest as redactConfig sets them. A redacted rendering
// hides redactHidden and hidden, and shows redactShown and shown.
var redactTests = []struct {
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

// redactHidden are the credentials redactConfig sets outside the provider.
var redactHidden = []string{
	"marker-oidc-secret", "marker-issuer-user", "marker-issuer-pass", "marker-pg-pass",
	"marker-acme-user", "marker-derp-user", "marker-derp-pass",
	"marker-derpmap", "marker-go-provider",
	"marker-server-user", "marker-server-pass", "marker-cli-user",
	"marker-dns-user", "marker-dns-pass", "marker-split-user",
}

// redactShown is what of redactConfig's values a redacted rendering keeps.
var redactShown = []string{
	"file:/run/credentials/cli_key", "idp.example.com", "derp.example.com",
	"https://headscale.example.com", "https://cli.example.com", "1.1.1.1",
	"https://dns.example.com/dns-query", "https://dns.example.com/q",
}

// redactConfig is Default() with a credential in every key that can hold
// one, provider as dns.challenge.provider, and some set only from Go.
func redactConfig(provider map[string]any) types.Config {
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
	cfg.DNSConfig.Challenge.ProviderSettings = maps.Clone(provider)
	cfg.DNSConfig.Challenge.Provider = fakeProvider{Token: "marker-go-provider"} //nolint:gosec // a test marker, not a credential

	return cfg
}

// TestMarshalRedacts: what Marshal prints holds no credential, in any
// format: a literal secret, a DNS provider setting of any shape, URL
// userinfo, in URL and plain string keys alike, and nothing set only from
// Go. The running values keep theirs.
func TestMarshalRedacts(t *testing.T) {
	for _, tt := range redactTests {
		for _, ext := range fileFormats {
			t.Run(tt.name+ext, func(t *testing.T) {
				cfg := redactConfig(tt.provider)

				out, err := Marshal(&cfg, ext)
				require.NoError(t, err)

				for _, h := range append(slices.Clone(redactHidden), tt.hidden...) {
					assert.NotContains(t, string(out), h)
				}

				for _, s := range append(slices.Clone(redactShown), tt.shown...) {
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

// serverURLRedactTests are server_url values with userinfo, each with what
// a redacted rendering shows: "" when the value is withheld whole.
var serverURLRedactTests = []struct {
	serverURL string
	shown     string
}{
	{serverURL: "https://headscale.example.com", shown: "https://headscale.example.com"},
	{serverURL: "https://marker-user:marker-pass@headscale.example.com", shown: "https://headscale.example.com"}, //nolint:gosec // test markers, not credentials
	{serverURL: "https://marker-user@headscale.example.com", shown: "https://headscale.example.com"},
	{serverURL: "https://marker-user:marker-pass@headscale.example.com/%zz"}, //nolint:gosec // test markers, not credentials
	{serverURL: "https://alice:marker-pass?@headscale.example.com"},
	{serverURL: "https://alice:marker-pass#@headscale.example.com"},
	{serverURL: "https://alice:marker-pass@headscale.example.com:port"},
	{serverURL: "https:/alice:marker-pass@headscale.example.com"},
}

// TestMarshalRedactsServerURL: server_url is a string, not an HTTPURL, but
// its userinfo is as secret; a value whose userinfo cannot be told from the
// rest is withheld whole. The raw map, as the round trip writes it, keeps
// the value.
func TestMarshalRedactsServerURL(t *testing.T) {
	for _, tt := range serverURLRedactTests {
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
