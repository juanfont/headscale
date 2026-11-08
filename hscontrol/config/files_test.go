package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/google/go-cmp/cmp"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/libdns/cloudflare"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func write(t *testing.T, path, content string) string {
	t.Helper()
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

	return path
}

func keyText(t *testing.T) string {
	t.Helper()

	b, err := key.NewMachine().MarshalText()
	require.NoError(t, err)

	return string(b)
}

const badGroup = `{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`

func TestFiles(t *testing.T) {
	dir := t.TempDir()
	cfg := &types.Config{
		Noise:  types.NoiseConfig{PrivateKeyPath: filepath.Join(dir, "noise.key")},
		Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: filepath.Join(dir, "policy.hujson")},
		DERP: types.DERPConfig{
			Paths:  []string{"a.yaml", "b.yaml"},
			Server: types.DERPServerConfig{Enabled: true, PrivateKeyPath: filepath.Join(dir, "derp.key")},
		},
		DNSConfig: types.DNSConfig{ExtraRecordsPath: "records.json"},
		TLS:       types.TLSConfig{CertPath: "c.pem", KeyPath: "k.pem"},
	}

	type entry struct {
		Key, Path        string
		CreatedAtStartup bool
	}

	files := Files(cfg)

	got := make([]entry, 0, len(files))
	for _, f := range files {
		got = append(got, entry{f.Key, f.Path, f.CreatedAtStartup})
	}

	want := []entry{
		{"policy.path", filepath.Join(dir, "policy.hujson"), false},
		{"derp.paths", "a.yaml", false},
		{"derp.paths", "b.yaml", false},
		{"dns.extra_records_path", "records.json", false},
		{"tls.cert_path, tls.key_path", "c.pem, k.pem", false},
		{"noise.private_key_path", filepath.Join(dir, "noise.key"), true},
		{"derp.server.private_key_path", filepath.Join(dir, "derp.key"), true},
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("Files() mismatch (-want +got):\n%s", diff)
	}

	// A policy in the database and a disabled DERP server name no file.
	cfg.Policy.Mode = types.PolicyModeDB
	cfg.DERP.Server.Enabled = false

	for _, f := range Files(cfg) {
		require.NotContains(t, []string{"policy.path", "derp.server.private_key_path"}, f.Key)
	}

	// A file: secret is listed, unread, only where startup reads it.
	missing := types.Secret("file:" + filepath.Join(dir, "missing"))
	postgres := types.DatabaseConfig{Type: types.DatabasePostgres, Postgres: types.PostgresConfig{Pass: missing}}
	oidc := types.OIDCConfig{Issuer: "https://idp.example.com", ClientSecret: missing}
	provider := types.DNSChallengeConfig{ProviderSettings: map[string]any{
		"name": "cloudflare", "zone_token": string(missing), "api_token": string(missing),
	}}

	for _, tt := range []struct {
		name string
		cfg  types.Config
		want []string
	}{
		{name: "postgres pass", cfg: types.Config{Database: postgres}, want: []string{"database.postgres.pass"}},
		{name: "sqlite reads no postgres pass", cfg: types.Config{Database: types.DatabaseConfig{Type: types.DatabaseSqlite, Postgres: postgres.Postgres}}},
		{name: "oidc with an issuer", cfg: types.Config{OIDC: oidc}, want: []string{"oidc.client_secret"}},
		{name: "oidc without an issuer", cfg: types.Config{OIDC: types.OIDCConfig{ClientSecret: missing}}},
		{name: "literal secrets", cfg: types.Config{
			Database: types.DatabaseConfig{Type: types.DatabasePostgres, Postgres: types.PostgresConfig{Pass: "literal"}},
			OIDC:     types.OIDCConfig{Issuer: oidc.Issuer, ClientSecret: "literal"},
		}},
		{
			name: "provider settings",
			cfg:  types.Config{DNSConfig: types.DNSConfig{Challenge: provider}},
			want: []string{"dns.challenge.provider.api_token", "dns.challenge.provider.zone_token"},
		},
		{
			name: "go-only provider reads no settings",
			cfg: types.Config{
				DNSConfig: types.DNSConfig{Challenge: types.DNSChallengeConfig{
					ProviderSettings: provider.ProviderSettings, Provider: &cloudflare.Provider{},
				}},
			},
		},
		{
			name: "sorted by key",
			cfg:  types.Config{Database: postgres, OIDC: oidc, DNSConfig: types.DNSConfig{Challenge: provider}},
			want: []string{
				"database.postgres.pass", "dns.challenge.provider.api_token",
				"dns.challenge.provider.zone_token", "oidc.client_secret",
			},
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			var keys []string

			for _, f := range Files(&tt.cfg) {
				require.ErrorIs(t, f.Check(), ErrSecretNotRead, f.Key)
				require.Equal(t, filepath.Join(dir, "missing"), f.Path, f.Key)

				keys = append(keys, f.Key)
			}

			require.Equal(t, tt.want, keys)
		})
	}
}

func TestFilesChecks(t *testing.T) {
	tests := []struct {
		name    string
		build   func(t *testing.T, dir string) *types.Config
		key     string
		wantErr error  // errors.Is target
		wantMsg string // substring, when no sentinel exists
	}{
		{
			name: "policy valid",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "p.hujson"), `{"acls":[{"action":"accept","src":["*"],"dst":["*:*"]}]}`)

				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p}}
			},
			key: "policy.path",
		},
		{
			name: "policy with undefined group",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "p.hujson"), badGroup)

				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p}}
			},
			key:     "policy.path",
			wantErr: policyv2.ErrGroupNotDefined,
		},
		{
			name: "policy with failing tests",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "p.hujson"), `{"acls":[],"tests":[{"src":"alice@","accept":["bob@:22"]}]}`)

				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p}}
			},
			key:     "policy.path",
			wantMsg: "test(s) failed",
		},
		{
			name: "policy empty",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "p.hujson"), "")

				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p}}
			},
			key:     "policy.path",
			wantErr: policyv2.ErrPolicyEmpty,
		},
		{
			name: "policy missing",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: filepath.Join(dir, "nope")}}
			},
			key:     "policy.path",
			wantErr: os.ErrNotExist,
		},
		{
			name: "derp map empty",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{DERP: types.DERPConfig{Paths: []string{write(t, filepath.Join(dir, "d.yaml"), "{}")}}}
			},
			key:     "derp.paths",
			wantMsg: "d.yaml",
		},
		{
			name: "extra records valid",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "r.json"), `[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`)

				return &types.Config{DNSConfig: types.DNSConfig{ExtraRecordsPath: p}}
			},
			key: "dns.extra_records_path",
		},
		{
			name: "extra records malformed",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{DNSConfig: types.DNSConfig{ExtraRecordsPath: write(t, filepath.Join(dir, "r.json"), "{not json")}}
			},
			key:     "dns.extra_records_path",
			wantMsg: "unmarshalling records",
		},
		{
			name: "tls pair missing",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{TLS: types.TLSConfig{CertPath: filepath.Join(dir, "c.pem"), KeyPath: filepath.Join(dir, "k.pem")}}
			},
			key:     "tls.cert_path, tls.key_path",
			wantErr: os.ErrNotExist,
		},
		{
			name: "noise key missing",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{Noise: types.NoiseConfig{PrivateKeyPath: filepath.Join(dir, "sub", "noise.key")}}
			},
			key:     "noise.private_key_path",
			wantErr: os.ErrNotExist,
		},
		{
			name: "noise key corrupt",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{Noise: types.NoiseConfig{PrivateKeyPath: write(t, filepath.Join(dir, "noise.key"), "garbage")}}
			},
			key:     "noise.private_key_path",
			wantMsg: "parsing private key",
		},
		{
			name: "derp key equals noise key",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				k := keyText(t)

				return &types.Config{
					Noise: types.NoiseConfig{PrivateKeyPath: write(t, filepath.Join(dir, "noise.key"), k)},
					DERP: types.DERPConfig{
						Server: types.DERPServerConfig{Enabled: true, PrivateKeyPath: write(t, filepath.Join(dir, "derp.key"), k+"\n")},
					},
				}
			},
			key:     "derp.server.private_key_path",
			wantErr: ErrSameKey,
		},
		{
			name: "derp key differs from noise key",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{
					Noise: types.NoiseConfig{PrivateKeyPath: write(t, filepath.Join(dir, "noise.key"), keyText(t))},
					DERP: types.DERPConfig{
						Server: types.DERPServerConfig{Enabled: true, PrivateKeyPath: write(t, filepath.Join(dir, "derp.key"), keyText(t))},
					},
				}
			},
			key: "derp.server.private_key_path",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			var found bool

			for _, f := range Files(tt.build(t, dir)) {
				if f.Key != tt.key {
					continue
				}

				found = true
				err := f.Check()

				switch {
				case tt.wantErr != nil:
					require.ErrorIs(t, err, tt.wantErr)
				case tt.wantMsg != "":
					require.ErrorContains(t, err, tt.wantMsg)
				default:
					require.NoError(t, err)
				}
			}

			require.True(t, found, "no file with key %q", tt.key)

			// Checks never create anything.
			entries, err := os.ReadDir(dir)
			require.NoError(t, err)

			for _, e := range entries {
				require.False(t, e.IsDir(), "check created %s", e.Name())
			}
		})
	}
}

func TestCheckDERPMapFile(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, CheckDERPMapFile(write(t, filepath.Join(dir, "ok.yaml"), `regions:
  900:
    regionid: 900
    regioncode: test
    nodes:
      - name: 900a
        regionid: 900
        hostname: derp.example.com
`)))
	require.ErrorContains(t, CheckDERPMapFile(write(t, filepath.Join(dir, "bad.yaml"), "regions: [")), "reading DERP map")
	require.ErrorIs(t, CheckDERPMapFile(filepath.Join(dir, "missing.yaml")), os.ErrNotExist)
}

func TestCheckExtraRecordsFile(t *testing.T) {
	dir := t.TempDir()

	require.NoError(t, CheckExtraRecordsFile(write(t, filepath.Join(dir, "ok.json"),
		`[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`)))

	err := CheckExtraRecordsFile(write(t, filepath.Join(dir, "bad.json"), `[{"name": "secret-ish"`))
	require.ErrorContains(t, err, "bad.json")
	require.NotContains(t, err.Error(), "secret-ish", "file content must not be echoed")

	require.ErrorIs(t, CheckExtraRecordsFile(filepath.Join(dir, "missing.json")), os.ErrNotExist)
}

func TestReadPrivateKey(t *testing.T) {
	dir := t.TempDir()
	k := keyText(t)

	got, err := ReadPrivateKey(write(t, filepath.Join(dir, "k"), " "+k+"\n"))
	require.NoError(t, err)

	b, err := got.MarshalText()
	require.NoError(t, err)
	require.Equal(t, k, string(b))

	_, err = ReadPrivateKey(filepath.Join(dir, "missing"))
	require.ErrorIs(t, err, os.ErrNotExist)
}
