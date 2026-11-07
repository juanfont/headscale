package hscontrol

import (
	"os"
	"path/filepath"
	"testing"

	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"tailscale.com/types/key"
)

func TestCheckFiles(t *testing.T) {
	keyText := func(t *testing.T) string {
		t.Helper()

		k := key.NewMachine()
		b, err := k.MarshalText()
		require.NoError(t, err)

		return string(b)
	}

	write := func(t *testing.T, path, content string) string {
		t.Helper()
		require.NoError(t, os.WriteFile(path, []byte(content), 0o600))

		return path
	}

	sharedKeys := func(noise, derp string) *types.Config {
		return &types.Config{
			NoisePrivateKeyPath: noise,
			DERP:                types.DERPConfig{ServerEnabled: true, ServerPrivateKeyPath: derp},
		}
	}

	tests := []struct {
		name    string
		build   func(t *testing.T, dir string) *types.Config
		wantErr []string
		check   func(t *testing.T, dir string, err error)
	}{
		{
			name:  "nothing referenced",
			build: func(*testing.T, string) *types.Config { return &types.Config{} },
		},
		{
			name: "missing noise key is not created",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{NoisePrivateKeyPath: filepath.Join(dir, "sub", "noise.key")}
			},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "sub"))
			},
		},
		{
			name: "corrupt noise key",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{NoisePrivateKeyPath: write(t, filepath.Join(dir, "noise.key"), "garbage")}
			},
			wantErr: []string{"parsing private key", "noise.private_key_path"},
		},
		{
			name: "derp key equals noise key",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				k := keyText(t)

				return &types.Config{
					NoisePrivateKeyPath: write(t, filepath.Join(dir, "noise.key"), k),
					DERP: types.DERPConfig{
						ServerEnabled:        true,
						ServerPrivateKeyPath: write(t, filepath.Join(dir, "derp.key"), k),
					},
				}
			},
			wantErr: []string{"derp.server.private_key_path"},
		},
		{
			name: "shared missing key path is rejected and not created",
			build: func(_ *testing.T, dir string) *types.Config {
				p := filepath.Join(dir, "sub", "shared.key")

				return &types.Config{
					NoisePrivateKeyPath: p,
					DERP:                types.DERPConfig{ServerEnabled: true, ServerPrivateKeyPath: p},
				}
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "sub"))
			},
		},
		{
			name: "shared missing key via symlinked parent is rejected",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dir, "real"), 0o700))
				require.NoError(t, os.Symlink("real", filepath.Join(dir, "alias")))

				return &types.Config{
					NoisePrivateKeyPath: filepath.Join(dir, "real", "shared.key"),
					DERP: types.DERPConfig{
						ServerEnabled:        true,
						ServerPrivateKeyPath: filepath.Join(dir, "alias", "shared.key"),
					},
				}
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoFileExists(t, filepath.Join(dir, "real", "shared.key"))
			},
		},
		{
			name: "dangling leaf symlink to shared missing key is rejected",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Symlink(filepath.Join(dir, "shared.key"), filepath.Join(dir, "alias.key")))

				return sharedKeys(filepath.Join(dir, "shared.key"), filepath.Join(dir, "alias.key"))
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoFileExists(t, filepath.Join(dir, "shared.key"))
			},
		},
		{
			name: "dangling parent symlink to shared missing key is rejected",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dir, "real"), 0o700))
				require.NoError(t, os.Symlink(filepath.Join(dir, "real", "pending"), filepath.Join(dir, "alias")))

				return sharedKeys(
					filepath.Join(dir, "real", "pending", "shared.key"),
					filepath.Join(dir, "alias", "shared.key"))
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "real", "pending"))
			},
		},
		{
			name: "dotdot after symlink with dangling key link is rejected",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "base"), 0o700))
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "other", "sub"), 0o700))
				require.NoError(t, os.Symlink("../other/sub", filepath.Join(dir, "base", "link")))
				require.NoError(t, os.Symlink("../base/shared.key", filepath.Join(dir, "other", "shared.key")))

				return sharedKeys(
					filepath.Join(dir, "base", "shared.key"),
					dir+"/base/link/../shared.key")
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoFileExists(t, filepath.Join(dir, "base", "shared.key"))
			},
		},
		{
			name: "dotdot back into existing links after a missing name is rejected",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Mkdir(filepath.Join(dir, "sub"), 0o700))
				require.NoError(t, os.Symlink(dir, filepath.Join(dir, "alias")))
				require.NoError(t, os.Symlink(dir+"/foo/../alias/sub", filepath.Join(dir, "link")))

				return sharedKeys(filepath.Join(dir, "foo", "shared.key"), dir+"/link/../foo/shared.key")
			},
			wantErr: []string{"derp.server.private_key_path", "must differ"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "foo"))
			},
		},
		{
			name: "dotdot after a missing name to a distinct existing key passes",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "other", "sub"), 0o700))
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "other", "new"), 0o700))
				write(t, filepath.Join(dir, "other", "new", "shared.key"), keyText(t))
				require.NoError(t, os.Symlink(filepath.Join(dir, "other", "sub"), filepath.Join(dir, "link")))
				require.NoError(t, os.Symlink(dir+"/new/../link/../new/shared.key", filepath.Join(dir, "alias.key")))

				return sharedKeys(filepath.Join(dir, "new", "shared.key"), filepath.Join(dir, "alias.key"))
			},
			check: func(t *testing.T, dir string, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NoDirExists(t, filepath.Join(dir, "new"))
			},
		},
		{
			name: "symlink loop behind a missing prefix is an error",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Symlink("loop", filepath.Join(dir, "loop")))

				return sharedKeys(filepath.Join(dir, "pending", "noise.key"), dir+"/pending/../loop/derp.key")
			},
			wantErr: []string{"derp.server.private_key_path"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "pending"))
			},
		},
		{
			name: "regular file as directory behind a missing prefix is an error",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				write(t, filepath.Join(dir, "file"), "x")

				return sharedKeys(filepath.Join(dir, "pending", "noise.key"), dir+"/pending/../file/derp.key")
			},
			wantErr: []string{"derp.server.private_key_path"},
			check: func(t *testing.T, dir string, _ error) {
				t.Helper()
				assert.NoDirExists(t, filepath.Join(dir, "pending"))
			},
		},
		{
			name: "symlink loop errors without hanging",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.Symlink("b", filepath.Join(dir, "a")))
				require.NoError(t, os.Symlink("a", filepath.Join(dir, "b")))

				return sharedKeys(filepath.Join(dir, "noise.key"), filepath.Join(dir, "a"))
			},
			wantErr: []string{"derp.server.private_key_path"},
		},
		{
			name: "dotdot through symlink to a distinct existing key passes",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "a"), 0o700))
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "b", "child"), 0o700))
				require.NoError(t, os.MkdirAll(filepath.Join(dir, "b", "a"), 0o700))
				require.NoError(t, os.Symlink(filepath.Join(dir, "b", "child"), filepath.Join(dir, "link")))
				write(t, filepath.Join(dir, "a", "key"), keyText(t))
				write(t, filepath.Join(dir, "b", "a", "key"), keyText(t))

				return &types.Config{
					NoisePrivateKeyPath: filepath.Join(dir, "a", "key"),
					DERP: types.DERPConfig{
						ServerEnabled:        true,
						ServerPrivateKeyPath: dir + "/link/../a/key",
					},
				}
			},
			check: func(t *testing.T, _ string, err error) {
				t.Helper()
				require.NoError(t, err)
			},
		},
		{
			name: "distinct missing key paths pass",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{
					NoisePrivateKeyPath: filepath.Join(dir, "sub", "noise.key"),
					DERP: types.DERPConfig{
						ServerEnabled:        true,
						ServerPrivateKeyPath: filepath.Join(dir, "sub", "derp.key"),
					},
				}
			},
			check: func(t *testing.T, dir string, err error) {
				t.Helper()
				require.NoError(t, err)
				assert.NoDirExists(t, filepath.Join(dir, "sub"))
			},
		},
		{
			name: "policy with undefined group",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "policy.hujson"),
					`{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`)

				return &types.Config{Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p}}
			},
			wantErr: []string{"policy.path"},
			check: func(t *testing.T, _ string, err error) {
				t.Helper()
				require.ErrorIs(t, err, policyv2.ErrGroupNotDefined)
			},
		},
		{
			name: "extra records valid",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "extra.json"), `[{"name":"a.example.com","type":"A","value":"100.64.0.1"}]`)

				return &types.Config{DNSConfig: types.DNSConfig{ExtraRecordsPath: p}}
			},
		},
		{
			name: "extra records malformed",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{DNSConfig: types.DNSConfig{ExtraRecordsPath: write(t, filepath.Join(dir, "extra.json"), "{not json")}}
			},
			wantErr: []string{"dns.extra_records_path"},
		},
		{
			name: "tls cert missing",
			build: func(_ *testing.T, dir string) *types.Config {
				return &types.Config{TLS: types.TLSConfig{
					CertPath: filepath.Join(dir, "c.pem"),
					KeyPath:  filepath.Join(dir, "k.pem"),
				}}
			},
			wantErr: []string{"tls.cert_path", "tls.key_path"},
		},
		{
			name: "derp paths empty map",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				return &types.Config{DERP: types.DERPConfig{Paths: []string{write(t, filepath.Join(dir, "d.yaml"), "{}")}}}
			},
			wantErr: []string{"derp.paths"},
		},
		{
			name: "all problems reported together",
			build: func(t *testing.T, dir string) *types.Config {
				t.Helper()

				p := write(t, filepath.Join(dir, "policy.hujson"),
					`{"acls":[{"action":"accept","src":["group:missing"],"dst":["*:*"]}]}`)

				return &types.Config{
					Policy: types.PolicyConfig{Mode: types.PolicyModeFile, Path: p},
					TLS:    types.TLSConfig{CertPath: filepath.Join(dir, "c.pem"), KeyPath: filepath.Join(dir, "k.pem")},
					DERP:   types.DERPConfig{Paths: []string{write(t, filepath.Join(dir, "d.yaml"), "{}")}},
				}
			},
			wantErr: []string{"policy.path", "tls.cert_path", "derp.paths"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			err := CheckFiles(tt.build(t, dir))

			if len(tt.wantErr) == 0 && tt.check == nil {
				require.NoError(t, err)
				return
			}

			if len(tt.wantErr) == 0 {
				require.NoError(t, err)
			}

			for _, s := range tt.wantErr {
				require.ErrorContains(t, err, s)
			}

			if tt.check != nil {
				tt.check(t, dir, err)
			}
		})
	}
}
