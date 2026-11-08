// Package config checks headscale's configuration and the files it names.
// It imports types; types, derp, dns and policy must never import it.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"tailscale.com/types/key"
)

var (
	ErrSameKey = errors.New("noise and DERP private keys must differ")

	// ErrSecretNotRead is the check of a file: secret: no check reads one.
	ErrSecretNotRead = errors.New("secret, not read")
)

// File is one file the configuration names.
type File struct {
	Key  string // config key, e.g. "policy.path"
	Path string // as startup resolves it; a secret's as written

	// CreatedAtStartup marks key files: startup creates them when missing,
	// so a missing one is not an error.
	CreatedAtStartup bool

	// Check parses the file.
	Check func() error
}

// Files lists every file cfg names, in config order, with the check for its
// kind. Paths are resolved as startup resolves them.
func Files(cfg *types.Config) []File {
	var files []File

	if cfg.Policy.Mode == types.PolicyModeFile && cfg.Policy.Path != "" {
		p := cfg.AbsPath(cfg.Policy.Path)
		files = append(files, File{Key: "policy.path", Path: p, Check: func() error { return CheckPolicyFile(p) }})
	}

	for _, p := range cfg.DERP.Paths {
		files = append(files, File{Key: "derp.paths", Path: p, Check: func() error { return CheckDERPMapFile(p) }})
	}

	if p := cfg.DNSConfig.ExtraRecordsPath; p != "" {
		files = append(files, File{Key: "dns.extra_records_path", Path: p, Check: func() error { return CheckExtraRecordsFile(p) }})
	}

	if c, k := cfg.AbsPath(cfg.TLS.CertPath), cfg.AbsPath(cfg.TLS.KeyPath); c != "" {
		files = append(files, File{
			Key:   "tls.cert_path, tls.key_path",
			Path:  c + ", " + k,
			Check: func() error { _, err := tls.LoadX509KeyPair(c, k); return err },
		})
	}

	noise := cfg.AbsPath(cfg.Noise.PrivateKeyPath)
	if noise != "" {
		files = append(files, File{
			Key: "noise.private_key_path", Path: noise, CreatedAtStartup: true,
			Check: func() error { _, err := ReadPrivateKey(noise); return err },
		})
	}

	if d := cfg.AbsPath(cfg.DERP.Server.PrivateKeyPath); cfg.DERP.Server.Enabled && d != "" {
		files = append(files, File{
			Key: "derp.server.private_key_path", Path: d, CreatedAtStartup: true,
			Check: func() error { return checkDERPKey(d, noise) },
		})
	}

	return append(files, secretFiles(cfg)...)
}

// secretFiles lists, by key, each file: secret startup reads, unread.
func secretFiles(cfg *types.Config) []File {
	var files []File

	add := func(key string, s types.Secret) {
		if s.IsFile() {
			files = append(files, File{
				Key: key, Path: strings.TrimPrefix(string(s), "file:"),
				Check: func() error { return ErrSecretNotRead },
			})
		}
	}

	if cfg.Database.Type == types.DatabasePostgres {
		add("database.postgres.pass", cfg.Database.Postgres.Pass)
	}

	if cfg.OIDC.Issuer != "" {
		add("oidc.client_secret", cfg.OIDC.ClientSecret)
	}

	// Startup builds the provider from its settings only without a Go-only
	// one. Bad settings are the loader's to report; this only collects keys.
	if cfg.DNSConfig.Challenge.Provider == nil && cfg.DNSConfig.Challenge.ProviderName() != "" {
		_, _ = cfg.DNSConfig.Challenge.NewProvider(func(key, value string) (string, error) {
			add(key, types.Secret(value))

			if types.Secret(value).IsFile() {
				return value, dns.ErrSecretUnread
			}

			return value, nil
		})
	}

	slices.SortFunc(files, func(a, b File) int { return strings.Compare(a.Key, b.Key) })

	return files
}

// CheckPolicyFile checks a policy file as "headscale check policy" does,
// tests and sshTests included.
func CheckPolicyFile(path string) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	return policyv2.CheckPolicy(b)
}

// CheckDERPMapFile parses a DERP map file as startup loads derp.paths.
func CheckDERPMapFile(path string) error {
	_, err := derp.GetDERPMap(types.DERPConfig{Paths: []string{path}}, "")

	return err
}

// CheckExtraRecordsFile parses a dns.extra_records_path file.
func CheckExtraRecordsFile(path string) error {
	_, _, err := dns.ReadExtraRecordsFromPath(path)

	return err
}

// ReadPrivateKey reads and parses a key file.
func ReadPrivateKey(path string) (*key.MachinePrivate, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading private key file: %w", err)
	}

	var k key.MachinePrivate

	err = k.UnmarshalText([]byte(strings.TrimSpace(string(b))))
	if err != nil {
		return nil, fmt.Errorf("parsing private key: %w", err)
	}

	return &k, nil
}

func checkDERPKey(derpPath, noisePath string) error {
	d, err := ReadPrivateKey(derpPath)
	if err != nil {
		return err
	}

	// A noise key that cannot be read fails on its own line.
	n, err := ReadPrivateKey(noisePath)
	if err == nil && d.Equal(*n) {
		return ErrSameKey
	}

	return nil
}
