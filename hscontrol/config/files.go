// Package config checks headscale's configuration and the files it names.
// It imports types; types, derp, dns and policy must never import it.
package config

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"tailscale.com/types/key"
)

var ErrSameKey = errors.New("noise and DERP private keys must differ")

// File is one file the configuration names.
type File struct {
	Key  string // config key, e.g. "policy.path"
	Path string // as startup resolves it

	// CreatedAtStartup marks key files: startup creates them when missing,
	// so a missing one is not an error.
	CreatedAtStartup bool

	// Check parses the file. It never creates, writes or contacts anything.
	Check func() error
}

// Files lists every file cfg names, in config order, with the check for its
// kind. Paths are resolved as startup resolves them.
func Files(cfg *types.Config) []File {
	var files []File

	if cfg.Policy.Mode == types.PolicyModeFile && cfg.Policy.Path != "" {
		p := util.AbsolutePathFromConfigPath(cfg.Policy.Path)
		files = append(files, File{Key: "policy.path", Path: p, Check: func() error { return CheckPolicyFile(p) }})
	}

	for _, p := range cfg.DERP.Paths {
		files = append(files, File{Key: "derp.paths", Path: p, Check: func() error { return CheckDERPMapFile(p) }})
	}

	if p := cfg.DNSConfig.ExtraRecordsPath; p != "" {
		files = append(files, File{Key: "dns.extra_records_path", Path: p, Check: func() error { return CheckExtraRecordsFile(p) }})
	}

	if c, k := cfg.TLS.CertPath, cfg.TLS.KeyPath; c != "" {
		files = append(files, File{
			Key:   "tls.cert_path, tls.key_path",
			Path:  c + ", " + k,
			Check: func() error { _, err := tls.LoadX509KeyPair(c, k); return err },
		})
	}

	noise := cfg.NoisePrivateKeyPath
	if noise != "" {
		files = append(files, File{
			Key: "noise.private_key_path", Path: noise, CreatedAtStartup: true,
			Check: func() error { _, err := ReadPrivateKey(noise); return err },
		})
	}

	if d := cfg.DERP.ServerPrivateKeyPath; cfg.DERP.ServerEnabled && d != "" {
		files = append(files, File{
			Key: "derp.server.private_key_path", Path: d, CreatedAtStartup: true,
			Check: func() error { return checkDERPKey(d, noise) },
		})
	}

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
	_, err := derp.GetDERPMap(types.DERPConfig{Paths: []string{path}})

	return err
}

// CheckExtraRecordsFile parses a dns.extra_records_path file.
func CheckExtraRecordsFile(path string) error {
	_, _, err := dns.ReadExtraRecordsFromPath(path)

	return err
}

// ReadPrivateKey reads and parses a key file without creating anything.
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
