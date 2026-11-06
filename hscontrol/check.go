package hscontrol

import (
	"crypto/tls"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
)

var errTooManyLinks = errors.New("too many symbolic links")

var errSameKey = errors.New("noise and DERP private keys must differ")

// CheckFiles parses every file the config names and reports all problems
// together. It never creates, writes or contacts anything.
func CheckFiles(cfg *types.Config) error {
	var errs []error

	if cfg.Policy.Mode == types.PolicyModeFile && cfg.Policy.Path != "" {
		b, err := os.ReadFile(util.AbsolutePathFromConfigPath(cfg.Policy.Path))
		if err == nil {
			_, err = policyv2.ParsePolicy(b)
		}

		if err != nil {
			errs = append(errs, fmt.Errorf("policy.path: %w", err))
		}
	}

	if len(cfg.DERP.Paths) > 0 {
		_, err := derp.GetDERPMap(types.DERPConfig{Paths: cfg.DERP.Paths})
		if err != nil {
			errs = append(errs, fmt.Errorf("derp.paths: %w", err))
		}
	}

	if p := cfg.DNSConfig.ExtraRecordsPath; p != "" {
		m, err := dns.NewExtraRecordsManager(p)
		if err != nil {
			errs = append(errs, fmt.Errorf("dns.extra_records_path: %w", err))
		} else {
			m.Close()
		}
	}

	if cfg.TLS.CertPath != "" {
		_, err := tls.LoadX509KeyPair(cfg.TLS.CertPath, cfg.TLS.KeyPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("loading TLS keypair (tls.cert_path=%q, tls.key_path=%q): %w",
				cfg.TLS.CertPath, cfg.TLS.KeyPath, err))
		}
	}

	noise, err := readOptionalKey(cfg.NoisePrivateKeyPath)
	if err != nil {
		errs = append(errs, fmt.Errorf("noise.private_key_path: %w", err))
	}

	if cfg.DERP.ServerEnabled {
		derpKey, err := readOptionalKey(cfg.DERP.ServerPrivateKeyPath)
		if err != nil {
			errs = append(errs, fmt.Errorf("derp.server.private_key_path: %w", err))
		} else {
			same, perr := samePath(cfg.NoisePrivateKeyPath, cfg.DERP.ServerPrivateKeyPath)

			switch {
			case perr != nil:
				errs = append(errs, perr)
			case same || noise != "" && noise == derpKey:
				errs = append(errs, fmt.Errorf("derp.server.private_key_path: %w", errSameKey))
			}
		}
	}

	return errors.Join(errs...)
}

// readOptionalKey returns the key text, or "" when unset or not yet created.
func readOptionalKey(path string) (string, error) {
	if path == "" {
		return "", nil
	}

	k, err := readPrivateKey(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}

	if err != nil {
		return "", err
	}

	b, err := k.MarshalText()

	return string(b), err
}

// samePath catches a shared key file that does not exist yet, which the
// content comparison cannot see but startup rejects after creating it.
// A path that cannot be resolved is an error: startup would fail on it too.
func samePath(noise, derp string) (bool, error) {
	if noise == "" || derp == "" {
		return false, nil
	}

	rn, err := resolveLoose(noise)
	if err != nil {
		return false, fmt.Errorf("noise.private_key_path: %w", err)
	}

	rd, err := resolveLoose(derp)
	if err != nil {
		return false, fmt.Errorf("derp.server.private_key_path: %w", err)
	}

	return rn == rd, nil
}

// maxSymlinks bounds link expansion so a loop cannot hang the check.
const maxSymlinks = 255

// resolveLoose resolves p like `realpath -m`: symlinks are followed
// component by component, including dangling ones, and names that do not
// exist are kept as-is. p is not cleaned first: ".." after a symlink walks
// the link target, not the lexical parent.
func resolveLoose(p string) (string, error) {
	if !filepath.IsAbs(p) {
		wd, err := os.Getwd()
		if err != nil {
			return "", err
		}

		p = wd + string(filepath.Separator) + p
	}

	sep := string(filepath.Separator)
	queue := strings.Split(p, sep)
	cur := sep
	links := 0

	for len(queue) > 0 {
		c := queue[0]
		queue = queue[1:]

		switch c {
		case "", ".":
			continue
		case "..":
			cur = filepath.Dir(cur)

			continue
		}

		next := filepath.Join(cur, c)

		fi, err := os.Lstat(next)
		if errors.Is(err, os.ErrNotExist) {
			// A missing name cannot be a link, but a later ".." may
			// climb back into existing directories whose links count.
			cur = next

			continue
		}

		if err != nil {
			return "", err
		}

		if fi.Mode()&os.ModeSymlink == 0 {
			cur = next

			continue
		}

		links++
		if links > maxSymlinks {
			return "", fmt.Errorf("%w resolving %q", errTooManyLinks, p)
		}

		target, err := os.Readlink(next)
		if err != nil {
			return "", err
		}

		if filepath.IsAbs(target) {
			cur = sep
		}

		queue = append(strings.Split(target, sep), queue...)
	}

	return cur, nil
}
