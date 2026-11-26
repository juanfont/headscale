package config

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/juanfont/headscale/hscontrol/derp"
	"github.com/juanfont/headscale/hscontrol/dns"
	policyv2 "github.com/juanfont/headscale/hscontrol/policy/v2"
	"github.com/juanfont/headscale/hscontrol/types"
)

// ErrCheckFailed is a check of "headscale check all" with a line that is
// FAIL.
var ErrCheckFailed = errors.New("check failed")

// MaxFileSize is what a check, or a command of the CLI, reads at most of one
// file or of stdin, so that /dev/zero or an endless pipe is an error and not
// all of the memory.
// The server reads these files whole, with no limit of its own, so the
// limit is far above any real one: a check must not refuse a file the
// server takes.
const MaxFileSize int64 = 16 << 20

// ErrTooLarge is a file or stdin larger than [MaxFileSize].
var ErrTooLarge = errors.New("more than a command reads")

// ReadAtMost reads r, named name in its error, and fails when it holds more
// than limit bytes.
func ReadAtMost(name string, r io.Reader, limit int64) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}

	if int64(len(b)) > limit {
		return nil, fmt.Errorf("%s is larger than %d MiB, %w", name, limit>>20, ErrTooLarge)
	}

	return b, nil
}

// readFile reads the file at path, at most limit bytes of it when limit is
// not 0.
func readFile(path string, limit int64) ([]byte, error) {
	if limit == 0 {
		return os.ReadFile(path)
	}

	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ReadAtMost(path, f, limit)
}

// CheckConfig loads the configuration as serve does, from path, or found
// in the places serve searches when path is "", and validates it. The
// result is never nil: its Config is set once loading succeeded, also when
// validation fails, and its Warnings hold what loading and validation warn
// about.
func CheckConfig(path string, environ []string) (*Loaded, error) {
	return validated(loadFile(path, read{limit: MaxFileSize}, environ))
}

// CheckConfigData is [CheckConfig] of a configuration that the caller read,
// such as stdin, as [LoadData] reads it.
func CheckConfigData(name, ext string, data []byte, environ []string) (*Loaded, error) {
	l, err := LoadData(name, ext, data, environ)
	if err != nil {
		return l, fmt.Errorf("loading config file %s: %w", name, err)
	}

	return validated(l, nil)
}

func validated(l *Loaded, err error) (*Loaded, error) {
	if err != nil {
		return l, err
	}

	err = Validate(l.Config)
	l.Warnings = append(l.Warnings, Warnings(l.Config)...)

	return l, err
}

// LoadFile is [Load] of the file at path, or of the one found in the places
// serve searches when path is "", with an error that names the file.
func LoadFile(path string, environ []string) (*Loaded, error) {
	return loadFile(path, read{}, environ)
}

func loadFile(path string, r read, environ []string) (*Loaded, error) {
	l, err := load(path, path != "", r, environ)

	switch {
	case err != nil && path != "":
		return l, fmt.Errorf("loading config file %s: %w", path, err)
	case err != nil:
		return l, fmt.Errorf("loading config: %w", err)
	}

	return l, nil
}

// Source names where l came from: its file, or the defaults and the
// environment.
func (l *Loaded) Source() string {
	return cmp.Or(l.File, "(defaults and environment)")
}

// CheckPolicy checks the policy file at path as "headscale check policy"
// does, its tests and sshTests included, and counts the tests that passed.
func CheckPolicy(path string) (int, error) {
	b, err := readFile(path, MaxFileSize)
	if err != nil {
		return 0, fmt.Errorf("reading policy file: %w", err)
	}

	return CheckPolicyData(b)
}

// CheckPolicyText is [CheckPolicyData] that first refuses, as API v0 and a
// reload do, a text with a NUL byte, of only white space, or whose value is
// not an object. The old CLI, as the older APIs, takes such a text.
func CheckPolicyText(b []byte) (int, error) {
	err := policyv2.CheckPolicyText(b)
	if err != nil {
		return 0, err
	}

	return CheckPolicyData(b)
}

// CheckPolicyData is [CheckPolicy] of a policy that the caller read.
func CheckPolicyData(b []byte) (int, error) {
	err := policyv2.CheckPolicy(b)
	if err != nil {
		return 0, err
	}

	// It parsed, or CheckPolicy would have failed.
	pol, _ := policyv2.ParsePolicy(b)
	if pol == nil {
		return 0, nil
	}

	return len(pol.Tests) + len(pol.SSHTests), nil
}

// CheckDERPMapData is [CheckDERPMapFile] of a DERP map that the caller
// read: name names it in messages, ext names its format.
func CheckDERPMapData(name, ext string, b []byte) error {
	_, err := derp.ParseDERPMap(name, ext, b)

	return err
}

// CheckExtraRecordsData is [CheckExtraRecordsFile] of records that the
// caller read: name names them in messages, ext names their format.
func CheckExtraRecordsData(name, ext string, b []byte) error {
	// An empty file is no records, as the server reads one.
	if len(b) == 0 {
		return nil
	}

	_, err := dns.ParseExtraRecords(name, ext, b)

	return err
}

// CheckAll writes the report of "headscale check all" to w: the
// configuration from src, which failed with err or is cfg, then each file
// it names, with ok, FAIL (the error below it) or skip. Skip is a key file
// that startup creates when it is missing, or a "file:<path>" secret. It
// returns ErrCheckFailed when any line is FAIL.
func CheckAll(w io.Writer, cfg *types.Config, src string, err error) error {
	if err != nil {
		printCheckLine(w, "FAIL", "config", src, len("config"), err)

		return fmt.Errorf("%w: config, files not checked", ErrCheckFailed)
	}

	files := Files(cfg)

	width := len("config")
	for _, f := range files {
		width = max(width, len(f.Key))
	}

	printCheckLine(w, "ok", "config", src, width, nil)

	failed := 0

	for _, f := range files {
		err := f.Check()

		switch {
		case err == nil:
			printCheckLine(w, "ok", f.Key, f.Path, width, nil)
		case f.CreatedAtStartup && errors.Is(err, os.ErrNotExist):
			printCheckLine(w, "skip", f.Key, f.Path+" (missing; startup creates it)", width, nil)
		case errors.Is(err, ErrSecretNotRead):
			printCheckLine(w, "skip", f.Key, f.Path+" ("+err.Error()+")", width, nil)
		default:
			failed++

			printCheckLine(w, "FAIL", f.Key, f.Path, width, err)
		}
	}

	if failed > 0 {
		return fmt.Errorf("%w: %d of %d files", ErrCheckFailed, failed, len(files))
	}

	return nil
}

// printCheckLine prints one result; an error goes indented below it.
func printCheckLine(w io.Writer, status, key, path string, width int, err error) {
	fmt.Fprintf(w, "%-4s  %-*s  %s\n", status, width, key, path)

	if err != nil {
		for l := range strings.SplitSeq(err.Error(), "\n") {
			fmt.Fprintf(w, "      %s\n", l)
		}
	}
}
