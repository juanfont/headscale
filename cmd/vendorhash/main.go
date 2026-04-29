// vendorhash maintains the Nix SRI hash for the Go module vendor tree
// and stores it in flakehashes.json alongside a content fingerprint of
// go.mod and go.sum.
//
// Each block records its input fingerprint (goModSum) so that re-runs
// with no input change are essentially free: the fast path is just a
// sha256 over two small files. The vendor tree is only re-walked when
// the fingerprint actually drifts.
//
// Subcommands:
//
//	vendorhash check   exit non-zero if flakehashes.json is stale
//	vendorhash update  recompute and rewrite flakehashes.json
//
// The JSON schema and goModFingerprint algorithm mirror upstream
// tailscale's tool/updateflakes so a future shared library extraction
// is straightforward.
package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"

	"tailscale.com/cmd/nardump/nardump"
)

const (
	hashesFile = "flakehashes.json"
	goModFile  = "go.mod"
	goSumFile  = "go.sum"
)

type FlakeHashes struct {
	Vendor VendorBlock `json:"vendor"`
}

type VendorBlock struct {
	GoModSum string `json:"goModSum"`
	SRI      string `json:"sri"`
}

func main() {
	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	ctx := context.Background()

	var err error

	switch os.Args[1] {
	case "check":
		err = cmdCheck(ctx)
	case "update":
		err = cmdUpdate(ctx)
	case "-h", "--help", "help":
		usage()
		return
	default:
		usage()
		os.Exit(2)
	}

	if err != nil {
		if errors.Is(err, errStale) {
			os.Exit(1)
		}

		fmt.Fprintln(os.Stderr, "vendorhash:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: vendorhash <check|update>")
}

// errStale signals to main that the check found a mismatch; it has
// already printed a remediation message, so main should exit 1
// silently.
var errStale = errors.New("vendor hash stale")

// cmdCheck verifies that flakehashes.json matches the current
// go.mod/go.sum. The fast path (fingerprint unchanged) costs only
// a sha256 over the two files. On mismatch, it computes the actual
// SRI so the failure message gives the developer the value to paste
// (or to run `vendorhash update`).
func cmdCheck(ctx context.Context) error {
	hashes, err := loadHashes()
	if err != nil {
		return err
	}

	curFP, err := goModFingerprint()
	if err != nil {
		return err
	}

	if curFP == hashes.Vendor.GoModSum {
		return nil
	}

	curSRI, err := hashVendor(ctx)
	if err != nil {
		return err
	}

	fmt.Fprintln(os.Stderr, "vendor hash is stale.")
	fmt.Fprintf(os.Stderr, "  expected goModSum: %s\n", hashes.Vendor.GoModSum)
	fmt.Fprintf(os.Stderr, "    actual goModSum: %s\n", curFP)
	fmt.Fprintf(os.Stderr, "       expected sri: %s\n", hashes.Vendor.SRI)
	fmt.Fprintf(os.Stderr, "         actual sri: %s\n", curSRI)
	fmt.Fprintln(os.Stderr, "run: go run ./cmd/vendorhash update")
	// Also emit machine-parseable lines so CI can pick them up.
	fmt.Printf("expected_sri=%s\n", hashes.Vendor.SRI)
	fmt.Printf("actual_sri=%s\n", curSRI)

	return errStale
}

func cmdUpdate(ctx context.Context) error {
	fp, err := goModFingerprint()
	if err != nil {
		return err
	}

	sri, err := hashVendor(ctx)
	if err != nil {
		return err
	}

	return writeHashes(FlakeHashes{
		Vendor: VendorBlock{
			GoModSum: fp,
			SRI:      sri,
		},
	})
}

// goModFingerprint returns a content fingerprint of go.mod and go.sum
// that changes whenever either file changes. The byte layout matches
// upstream tailscale's tool/updateflakes.
func goModFingerprint() (string, error) {
	h := sha256.New()

	for _, f := range []string{goModFile, goSumFile} {
		b, err := os.ReadFile(f)
		if err != nil {
			return "", err
		}

		fmt.Fprintf(h, "%s %d\n", f, len(b))
		h.Write(b)
	}

	return "sha256-" + base64.StdEncoding.EncodeToString(h.Sum(nil)), nil
}

// hashVendor runs `go mod vendor` into a temporary directory and
// returns the Nix SRI hash of the resulting tree.
func hashVendor(ctx context.Context) (string, error) {
	out, err := os.MkdirTemp("", "nar-vendor-")
	if err != nil {
		return "", err
	}
	// `go mod vendor -o` requires the destination to not already exist.
	err = os.Remove(out)
	if err != nil {
		return "", err
	}

	defer os.RemoveAll(out)

	cmd := exec.CommandContext(ctx, "go", "mod", "vendor", "-o", out)

	cmd.Env = append(os.Environ(), "GOWORK=off")
	cmd.Stderr = os.Stderr

	err = cmd.Run()
	if err != nil {
		return "", fmt.Errorf("go mod vendor: %w", err)
	}

	return nardump.SRI(os.DirFS(out))
}

func loadHashes() (FlakeHashes, error) {
	var h FlakeHashes

	b, err := os.ReadFile(hashesFile)
	if err != nil {
		return h, err
	}

	err = json.Unmarshal(b, &h)
	if err != nil {
		return h, fmt.Errorf("%s: %w", hashesFile, err)
	}

	return h, nil
}

func writeHashes(h FlakeHashes) error {
	b, err := json.MarshalIndent(h, "", "  ")
	if err != nil {
		return err
	}

	b = append(b, '\n')

	// flakehashes.json is committed source read by Nix during evaluation;
	// world-readable matches every other tracked file in the repo.
	return os.WriteFile(hashesFile, b, 0o644) //nolint:gosec
}
