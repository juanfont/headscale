// Command tailscale-versions regenerates integration/tailscale-versions.json:
// the bare version list the suite tests (from capver) plus the per-arch
// registry pins (manifest digest + nix sha256) the offline nix checks load.
//
// It is wired as a //go:generate step in the integration package so a capver
// bump refreshes the pins in the same `make generate` pass as capver itself. It
// shells out to nix-prefetch-docker, so it runs in the nix dev shell — but only
// for tags that aren't already pinned: a routine generate with an unchanged
// version set makes no network call and rewrites nothing.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"regexp"

	"github.com/juanfont/headscale/hscontrol/capver"
)

// versionsJSONPath is relative to the integration package directory, which is
// the working directory go:generate runs this command from.
const versionsJSONPath = "tailscale-versions.json"

// genArches are the docker architectures pinned for every image. The registry
// images are multi-arch, so the imageDigest (the manifest index) is shared and
// only the nix sha256 differs per arch; pullImage selects by the build system.
var genArches = []string{"amd64", "arm64"}

var (
	reImageDigest = regexp.MustCompile(`imageDigest = "([^"]+)"`)
	reHash        = regexp.MustCompile(`hash = "([^"]+)"`)

	errPrefetchEmpty = errors.New("nix-prefetch-docker produced no digest/hash (rate limited? retry)")
)

// imageRef pins a multi-arch registry image for dockerTools.pullImage.
type imageRef struct {
	ImageName     string            `json:"imageName"`
	FinalImageTag string            `json:"finalImageTag"`
	ImageDigest   string            `json:"imageDigest"`
	SHA256        map[string]string `json:"sha256"`
}

// complete reports whether the pin already has a digest and every arch hash, so
// it can be reused without re-hitting the registry.
func (r imageRef) complete() bool {
	if r.ImageDigest == "" {
		return false
	}

	for _, a := range genArches {
		if r.SHA256[a] == "" {
			return false
		}
	}

	return true
}

// versionsFile is the single source of truth shared by the Go suite
// (MustTestVersions reads .versions) and the nix image pins (images.nix reads
// .images / .postgres). See integration/tailscale-versions.json.
type versionsFile struct {
	Versions []string            `json:"versions"`
	Images   map[string]imageRef `json:"images"`
	Postgres imageRef            `json:"postgres"`
}

func main() {
	err := run()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tailscale-versions:", err)
		os.Exit(1)
	}
}

func run() error {
	_, must := capver.IntegrationVersions()

	prev := readExisting()

	out := versionsFile{Versions: must, Images: map[string]imageRef{}}

	for _, v := range must {
		// head is built from source, not pulled.
		if v == "head" {
			continue
		}

		repo, tag := "ghcr.io/tailscale/tailscale", "v"+v
		if v == "unstable" {
			repo, tag = "tailscale/tailscale", "unstable"
		}

		ref, err := pinOrReuse(prev.Images[tag], repo, tag)
		if err != nil {
			return err
		}

		out.Images[tag] = ref
	}

	postgres, err := pinOrReuse(prev.Postgres, "postgres", "16")
	if err != nil {
		return err
	}

	out.Postgres = postgres

	return writeIfChanged(out)
}

// pinOrReuse keeps an already-complete pin so a routine generate makes no
// network call; only new or incomplete tags are prefetched. To deliberately
// refresh a mutable tag (unstable, postgres) delete its entry first.
func pinOrReuse(prev imageRef, repo, tag string) (imageRef, error) {
	if prev.complete() {
		return prev, nil
	}

	return pinImage(context.Background(), repo, tag)
}

// readExisting loads the current pins, or an empty file if absent/unparseable
// (a full regeneration).
func readExisting() versionsFile {
	vf := versionsFile{Images: map[string]imageRef{}}

	b, err := os.ReadFile(versionsJSONPath)
	if err != nil {
		return vf
	}

	err = json.Unmarshal(b, &vf)
	if err != nil {
		return versionsFile{Images: map[string]imageRef{}}
	}

	if vf.Images == nil {
		vf.Images = map[string]imageRef{}
	}

	return vf
}

// writeIfChanged only touches the file when the rendered JSON differs, so a
// no-op generate leaves the working tree (and git) clean.
func writeIfChanged(out versionsFile) error {
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("marshalling versions: %w", err)
	}

	b = append(b, '\n')

	old, err := os.ReadFile(versionsJSONPath)
	if err == nil && bytes.Equal(old, b) {
		fmt.Printf("%s already up to date\n", versionsJSONPath)

		return nil
	}

	err = os.WriteFile(versionsJSONPath, b, 0o600)
	if err != nil {
		return fmt.Errorf("writing %s: %w", versionsJSONPath, err)
	}

	fmt.Printf("wrote %s\n", versionsJSONPath)

	return nil
}

// pinImage prefetches repo:tag for every arch via nix-prefetch-docker and
// returns the shared manifest digest plus per-arch nix hashes.
func pinImage(ctx context.Context, repo, tag string) (imageRef, error) {
	ref := imageRef{ImageName: repo, FinalImageTag: tag, SHA256: map[string]string{}}

	for _, arch := range genArches {
		cmd := exec.CommandContext(ctx, "nix", "run", "nixpkgs#nix-prefetch-docker", "--",
			"--image-name", repo, "--image-tag", tag, "--arch", arch, "--os", "linux")

		var stdout bytes.Buffer

		cmd.Stdout = &stdout

		err := cmd.Run()
		if err != nil {
			return imageRef{}, fmt.Errorf("prefetch %s:%s (%s): %w", repo, tag, arch, err)
		}

		digest := firstSubmatch(reImageDigest, stdout.String())
		hash := firstSubmatch(reHash, stdout.String())

		if digest == "" || hash == "" {
			return imageRef{}, fmt.Errorf("%s:%s (%s): %w", repo, tag, arch, errPrefetchEmpty)
		}

		ref.ImageDigest = digest
		ref.SHA256[arch] = hash
	}

	return ref, nil
}

func firstSubmatch(re *regexp.Regexp, s string) string {
	m := re.FindStringSubmatch(s)
	if len(m) < 2 {
		return ""
	}

	return m[1]
}
