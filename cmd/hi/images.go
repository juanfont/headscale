package main

import (
	"fmt"

	"github.com/creachadair/command"
	"github.com/juanfont/headscale/hscontrol/capver"
)

// listImages prints all Docker Hub images required by integration tests.
// This is used by CI to pre-pull images once and distribute them as
// artifacts, avoiding Docker Hub rate limits on individual test jobs.
func listImages(env *command.Env) error {
	goVersion := detectGoVersion()
	fmt.Printf("golang:%s\n", goVersion)

	fmt.Println("postgres:latest")

	// MustTestVersions from integration/scenario.go:
	//   AllVersions[0:4] + AllVersions[len-2:]
	// AllVersions = ["head", "unstable", ...latest..., ...oldest...]
	allVersions := append(
		[]string{"head", "unstable"},
		capver.TailscaleLatestMajorMinor(
			capver.SupportedMajorMinorVersions, true,
		)...,
	)

	mustTestVersions := append(
		allVersions[0:4],
		allVersions[len(allVersions)-2:]...,
	)

	for _, v := range mustTestVersions {
		switch v {
		case "head":
			// Built locally, not pulled from Docker Hub.
			continue
		case "unstable":
			fmt.Printf("tailscale/tailscale:%s\n", v)
		default:
			fmt.Printf("tailscale/tailscale:v%s\n", v)
		}
	}

	return nil
}
