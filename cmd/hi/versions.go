package main

import (
	"fmt"
	"strings"

	"github.com/creachadair/command"
	"github.com/juanfont/headscale/integration"
)

// listTailscaleImages prints the Tailscale Docker images the integration
// suite needs to pull at runtime. The list is sourced from
// integration.MustTestVersions so CI and the test runner agree on a
// single source of truth. "head" and "unstable" are excluded because
// they are built locally from Dockerfile.tailscale-HEAD, not pulled.
func listTailscaleImages(_ *command.Env) error {
	for _, v := range integration.MustTestVersions {
		if v == "head" || v == "unstable" {
			continue
		}

		fmt.Println("tailscale/tailscale:v" + strings.TrimPrefix(v, "v"))
	}

	return nil
}

// listGolangImage prints the golang Docker image reference matching the
// Go toolchain in go.mod. Used by CI to pre-pull the image so hi doctor
// does not need to hit Docker Hub at test time.
func listGolangImage(_ *command.Env) error {
	fmt.Println("golang:" + detectGoVersion())

	return nil
}
