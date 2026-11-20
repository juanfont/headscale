//go:build newcli

package main

import (
	"os"

	"github.com/juanfont/headscale/cmd/headscale/newcli"
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
)

func main() {
	env := command.OSEnv()
	env.Releases = newcli.GitHubReleases

	os.Exit(command.Run(newcli.Tree(), os.Args[1:], env))
}
