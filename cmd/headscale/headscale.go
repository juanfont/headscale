//go:build !newcli

package main

import (
	"github.com/juanfont/headscale/cmd/headscale/cli"
	"github.com/rs/zerolog"
)

func main() {
	// zerolog's default, which the old CLI has always started with.
	consoleLog(zerolog.DebugLevel)

	cli.Execute()
}
