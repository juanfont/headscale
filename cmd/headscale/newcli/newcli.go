// Package newcli is the command tree of the headscale CLI: one spec per
// command, run by the builder in package command. It replaces the cobra
// CLI in cmd/headscale/cli, and is built with the build tag newcli until
// it does.
package newcli

import (
	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
)

// commands is the tree, in the order the root help lists it.
var commands = []command.Node{
	versionCmd,
	completionCmd,
	nodesGroup,
	usersGroup,
	apiGroup,
	debugGroup,
}

// Tree builds the command tree. It panics on a wrong spec, which is a
// fault in the program; a test builds the tree first.
func Tree() *command.Tree {
	t, err := command.Build("headscale", "headscale is an open source implementation of the Tailscale control server", commands...)
	if err != nil {
		panic(err)
	}

	return t
}
