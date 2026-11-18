// Command headscale is the shell-test binary: the kit's tree, the scripts
// and the __complete entry point, nothing else.
package main

import (
	"os"

	"spike/cmdline"
	"spike/cmdline/script"
	"spike/kit"
	libhs "spike/lib-headscale"
)

func main() {
	args := os.Args[1:]
	if cmdline.Serve(os.Stdout, libhs.Root(kit.NewTree()), args) {
		return
	}
	if len(args) != 2 || args[0] != "completion" || script.Write(os.Stdout, args[1], kit.Program) != nil {
		os.Exit(1)
	}
}
