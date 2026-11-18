// Command headscale is the shell-test binary: the kit's tree, the scripts
// and the __complete entry point, nothing else.
package main

import (
	"os"

	"spike/cmdline/script"
	hs "spike/final-headscale"
	"spike/kit"
)

func main() {
	args := os.Args[1:]
	if hs.KitTree().Serve(os.Stdout, args) {
		return
	}
	if len(args) != 2 || args[0] != "completion" || script.Write(os.Stdout, args[1], kit.Program) != nil {
		os.Exit(1)
	}
}
