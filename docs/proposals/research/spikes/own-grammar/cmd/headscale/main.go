// Command headscale is the shell-test binary: the kit's tree, the scripts and
// the __complete entry point, nothing else.
package main

import (
	"os"

	"spike/kit"
	own "spike/own-grammar"
)

func main() {
	t, args := kit.NewTree(), os.Args[1:]
	switch {
	case len(args) > 0 && (args[0] == "__complete" || args[0] == "__completeNoDesc"):
		own.Serve(t, os.Stdout, args[1:])
	case len(args) == 2 && args[0] == "completion":
		if err := (own.Adapter{}).Script(t, args[1], os.Stdout); err != nil {
			os.Exit(1)
		}
	default:
		os.Exit(1)
	}
}
