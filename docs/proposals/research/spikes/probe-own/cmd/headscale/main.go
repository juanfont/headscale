// Command headscale is the probe binary: completion scripts, __complete, and
// a dump of what the dispatcher parsed.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	own "probe-own"
	cs "probe-own/cobrascripts"
)

func main() {
	root, args := own.Tree(), os.Args[1:]
	if len(args) > 0 && (args[0] == cs.ShellCompRequestCmd || args[0] == cs.ShellCompNoDescRequestCmd) {
		own.Serve(os.Stdout, root, args[1:], args[0] == cs.ShellCompRequestCmd)
		return
	}
	if len(args) == 2 && args[0] == "completion" {
		if cs.Script(os.Stdout, args[1], "headscale", true) {
			return
		}
	}
	p, err := own.Dispatch(root, args, own.PflagParse)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"path": p.Path, "values": p.Values, "args": p.Args})
}
