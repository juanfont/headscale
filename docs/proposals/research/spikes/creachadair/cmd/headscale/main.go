// Command headscale is a test binary for driving the completion scripts
// through real shells: "completion <shell>" prints the script, and
// "__complete <words>" answers Tab. Nothing else runs (the kit's Exec
// needs the suite's recorder).
package main

import (
	"context"
	"fmt"
	"os"

	"spike/creachadair"
	"spike/kit"
)

func main() {
	a, t := creachadair.Adapter{}, kit.NewTree()
	var err error
	if len(os.Args) == 3 && os.Args[1] == "completion" {
		err = a.Script(t, os.Args[2], os.Stdout)
	} else {
		err = a.Run(context.Background(), t, os.Args[1:], kit.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr})
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
