// Tiny binary for driving completion through real shells.
package main

import (
	"context"
	"fmt"
	"os"
	"strings"

	"spike/kit"

	cobraadapter "spike/cobra"
)

func main() {
	a, args := cobraadapter.Adapter{}, os.Args[1:]
	var err error
	switch {
	case len(args) == 2 && args[0] == "completion":
		err = a.Script(kit.NewTree(), args[1], os.Stdout)
	case len(args) > 0 && strings.HasPrefix(args[0], "__complete"):
		err = a.CompleteRaw(context.Background(), kit.NewTree(), args[1:], os.Stdout)
	default:
		err = fmt.Errorf("probe binary: only completion and __complete")
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
