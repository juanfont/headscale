// Tiny binary for driving Tab through real shells: the kit's tree behind the
// urfave adapter. Completion requests never reach Exec, so no kit context is needed.
package main

import (
	"context"
	"fmt"
	"os"

	"spike/kit"
	"spike/urfave"
)

func main() {
	a, t := urfave.Adapter{}, kit.NewTree()
	if len(os.Args) > 1 && os.Args[1] == "__complete" { // referee: cobra-protocol entry point
		c, err := a.Complete(context.Background(), t, os.Args[2:])
		if err != nil {
			fmt.Println(":1")
			return
		}
		urfave.Answer(os.Stdout, c)
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "completion" {
		if err := a.Script(t, os.Args[2], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if err := a.Run(context.Background(), t, os.Args[1:], kit.Stdio{In: os.Stdin, Out: os.Stdout, Err: os.Stderr}); err != nil {
		fmt.Fprintln(os.Stderr, "Error:", err)
		os.Exit(1)
	}
}
