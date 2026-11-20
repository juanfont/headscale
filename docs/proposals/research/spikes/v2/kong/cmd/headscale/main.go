// Command headscale is the spike binary: the kit's tree behind the kong adapter.
package main

import (
	"context"
	"fmt"
	"os"

	"spike/kit"
	kongadapter "spike/kong"
)

func main() {
	a, t := kongadapter.Adapter{}, kit.NewTree()
	args := os.Args[1:]
	// WA: cobra's scripts call `headscale __complete <words…>`; answered before kong, as cobra does.
	if len(args) > 0 && args[0] == "__complete" { // WA
		c, err := a.Complete(context.Background(), t, args[1:])
		if err != nil {
			fmt.Println(":1")
			return
		}
		kongadapter.Answer(os.Stdout, c)
		return
	}
	// The kit's completion spec only records; the spike prints the script directly.
	if len(args) == 2 && args[0] == "completion" {
		if err := a.Script(t, args[1], os.Stdout); err != nil {
			fmt.Fprintln(os.Stderr, "Error:", err)
			os.Exit(1)
		}
		return
	}
	fmt.Fprintln(os.Stderr, "spike: only __complete and completion <shell> are wired")
	os.Exit(1)
}
