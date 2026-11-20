package main

import (
	"os"

	"spike/cmdline"
	"spike/cmdline/script"
)

func main() {
	root := &cmdline.Command{Name: "eqp", Commands: []*cmdline.Command{
		{Name: "list", Flags: []cmdline.Flag{{Name: "filter", Complete: cmdline.Words("name=web", "name=db")}}},
	}}
	if cmdline.Serve(os.Stdout, root, os.Args[1:]) {
		return
	}
	script.Write(os.Stdout, os.Args[2], "eqp")
}
