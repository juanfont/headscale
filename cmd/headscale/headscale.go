package main

import (
	"log"

	"github.com/juanfont/headscale/cmd/headscale/cli"
)

func main() {
	err := cli.LoadConfig("")
	if err != nil {
		log.Fatalf(err.Error())
	}

	cli.Execute()
}
