package main

import (
	"context"
	"os"

	"github.com/urfave/cli/v3"
)

func main() {
	_ = (&cli.Command{Name: "x", Commands: []*cli.Command{{Name: "a", Flags: []cli.Flag{&cli.StringFlag{Name: "s"}}}}}).Run(context.Background(), os.Args)
}
