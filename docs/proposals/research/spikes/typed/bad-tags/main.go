package main

import (
	"context"
	"time"

	"spike/typed"
)

// time.Duration has no reader: it has no UnmarshalText and nobody registered
// one. The build passes; NewTagged stops the program when it starts.
type in struct {
	Wait time.Duration `flag:"wait" help:"How long to wait"`
}

func main() {
	typed.NewTagged(typed.Command[in]{Name: "x", Run: func(context.Context, in) error { return nil }})
}
