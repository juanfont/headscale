package main

import (
	"context"

	"spike/typed"
)

// no Bind method
type in struct{ Force bool }

var _ = typed.New(typed.Command[in]{Name: "x", Run: func(context.Context, in) error { return nil }})

func main() {}
