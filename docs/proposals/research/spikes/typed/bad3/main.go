package main

import (
	"time"

	"spike/typed"
)

type in struct{ Routes []string }

// the parser gives a Duration, the field is []string
func (i *in) Bind(b *typed.Binder) { b.FlagFunc(&i.Routes, "routes", time.ParseDuration, "Routes") }

func main() {}
