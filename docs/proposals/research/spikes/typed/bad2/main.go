package main

import (
	"net/netip"

	"spike/typed"
)

type in struct{ Route netip.Prefix }

// netip.Prefix has no Parse method of its own
func (i *in) Bind(b *typed.Binder) { b.Flag(&i.Route, "route", "A route") }

func main() {}
