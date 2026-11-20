package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"time"

	"spike/typed"
)

// Expiry reads itself: a duration, or "never".
type Expiry struct {
	Never bool
	In    time.Duration
}

func (Expiry) Parse(s string) (Expiry, error) {
	if s == "never" {
		return Expiry{Never: true}, nil
	}
	d, err := time.ParseDuration(s)
	return Expiry{In: d}, err
}

// NodeRef is a node as typed; a later step looks it up.
type NodeRef string

func (NodeRef) Parse(s string) (NodeRef, error) {
	if s == "" {
		return "", fmt.Errorf("is empty")
	}
	return NodeRef(s), nil
}

type routesSetIn struct {
	Node   NodeRef
	Routes []netip.Prefix
	Expiry typed.Opt[Expiry]
	Force  bool
}

func (in *routesSetIn) Bind(b *typed.Binder) {
	b.Arg(&in.Node, "node")
	b.ArgFunc(&in.Routes, "routes", typed.List(netip.ParsePrefix))
	b.FlagFunc(&in.Expiry, "expiry", typed.Given(typed.Self[Expiry]()), "When it ends")
	b.FlagFunc(&in.Force, "force", typed.Bool, "Do not ask")
}

var root = typed.Group("prog", "",
	typed.Group("routes", "Manage routes",
		typed.New(typed.Command[routesSetIn]{
			Name: "set", Help: "Replace the routes of a node", Aliases: []string{"approve"},
			Run: func(_ context.Context, in routesSetIn) error {
				e, given := in.Expiry.Get()
				fmt.Printf("node=%s routes=%v expiry=%+v given=%v force=%v\n", in.Node, in.Routes, e, given, in.Force)
				return nil
			},
		}),
	),
)

func main() {
	if err := typed.Run(context.Background(), root, os.Args[1:]); err != nil {
		fmt.Printf("Error: %v (%T)\n", err, err)
	}
}
