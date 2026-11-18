package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"time"

	"spike/typed"
)

// Expiry reads itself with Go's standard interface: a duration, or "never".
type Expiry struct {
	Never bool
	In    time.Duration
}

func (e *Expiry) UnmarshalText(b []byte) error {
	if string(b) == "never" {
		*e = Expiry{Never: true}
		return nil
	}
	d, err := time.ParseDuration(string(b))
	*e = Expiry{In: d}
	return err
}

// NodeRef is a node as typed; a later step looks it up.
type NodeRef string

func (n *NodeRef) UnmarshalText(b []byte) error {
	if len(b) == 0 {
		return errors.New("is empty")
	}
	*n = NodeRef(b)
	return nil
}

type routesSetIn struct {
	Node    NodeRef           `arg:"node"`
	Routes  []netip.Prefix    `arg:"routes"`
	From    netip.Addr        `flag:"from" help:"Source address"`
	Expiry  typed.Opt[Expiry] `flag:"expiry" help:"When it ends"`
	Timeout time.Duration     `flag:"timeout" help:"How long to wait"`
	Force   bool              `flag:"force" help:"Do not ask"`
}

// time.Duration has no UnmarshalText, so it is the one type to register.
func init() { typed.Register(time.ParseDuration) }

func tree() typed.Node {
	return typed.Group("prog", "",
		typed.Group("routes", "Manage routes",
			typed.NewTagged(typed.Command[routesSetIn]{
				Name: "set", Help: "Replace the routes of a node", Aliases: []string{"approve"},
				Run: func(_ context.Context, in routesSetIn) error {
					e, given := in.Expiry.Get()
					fmt.Printf("node=%s routes=%v from=%v expiry=%+v given=%v timeout=%v force=%v\n",
						in.Node, in.Routes, in.From, e, given, in.Timeout, in.Force)
					return nil
				},
			}),
		),
	)
}

func main() {
	if len(os.Args) > 1 && os.Args[1] == "config" {
		// The same method reads the type from a config file.
		var cfg struct {
			Expiry Expiry       `json:"expiry"`
			Route  netip.Prefix `json:"route"`
		}
		err := json.Unmarshal([]byte(os.Args[2]), &cfg)
		fmt.Printf("%+v err=%v\n", cfg, err)
		return
	}
	if err := typed.Run(context.Background(), tree(), os.Args[1:]); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
