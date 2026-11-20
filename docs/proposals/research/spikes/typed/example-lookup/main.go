package main

import (
	"context"
	"fmt"
	"net/netip"
	"os"

	"spike/typed"
)

// Node is what the server knows. It stands for a generated API type.
type Node struct {
	ID   uint64
	Name string
}

type api struct{ nodes map[string]Node }

func (a *api) FindNode(_ context.Context, word string) (Node, error) {
	fmt.Println("  (lookup on the server:", word+")")
	n, ok := a.nodes[word]
	if !ok {
		return Node{}, fmt.Errorf("no such node")
	}
	return n, nil
}

type routesSetIn struct {
	Node   Node           `arg:"node"`
	Routes []netip.Prefix `arg:"routes"`
}

func main() {
	client := &api{nodes: map[string]Node{"mynode": {ID: 12, Name: "mynode"}}}
	typed.RegisterLate(client.FindNode) // once, for the type Node

	root := typed.Group("prog", "", typed.Group("routes", "Manage routes",
		typed.NewTagged(typed.Command[routesSetIn]{
			Name: "set", Help: "Replace the routes of a node",
			Run: func(_ context.Context, in routesSetIn) error {
				fmt.Printf("run: node %d (%s) routes=%v\n", in.Node.ID, in.Node.Name, in.Routes)
				return nil
			},
		})))
	if err := typed.Run(context.Background(), root, os.Args[1:]); err != nil {
		fmt.Printf("Error: %v\n", err)
	}
}
