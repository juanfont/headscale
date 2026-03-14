package main

import (
	"fmt"

	"github.com/rs/xid"
)

func main() {
	fmt.Print(xid.New().String())
}
