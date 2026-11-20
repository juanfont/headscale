package main

import (
	"flag"
	"fmt"
	"os"
	"text/template"
)

func main() {
	fs := flag.NewFlagSet("x", flag.ContinueOnError)
	s := fs.String("s", "", "")
	_ = fs.Parse(os.Args[1:])
	_ = template.Must(template.New("").Parse("{{.}}")).Execute(os.Stdout, *s)
	fmt.Println()
}
