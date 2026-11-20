// Package stdflag records what the standard library's flag package does with
// Headscale's argv shapes (variant 3).
package stdflag

import (
	"bytes"
	"flag"
	"strings"
	"testing"
)

func TestStdlib(t *testing.T) {
	for _, line := range []string{
		"12 --force", "--force 12", "-ojson", "-o=json", "-o json", "--output json",
		"--sort -last-seen", "--force=false", "-- -12", "-", "--forc 12", "-x",
	} {
		var out bytes.Buffer
		fs := flag.NewFlagSet("delete", flag.ContinueOnError)
		fs.SetOutput(&out)
		force := fs.Bool("force", false, "")
		o := fs.String("o", "", "")
		fs.StringVar(o, "output", "", "") // short and long are two flags
		sort := fs.String("sort", "", "")
		err := fs.Parse(strings.Fields(line))
		t.Logf("%-20q force=%v o=%q sort=%q args=%q err=%v (%T) printed=%d bytes",
			line, *force, *o, *sort, fs.Args(), err, err, out.Len())
	}
}
