package main

import (
	"fmt"
	"strings"
	"testing"

	"spike/cmdline"
)

func TestProbe2(t *testing.T) {
	for _, l := range []string{"-c|items|items|list", "items|delete|12|-hf", "-o|a|items|-o|b|list|-o|c", "items|delete|12|--force|--force=false", "-h|items|-o|json", "items|list|--name", "items|delete|--force|-h|12", "-c|x|items|-c|y|lst"} {
		m, err := cmdline.Parse(tree(), strings.Split(l, "|"))
		s := fmt.Sprintf("Path=%q Flags=%v Args=%q ArgAt=%v", m.Path, m.Flags, m.Args, m.ArgAt)
		if e, ok := err.(*cmdline.Error); ok {
			s += fmt.Sprintf(" ERR Kind=%d Path=%q Word=%q At=%d", e.Kind, e.Path, e.Word, e.At)
		}
		t.Logf("PARSE %q => %s", l, s)
	}
	for _, w := range [][2]string{{"items list --sort", ""}, {"-o json items list", "--"}, {"items delete", "-"}, {"items list", "--sort=i"}, {"items list", "-o=y"}} {
		var words []string
		if w[0] != "" {
			words = strings.Split(w[0], " ")
		}
		c, d := cmdline.Complete(tree(), words, w[1])
		t.Logf("COMPLETE %q %q => %q %d", words, w[1], c, d)
	}
}
