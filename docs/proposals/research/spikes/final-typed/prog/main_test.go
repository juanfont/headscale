package main

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"spike/cmdline"
)

// TestTree: New accepts the tree; tree panics when it does not.
func TestTree(t *testing.T) { tree() }

// TestParse: a line, and the structs it fills.
func TestParse(t *testing.T) {
	line, err := tree().Parse([]string{"-c", "x.yaml", "items", "ls", "--columns", "id,-name", "--name="})
	if err != nil {
		t.Fatal(err)
	}
	in, _ := cmdline.Get[listIn](line)
	c, _ := cmdline.Get[configFlags](line)
	name, given := in.Name.Get()
	if !slices.Equal(in.Columns, []Column{"id", "-name"}) || in.Limit != 50 || name != "" || !given || c.Config != "x.yaml" {
		t.Errorf("got %+v %+v", in, c)
	}
}

// TestRun: a command alone. The test fills the input struct by hand.
func TestRun(t *testing.T) {
	in := listIn{Limit: 5, Name: cmdline.Some("fig")}
	if err := list(context.Background(), in); err != nil {
		t.Fatal(err)
	}
}

// TestMistake: a mistake is data.
func TestMistake(t *testing.T) {
	_, err := tree().Parse([]string{"items", "list", "--limit", "ten", "--bogus"})
	var e *cmdline.UsageError
	if !errors.As(err, &e) || e.Kind != cmdline.BadValue || e.Flag != "limit" || e.At != 2 {
		t.Errorf("got %v", err)
	}
}

// TestTab: the answer the shell script reads, line by line.
func TestTab(t *testing.T) {
	for _, tc := range []struct{ line, want string }{
		{"items ", "list\tList items\ndelete\tDelete an item\n:4\n"},
		{"items list --sort ", "id\nname\n:4\n"},
		{"-c other.yaml items rm ", "21\n22\n:4\n"},
	} {
		var b bytes.Buffer
		tree().Serve(&b, append([]string{"__complete"}, strings.Split(tc.line, " ")...))
		if b.String() != tc.want {
			t.Errorf("%q: got %q", tc.line, b.String())
		}
	}
}
