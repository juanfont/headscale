package cmdline

import (
	"context"
	"testing"
)

func TestSealedListSeparator(t *testing.T) {
	type input struct {
		Colors []color `flag:"colors"`
	}

	tree, err := New(Command[input]{Name: "paint", Run: func(context.Context, input) error { return nil }})
	if err != nil {
		t.Fatal(err)
	}

	words, dir := tree.Complete([]string{"--colors"}, "red\r,")
	if len(words) != 0 || dir != NoFiles {
		t.Fatalf("completion after carriage return = %q, directive %d", words, dir)
	}
}
