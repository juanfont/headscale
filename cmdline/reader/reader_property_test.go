package reader

import (
	"slices"
	"testing"
)

func TestValueCompletionKeepsOffsets(t *testing.T) {
	flag := Flag{Name: "format", Short: 'f', Repeat: true}
	flag.Complete = func(m *Match, prefix string) ([]string, Directive) {
		if !slices.Equal(m.ArgAt, []int{0, 2}) {
			t.Errorf("argument offsets = %v, want [0 2]", m.ArgAt)
		}

		return []string{prefix}, KeepOrder
	}
	root := &Command{Name: "show", Flags: []Flag{flag}}

	words, dir := Complete(
		root,
		[]string{"first", "--format=old", "two words", "-f"},
		" x ",
	)
	if !slices.Equal(words, []string{" x "}) || dir != KeepOrder {
		t.Errorf("completion = %q, %d", words, dir)
	}
}
