package reader

import (
	"errors"
	"slices"
	"testing"
	"unicode"

	"pgregory.net/rapid"
)

func TestRapidReaderWhitespace(t *testing.T) {
	root := tree()

	for _, role := range []string{"command", "positional", "option-value"} {
		t.Run(role, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				space := rapid.StringOfN(rapid.RuneFrom(nil, unicode.White_Space), 1, 8, 32).Draw(rt, "whitespace")

				if role == "command" {
					path := []string{"nodes", "routes", "set"}
					depth := rapid.IntRange(0, 2).Draw(rt, "depth")

					word := path[depth]
					if depth == 2 && rapid.Bool().Draw(rt, "alias") {
						word = "approve"
					}

					if rapid.Bool().Draw(rt, "prepend") {
						word = space + word
					} else {
						word += space
					}

					argv := append(slices.Clone(path[:depth]), word)
					_, err := Parse(root, argv)

					var got *Error
					if !errors.As(err, &got) || got.Kind != UnknownCommand || got.At != depth || got.Word != word || !slices.Equal(got.Path, path[:depth]) {
						rt.Fatalf("argv %q: got %#v, want unknown command %q at %d", argv, err, word, depth)
					}

					return
				}

				argv := []string{"nodes", "delete"}

				if role == "option-value" {
					if rapid.Bool().Draw(rt, "attached") {
						argv = append(argv, "--output="+space)
					} else {
						argv = append(argv, "--output", space)
					}
				} else {
					if rapid.Bool().Draw(rt, "end options") {
						argv = append(argv, "--")
					}

					argv = append(argv, space)
				}

				line, err := Parse(root, argv)
				if err != nil {
					rt.Fatalf("argv %q: %v", argv, err)
				}

				words := line.Args
				if role == "option-value" {
					words = line.Values("output")
				}

				if !slices.Equal(words, []string{space}) {
					rt.Fatalf("argv %q: got words %q, want %q", argv, words, space)
				}
			})
		})
	}
}
