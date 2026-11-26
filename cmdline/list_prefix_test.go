package cmdline

import (
	"bytes"
	"context"
	"fmt"
	"strings"
	"testing"

	"pgregory.net/rapid"
)

func listPrefixTree(t *testing.T) *Tree {
	t.Helper()

	type input struct {
		Colors []color `flag:"colors"`
	}

	tree, err := New(
		Command[input]{
			Name: "paint",
			Run:  func(context.Context, input) error { return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	return tree
}

// Bound: the completer returns words only; file directives are
// TestListFileMetadata's.
func TestRapidListPrefix(t *testing.T) {
	tree := listPrefixTree(t)
	spaces := strings.NewReplacer("\t", " ", "\r", " ", "\n", " ")

	var delimiters, multiple, missing, described, paired int

	rapid.Check(t, func(rt *rapid.T) {
		item := rapid.Custom(func(t *rapid.T) string {
			space := rapid.StringOfN(
				rapid.RuneFrom([]rune(" \t\n\r\u00a0\u3000")),
				0,
				4,
				12,
			)
			left := space.Draw(t, "leading space")
			word := rapid.SampledFrom([]string{"red", "green", "blue"}).Draw(t, "color")

			return left + word + space.Draw(t, "trailing space")
		})
		sealed := rapid.SliceOfN(item, 0, 6).Draw(rt, "sealed items")
		current := rapid.OneOf(rapid.SampledFrom([]string{"", "r", "red", "g", "bl", "x"}), rapid.StringMatching(`[a-z]{0,8}`)).
			Draw(rt, "current item")
		inline := rapid.Bool().Draw(rt, "attached option")
		plain := rapid.Bool().Draw(rt, "omit descriptions")

		prefix := strings.Join(sealed, ",")
		blocked := strings.ContainsAny(prefix, "\r\n\t")
		dir := NoFiles

		if len(sealed) > 0 {
			prefix += ","
			dir |= NoSpace
		}

		var candidates []string

		for _, choice := range []string{"red", "green", "blue"} {
			if !strings.HasPrefix(choice, current) {
				continue
			}

			if blocked {
				dir = NoFiles
				break
			}

			word := prefix + choice
			if choice == "red" && !plain {
				word += "\tWarm"
				described++
			}

			candidates = append(candidates, word)
		}

		if blocked && dir == NoFiles {
			delimiters++
		}

		if len(sealed) > 1 {
			multiple++
		}

		if len(candidates) == 0 {
			missing++
		}

		mode := "__complete"
		if plain {
			mode = "__completeNoDesc"
		}

		argv := []string{mode, "--colors", prefix + current}
		if inline {
			argv = []string{mode, "--colors=" + prefix + current}
		}

		var output bytes.Buffer

		want := strings.Join(append(candidates, fmt.Sprintf(":%d", dir)), "\n") + "\n"
		if !tree.Serve(&output, argv) || output.String() != want {
			fatalf(rt, "completion %q = %q, want %q", argv, output.String(), want)
		}

		if len(sealed) > 0 {
			// One delimiter at a time prevents a second delimiter from hiding a missing check.
			clean := spaces.Replace(prefix)
			for _, sep := range []string{"\t", "\r", "\n"} {
				cursor := sep + clean
				if inline {
					cursor = strings.TrimSuffix(clean, ",") + sep + ","
				}

				words, directive := tree.Complete([]string{"--colors"}, cursor)
				if len(words) != 0 || directive != NoFiles {
					fatalf(
						rt,
						"single delimiter in %q: got %q, directive %d",
						cursor,
						words,
						directive,
					)
				}

				paired++
			}
		}
	})
	t.Logf(
		"model classes blocked-prefixes=%d multiple-items=%d empty-replies=%d described-words=%d separate-delimiters=%d",
		delimiters,
		multiple,
		missing,
		described,
		paired,
	)
}
