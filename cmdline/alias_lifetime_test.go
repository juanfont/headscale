package cmdline

import (
	"bytes"
	"context"
	"slices"
	"strconv"
	"testing"

	"pgregory.net/rapid"
)

// Each checked tree retains its declarations while the caller builds the next one.
func TestRapidAliasLifetime(t *testing.T) {
	for _, surface := range []string{"parse", "completion", "reference"} {
		t.Run(surface, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				count := rapid.IntRange(1, 4).Draw(rt, "trees")
				groupAlias, leafAlias := []string{""}, []string{""}

				type snapshot struct {
					tree        *Tree
					group, leaf string
					ran         *string
				}

				built := make([]snapshot, 0, count)
				for i := range count {
					suffix := strconv.Itoa(i) + rapid.StringOfN(rapid.RuneFrom([]rune("abcxyz")), 0, 5, 5).Draw(rt, "suffix")
					groupAlias[0], leafAlias[0] = "g"+suffix, "l"+suffix
					ran := ""
					leaf := func(name string, aliases []string) Node {
						return Command[struct{}]{Name: name, Aliases: aliases, Run: func(context.Context, struct{}) error { ran = name; return nil }}
					}

					tree, err := New(Group{Name: "tool", Commands: []Node{
						Group{Name: "items", Aliases: groupAlias, Commands: []Node{leaf("list", leafAlias), leaf("count", nil)}},
						leaf("other", nil),
					}})
					if err != nil {
						rt.Fatal(err)
					}

					built = append(built, snapshot{tree, groupAlias[0], leafAlias[0], &ran})
				}

				if rapid.Bool().Draw(rt, "reuse group") {
					groupAlias[0] = rapid.SampledFrom([]string{"other", "fresh", ""}).Draw(rt, "new group word")
				}

				if rapid.Bool().Draw(rt, "reuse leaf") {
					leafAlias[0] = rapid.SampledFrom([]string{"count", "new", ""}).Draw(rt, "new leaf word")
				}

				for _, s := range built {
					switch surface {
					case "parse":
						for _, route := range []struct {
							words    []string
							path     []string
							callback string
						}{
							{[]string{s.group, s.leaf}, []string{"items", "list"}, "list"},
							{[]string{"items", "count"}, []string{"items", "count"}, "count"},
							{[]string{"other"}, []string{"other"}, "other"},
						} {
							line, err := s.tree.Parse(route.words)
							if err != nil {
								rt.Fatalf("saved path %q refused: %v", route.words, err)
							}

							*s.ran = ""

							err = line.Run(rt.Context())
							if err != nil || *s.ran != route.callback || !slices.Equal(line.Command.Path, route.path) {
								rt.Fatalf("saved path %q selected %q, callback %q", route.words, line.Command.Path, *s.ran)
							}
						}
					case "completion":
						for _, target := range []struct {
							parents []string
							word    string
						}{{nil, s.group}, {[]string{"items"}, s.leaf}} {
							cur := target.word[:2]
							want := []string{target.word}

							got, d := s.tree.Complete(target.parents, cur)
							if d != NoFiles || !slices.Equal(got, want) {
								rt.Fatalf("completion below %q: got %q, directive %d, want %q", target.parents, got, d, want)
							}

							var buf bytes.Buffer

							args := slices.Concat([]string{"__completeNoDesc"}, target.parents, []string{cur})
							if !s.tree.Serve(&buf, args) || buf.String() != target.word+"\n:4\n" {
								rt.Fatalf("shell completion below %q: %q", target.parents, buf.String())
							}
						}
					case "reference":
						g := s.tree.Root().Commands[0]

						l := g.Commands[0]
						if !slices.Equal(g.Aliases, []string{s.group}) || !slices.Equal(l.Aliases, []string{s.leaf}) {
							rt.Fatalf("reference aliases %q/%q, want %q/%q", g.Aliases, l.Aliases, s.group, s.leaf)
						}
					}
				}
			})
		})
	}
}
