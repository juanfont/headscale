package newcli

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmdline/argtest"
	"pgregory.net/rapid"
)

// On an empty server, all list leaves must preserve an empty collection across API and CLI JSON.
//
// Bound: the request query is not checked, so a wrong page size passes on
// an empty store.
func TestRapidEmptyListCatalogue(t *testing.T) {
	f := newFixture(t, false)
	endpoints := map[string]listAt{
		"users list":             users,
		"nodes list":             nodes,
		"nodes routes list":      nodes,
		"nodes tags list":        tags,
		"auth keys list":         authKeys,
		"api keys list":          apiKeys,
		"api oauth-clients list": oauthClients,
	}
	seen := map[string]bool{}

	for _, c := range Tree().Commands() {
		if !strings.HasSuffix(c.Path, " list") {
			continue
		}

		ep, ok := endpoints[c.Path]
		if !ok {
			t.Fatalf("missing API oracle for %s", c.Path)
		}

		seen[c.Path] = true
		t.Run(c.Path, func(t *testing.T) {
			var aliases, early int

			rapid.Check(t, func(rt *rapid.T) {
				path := strings.Fields(c.Path)
				if len(c.Aliases) > 0 && rapid.Bool().Draw(rt, "alias") {
					path[len(path)-1] = rapid.SampledFrom(c.Aliases).
						Draw(rt, "leaf alias")
					aliases++
				}

				name := rapid.SampledFrom([]string{"--output", "-o"}).
					Draw(rt, "output flag")

				argv := argtest.Interleave(rt, path, argtest.Option(rt, name, "json"))
				if strings.HasPrefix(argv[0], "-") {
					early++
				}

				size := rapid.IntRange(1, 4).Draw(rt, "page size")

				r := f.run(t, cliCase{args: strings.Join(argv, " "), pageSize: size})
				if r.code != 0 || r.stderr != "" || r.stdout != "[]\n" {
					fatalf(
						rt,
						"argv=%q: exit=%d stdout=%q stderr=%q",
						argv,
						r.code,
						r.stdout,
						r.stderr,
					)
				}

				pages := r.answers[ep.path]
				if len(pages) != 1 || len(r.asked) != 1 {
					fatalf(
						rt,
						"argv=%q: requests=%q pages=%d at %s",
						argv,
						r.asked,
						len(pages),
						ep.path,
					)
				}

				var page map[string]json.RawMessage
				if json.Unmarshal(pages[0], &page) != nil ||
					string(page[ep.items]) != "[]" {
					fatalf(
						rt,
						"argv=%q: expected an empty %s array in API response %s",
						argv,
						ep.items,
						pages[0],
					)
				}
			})
			t.Logf(
				"model classes leaf-aliases=%d global-before-command=%d",
				aliases,
				early,
			)
		})
	}

	if len(seen) != len(endpoints) {
		t.Fatalf("declared list leaves %v; expected %d", seen, len(endpoints))
	}
}
