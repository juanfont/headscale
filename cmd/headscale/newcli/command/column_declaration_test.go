package command

import (
	"bytes"
	"slices"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli/table"
	"pgregory.net/rapid"
)

// Snapshot the observable list and sheet before the caller reuses its declarations.
func TestRapidColumnDeclarations(t *testing.T) {
	type row struct {
		ID         string            `json:"id"`
		Name       string            `json:"name"`
		Other      string            `json:"other"`
		Tags       []string          `json:"tags"`
		Attributes map[string]string `json:"attributes"`
		Extra      map[string]string `json:"extra"`
	}

	for _, surface := range []string{"filter", "sort", "cell", "sheet", "block", "fold-map", "fold-values", "fold-filter", "catalogue"} {
		t.Run(surface, func(t *testing.T) {
			rapid.Check(t, func(rt *rapid.T) {
				suffix := rapid.StringOfN(rapid.RuneFrom([]rune("abcdefg")), 0, 6, 6).Draw(rt, "suffix")
				first, second := "aa"+suffix, "zz"+suffix
				tags := []string{"red" + suffix, "blue" + suffix}

				rows := []row{{ID: "1", Name: second, Other: first, Tags: slices.Clone(tags), Attributes: map[string]string{"k": first}, Extra: map[string]string{"k": second}}, {ID: "2", Name: first, Other: second}}
				if rapid.Bool().Draw(rt, "reverse rows") {
					slices.Reverse(rows)
				}

				fold := map[string][]string{"pair": tags}
				columns := table.Columns[row]{{Name: "id", Field: "id", Default: true}, {Name: "name", Field: "name", Default: true}, {Name: "tags", Field: "tags", Fold: fold, Default: true}}
				blocks := table.Blocks[row]{{Title: "Details", Field: "attributes"}}
				list := NewList(ListSpec[NoInput, row]{Name: "list", Short: "List items", Long: "List items.", Example: []string{"prog list"}, Local: true, NoRows: "No items.", Columns: columns, Run: func(Ctx, NoInput) ([]row, error) { return rows, nil }})
				sheetRow := slices.IndexFunc(rows, func(r row) bool { return r.ID == "1" })
				get := New(Spec[NoInput, row]{Name: "get", Short: "Get item", Long: "Get an item.", Example: []string{"prog get"}, Local: true, Columns: columns, Blocks: blocks, Run: func(Ctx, NoInput) (row, error) { return rows[sheetRow], nil }})

				tree, err := Build("prog", "Items", list, get)
				if err != nil {
					rt.Fatal(err)
				}

				line := map[string][]string{
					"filter":      {"list", "--filter=name=" + first, "--columns=id"},
					"sort":        {"list", "--sort=name", "--columns=id"},
					"cell":        {"list", "--columns=name"},
					"sheet":       {"get"},
					"block":       {"get"},
					"fold-map":    {"list", "--columns=tags"},
					"fold-values": {"get"},
					"fold-filter": {"list", "--filter=tags=pair", "--columns=id"},
					"catalogue":   {"list", "--list-columns", "-o", "json"},
				}[surface]
				observe := func() string {
					var out, diag bytes.Buffer
					if exit := Run(tree, line, Env{Stdout: &out, Stderr: &diag}); exit != 0 || diag.Len() != 0 {
						rt.Fatalf("run %q: exit %d, stderr %q", line, exit, diag.String())
					}

					return out.String()
				}
				expected := observe()

				switch surface {
				case "filter":
					if expected != "ID\n2\n" {
						rt.Fatalf("filter control %q", expected)
					}
				case "sort":
					if expected != "ID\n2\n1\n" {
						rt.Fatalf("sort control %q", expected)
					}
				case "fold-filter":
					if expected != "ID\n1\n" {
						rt.Fatalf("fold filter control %q", expected)
					}
				}

				switch surface {
				case "block":
					blocks[0].Field = "extra"
				case "fold-map":
					delete(fold, "pair")
				case "fold-values":
					tags[0] = "new" + suffix
				case "fold-filter":
					if rapid.Bool().Draw(rt, "reuse values") {
						tags[0] = "new" + suffix
					} else {
						delete(fold, "pair")
					}
				default:
					columns[1].Field = "other"
				}

				if actual := observe(); actual != expected {
					rt.Fatalf("reuse changed %s output for %q: got %q, want %q", surface, line, actual, expected)
				}
			})
		})
	}
}
