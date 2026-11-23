package newcli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"net/http"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"pgregory.net/rapid"
)

// Unknown JSON fields belong to the API row, even after the CLI reorders it.
func TestRapidRawListRows(t *testing.T) {
	f := newFixture(t, true)
	fleet(t, f)

	for _, kind := range []string{"users", "nodes"} {
		t.Run(kind, func(t *testing.T) {
			path := "/api/headscale/v0/" + kind
			ids, byID := rawFixtureList(t, f, kind, path)
			socket := filepath.Join(filepath.Dir(f.srv.SocketPath), "rows.sock")
			serve := rawListServer(t, kind, path, socket)

			var wide, nested, absent, severalPages, fractions, exponents, signedZeros int

			rapid.Check(t, func(rt *rapid.T) {
				count := rapid.IntRange(1, len(ids)).Draw(rt, "rows")
				size := rapid.IntRange(1, count).Draw(rt, "page size")
				start := rapid.IntRange(0, count).Draw(rt, "rows to filter out")

				threshold := 0
				if start > 0 {
					threshold = ids[start-1]
				}

				desc := rapid.Bool().Draw(rt, "descending")
				key := "future" + rapid.StringOfN(rapid.RuneFrom([]rune("abcø012")), 0, 8, 12).Draw(rt, "field suffix")

				rows := make([]map[string]json.RawMessage, 0, count)
				for i := range count {
					row := maps.Clone(byID[ids[i]])
					if _, exists := row[key]; exists {
						rt.Fatalf("fixture already contains %q", key)
					}

					value, present := drawFutureValue(rt)
					if present {
						body, err := json.Marshal(value)
						if err != nil {
							rt.Fatal(err)
						}

						row[key] = body
					}

					if i >= start {
						switch n := value.(type) {
						case uint64:
							wide++
						case json.Number:
							if strings.ContainsAny(n.String(), "eE") {
								exponents++
							} else if n == "-0" {
								signedZeros++
							} else {
								fractions++
							}
						case map[string]any:
							nested++
						}

						if !present {
							absent++
						}
					}

					rows = append(rows, row)
				}

				serve(rows, size)

				order := "id"
				if desc {
					order = "-id"
				}

				got := f.run(t, cliCase{args: fmt.Sprintf("%s list -o json --sort=%s --filter=id>%d", kind, order, threshold), pageSize: size, release: "0.30.1", env: []string{"HEADSCALE_UNIX_SOCKET=" + socket}})
				if got.code != 0 || got.stderr != "" || len(got.answers[path]) != (count+size-1)/size {
					rt.Fatalf("exit=%d pages=%d stderr=%q", got.code, len(got.answers[path]), got.stderr)
				}

				if count > size {
					severalPages++
				}

				want := slices.Clone(rows[start:])
				if desc {
					slices.Reverse(want)
				}

				expected, err := json.Marshal(want)
				if err != nil {
					rt.Fatal(err)
				}

				if diff := cmp.Diff(listJSONValue(rt, expected), listJSONValue(rt, []byte(got.stdout))); diff != "" {
					rt.Fatalf("page size=%d filter=id>%d sort=%s (-want +got):\n%s", size, threshold, order, diff)
				}
			})
			t.Logf("model classes visible-wide-integers=%d visible-nested-fields=%d visible-absent-fields=%d multiple-pages=%d visible-fractions=%d visible-exponents=%d visible-negative-zeros=%d", wide, nested, absent, severalPages, fractions, exponents, signedZeros)
		})
	}
}

func rawFixtureList(t *testing.T, f *fixture, kind, path string) ([]int, map[int]map[string]json.RawMessage) {
	t.Helper()
	base := f.run(t, cliCase{args: kind + " list -o json", pageSize: 100})
	pages := base.answers[path]

	var page map[string][]map[string]json.RawMessage
	if base.code != 0 || len(pages) != 1 || json.Unmarshal(pages[0], &page) != nil || len(page[kind]) < 2 {
		t.Fatalf("fixture %s: exit=%d pages=%d stderr=%q", kind, base.code, len(pages), base.stderr)
	}

	ids := make([]int, 0, len(page[kind]))

	byID := make(map[int]map[string]json.RawMessage)

	for _, row := range page[kind] {
		var id string

		err := json.Unmarshal(row["id"], &id)
		if err != nil {
			t.Fatal(err)
		}

		n, err := strconv.Atoi(id)
		if err != nil || n <= 0 || byID[n] != nil {
			t.Fatalf("invalid or repeated fixture ID %q", id)
		}

		ids = append(ids, n)
		byID[n] = row
	}

	slices.Sort(ids)

	return ids, byID
}

// One Unix listener serves a whole run without consuming ephemeral TCP ports per draw.
func rawListServer(t *testing.T, kind, path, socket string) func([]map[string]json.RawMessage, int) {
	t.Helper()

	type page struct {
		rows []map[string]json.RawMessage
		size int
	}

	var current atomic.Pointer[page]

	ln, err := new(net.ListenConfig).Listen(t.Context(), "unix", socket)
	if err != nil {
		t.Fatal(err)
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := current.Load()
		rows, size := p.rows, p.size

		w.Header().Set("Headscale-Version", "0.30.1")

		if r.Method != http.MethodGet || r.URL.Path != path || r.URL.Query().Get("pageSize") != strconv.Itoa(size) {
			http.Error(w, "unexpected page request", http.StatusBadRequest)
			return
		}

		first := 0

		if token := r.URL.Query().Get("pageToken"); token != "" {
			var err error

			first, err = strconv.Atoi(token)
			if err != nil || first <= 0 || first >= len(rows) {
				http.Error(w, "unexpected token", http.StatusBadRequest)
				return
			}
		}

		end := min(first+size, len(rows))

		answer := map[string]any{kind: rows[first:end]}
		if end < len(rows) {
			answer["nextPageToken"] = strconv.Itoa(end)
		}

		err := json.NewEncoder(w).Encode(answer)
		if err != nil {
			t.Error(err)
		}
	})
	srv := &http.Server{Handler: handler, ReadHeaderTimeout: time.Second}
	srv.SetKeepAlivesEnabled(false)

	done := make(chan error, 1)
	go func() { done <- srv.Serve(ln) }()

	t.Cleanup(func() {
		err := srv.Close()
		if err != nil {
			t.Error(err)
		}

		err = <-done
		if !errors.Is(err, http.ErrServerClosed) {
			t.Error(err)
		}
	})

	return func(rows []map[string]json.RawMessage, size int) { current.Store(&page{rows: rows, size: size}) }
}

func drawFutureValue(rt *rapid.T) (any, bool) {
	switch rapid.IntRange(0, 10).Draw(rt, "field shape") {
	case 0:
		return uint64(1<<53) + 2*uint64(rapid.Uint16().Draw(rt, "integer offset")) + 1, true
	case 1:
		return rapid.StringN(0, 12, 48).Draw(rt, "text"), true
	case 2:
		return rapid.Bool().Draw(rt, "boolean"), true
	case 3:
		return map[string]any{"items": []any{uint64(1<<53) + 1, rapid.StringN(0, 12, 48).Draw(rt, "nested text")}}, true
	case 4:
		return nil, true
	case 5:
		return []any{rapid.Int16().Draw(rt, "small integer")}, true
	case 6:
		return nil, false
	case 7:
		whole := int64(1<<53) + int64(rapid.Uint16().Draw(rt, "whole offset"))
		if rapid.Bool().Draw(rt, "negative") {
			whole = -whole
		}

		return json.Number(strconv.FormatInt(whole, 10) + ".5"), true
	case 8:
		mantissa := rapid.SampledFrom([]string{"1", "-1", "0.125", "9007199254740993"}).Draw(rt, "mantissa")
		marker := rapid.SampledFrom([]string{"e", "E"}).Draw(rt, "exponent marker")
		exponent := rapid.IntRange(-400, 400).Draw(rt, "exponent")

		return json.Number(mantissa + marker + strconv.Itoa(exponent)), true
	case 9:
		return json.Number("-0"), true
	default:
		return rapid.SampledFrom([]json.Number{"1e+0", "1e00", "-0.0", "1.500", "-0E+00", "1E+002"}).Draw(rt, "number spelling"), true
	}
}

func listJSONValue(rt *rapid.T, body []byte) any {
	rt.Helper()

	if !json.Valid(body) {
		rt.Fatalf("invalid JSON: %q", body)
	}

	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.UseNumber()

	var value any

	err := decoder.Decode(&value)
	if err != nil {
		rt.Fatal(err)
	}

	return value
}
