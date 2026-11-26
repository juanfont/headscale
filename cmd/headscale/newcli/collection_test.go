package newcli

import (
	"cmp"
	"encoding/json"
	"maps"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/cmd/headscale/newcli/command"
	"github.com/juanfont/headscale/cmdline/argtest"
	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

type collectionRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

type collectionAction struct {
	op, bank, next string
	slot           int
	byID, retired  bool
	words          []string
}

func collectionActions(
	withDelete bool,
	names []string,
) *rapid.Generator[[]collectionAction] {
	verbs := []string{"create", "get", "rename", "list"}
	if withDelete {
		verbs = append(verbs, "delete")
	}

	step := rapid.Custom(func(rt *rapid.T) collectionAction {
		op := rapid.SampledFrom(verbs).Draw(rt, "operation")

		action := collectionAction{op: op}
		if op != "list" {
			action.bank = rapid.SampledFrom([]string{"all", "active", "released"}).
				Draw(rt, "bank")
			action.slot = rapid.IntRange(0, len(names)-1).Draw(rt, "slot")
		}

		if op == "get" || op == "rename" || op == "delete" {
			action.byID = rapid.Bool().Draw(rt, "ID")
			if withDelete {
				action.retired = rapid.Bool().Draw(rt, "retired ID")
			}
		}

		path := []string{"users", op, "{target}"}
		if op == "rename" {
			path[1] = "set"
			action.next = rapid.SampledFrom(names).Draw(rt, "destination")
		}

		switch op {
		case "delete":
			action.words = append(path, "--force")
		case "list":
			action.words = []string{
				"users",
				rapid.SampledFrom([]string{"list", "ls"}).Draw(rt, "list alias"),
				"--sort",
				"id",
				"--columns=id",
			}
		default:
			action.words = argtest.Interleave(
				rt,
				path,
				argtest.Option(rt, "--output", "json"),
			)
			if op == "rename" {
				action.words = append(
					action.words,
					argtest.Option(rt, "--name", action.next)...)
			}
		}

		return action
	})

	return rapid.SliceOfN(step, 1, 12)
}

type collectionState struct {
	names   []string
	current map[string]string
	freed   map[string]bool
	retired []string
}

func (m *collectionState) target(a collectionAction) (string, collectionRow) {
	names := m.names
	if a.bank == "active" && len(m.current) > 0 {
		names = slices.Sorted(maps.Keys(m.current))
	}

	if a.bank == "released" && len(m.freed) > 0 {
		names = slices.Sorted(maps.Keys(m.freed))
	}

	name := names[a.slot%len(names)]

	row := collectionRow{ID: m.current[name], Name: name}

	var target string

	switch {
	case a.retired && len(m.retired) > 0:
		target = m.retired[a.slot%len(m.retired)]
	case a.byID && row.ID == "":
		candidates := []string{"0", "1", "9007199254740993", "18446744073709551615"}
		target = candidates[a.slot%len(candidates)]
	case a.byID:
		return row.ID, row
	default:
		return name, row
	}

	for name, id := range m.current {
		if id == target {
			return target, collectionRow{ID: id, Name: name}
		}
	}

	return target, collectionRow{}
}

func (m *collectionState) run(
	t *testing.T,
	rt *rapid.T,
	f *fixture,
	a collectionAction,
	counts map[string]int,
) {
	t.Helper()
	rt.Helper()

	target, row := m.target(a)

	words := slices.Clone(a.words)
	for i, w := range words {
		if w == "{target}" {
			words[i] = target
		}
	}

	got := f.run(t, cliCase{args: strings.Join(words, " "), pageSize: 1})
	counts["actions"]++
	refused := false

	switch a.op {
	case "create":
		refused = row.ID != ""
	case "get", "delete":
		refused = row.ID == ""
	case "rename":
		refused = row.ID == "" || (row.Name != a.next && m.current[a.next] != "")
	}

	if a.retired && len(m.retired) > 0 && row.ID == "" {
		counts["stale"]++
		counts["stale-"+a.op]++
	}

	if a.byID && row.ID == "" && (!a.retired || len(m.retired) == 0) {
		counts["absent-ids"]++
	}

	if refused {
		message := "Error: no user matches " + strconv.Quote(target) + ".\n"
		if row.ID != "" {
			name := target
			if a.op == "rename" {
				name = a.next
			}

			message = "Error: the name " + strconv.Quote(
				name,
			) + " belongs to User " + m.current[name] + " (" + name + ").\n"
		}

		if got.code != 1 || got.stdout != "" || got.stderr != message {
			fatalf(
				rt,
				"refusal for %q: exit=%d stdout=%q stderr=%q want=%q",
				words,
				got.code,
				got.stdout,
				got.stderr,
				message,
			)
		}

		counts["refused"]++

		return
	}

	m.applyResult(rt, a, row, got, words, counts)
}

func (m *collectionState) applyResult(
	rt *rapid.T,
	a collectionAction,
	row collectionRow,
	got result,
	words []string,
	counts map[string]int,
) {
	rt.Helper()

	if got.code != 0 || got.stderr != "" {
		fatalf(
			rt,
			"expected success for %q, got exit=%d stderr=%q",
			words,
			got.code,
			got.stderr,
		)
	}

	switch a.op {
	case "list":
		if want := listedUserIDs(m.current); got.stdout != want {
			fatalf(rt, "list: got %q want %q", got.stdout, want)
		}
	case "delete":
		if got.stdout != "User "+row.ID+" ("+row.Name+") deleted.\n" {
			fatalf(rt, "delete: got %q for %+v", got.stdout, row)
		}

		delete(m.current, row.Name)
		m.freed[row.Name] = true
		m.retired = append(m.retired, row.ID)
		counts["removed"]++
	default:
		var actual collectionRow

		err := json.Unmarshal([]byte(got.stdout), &actual)
		if err != nil {
			fatalf(rt, "%v", err)
		}

		switch a.op {
		case "create":
			row.ID = actual.ID
			if row.ID == "" {
				rt.Fatal("created user has no ID")
			}

			counts["created"]++
		case "rename":
			if a.next != row.Name {
				delete(m.current, row.Name)
				m.freed[row.Name] = true
				row.Name = a.next
				counts["renamed"]++
			}
		}

		if actual != row {
			fatalf(rt, "%s returned %+v, want %+v", a.op, actual, row)
		}

		if a.op != "get" {
			if m.freed[row.Name] {
				counts["reused"]++

				delete(m.freed, row.Name)
			}

			m.current[row.Name] = row.ID
		}
	}
}

func resetCollectionUsers(rt *rapid.T, f *fixture) {
	rt.Helper()

	st := f.srv.State()

	users, err := st.ListAllUsers()
	if err != nil {
		fatalf(rt, "%v", err)
	}

	for _, user := range users {
		_, err = st.DeleteUser(types.UserID(user.ID))
		if err != nil {
			fatalf(rt, "%v", err)
		}
	}
}

// Bound: a create's ID is taken from the command, so reuse of a retired ID
// passes.
func TestRapidUserCollection(t *testing.T) {
	names := []string{"rapida", "rapidb", "rapidc", "rapidd"}

	for _, withDelete := range []bool{false, true} {
		suite := "common"
		if withDelete {
			suite = "delete"
		}

		t.Run(suite, func(t *testing.T) {
			if withDelete &&
				!slices.ContainsFunc(
					Tree().Commands(),
					func(c command.Command) bool { return c.Path == "users delete" },
				) {
				t.Skip("this head has no users delete command")
			}

			f := newFixture(t, true)

			initial, err := f.srv.State().ListAllUsers()
			if err != nil || len(initial) != 0 {
				t.Fatalf(
					"expected fresh user collection: rows=%d err=%v",
					len(initial),
					err,
				)
			}

			counts := map[string]int{}
			traces := collectionActions(withDelete, names)

			rapid.Check(t, func(rt *rapid.T) {
				// Draw the whole symbolic trace before execution so healthy replays consume the same input.
				trace := traces.Draw(rt, "trace")
				runCollectionTrace(t, rt, f, names, trace, counts)
			})
			t.Logf(
				"model classes created=%d renamed=%d deleted=%d refused=%d reused-names=%d multipage-reads=%d collection-actions=%d stale-id-lookups=%d stale-gets=%d stale-renames=%d stale-deletes=%d absent-numeric-selectors=%d",
				counts["created"],
				counts["renamed"],
				counts["removed"],
				counts["refused"],
				counts["reused"],
				counts["pages"],
				counts["actions"],
				counts["stale"],
				counts["stale-get"],
				counts["stale-rename"],
				counts["stale-delete"],
				counts["absent-ids"],
			)
		})
	}
}

func runCollectionTrace(
	t *testing.T,
	rt *rapid.T,
	f *fixture,
	names []string,
	trace []collectionAction,
	counts map[string]int,
) {
	t.Helper()
	rt.Helper()
	resetCollectionUsers(rt, f)

	model := collectionState{
		names:   names,
		current: map[string]string{},
		freed:   map[string]bool{},
	}
	for _, step := range trace {
		model.run(t, rt, f, step, counts)
		verifyUserCollection(t, rt, f, step.op, model.current)

		if len(model.current) > 1 {
			counts["pages"]++
		}
	}
}

func verifyUserCollection(
	t *testing.T,
	rt *rapid.T,
	f *fixture,
	op string,
	current map[string]string,
) {
	t.Helper()
	rt.Helper()
	// Read both persisted state and the paginated CLI listing after every action.
	dbRows, err := f.srv.State().ListAllUsers()
	if err != nil {
		fatalf(rt, "%v", err)
	}

	stored := map[string]string{}
	for _, user := range dbRows {
		stored[user.Name] = strconv.FormatUint(uint64(user.ID), 10)
	}

	list := f.run(t, cliCase{args: "users list -o json", pageSize: 1})

	var rows []collectionRow
	if list.code != 0 || list.stderr != "" ||
		json.Unmarshal([]byte(list.stdout), &rows) != nil ||
		rows == nil {
		fatalf(
			rt,
			"collection read failed: exit=%d stdout=%q stderr=%q",
			list.code,
			list.stdout,
			list.stderr,
		)
	}

	actual := map[string]string{}
	for _, row := range rows {
		actual[row.Name] = row.ID
	}

	if len(rows) != len(current) || len(dbRows) != len(current) ||
		!maps.Equal(actual, current) ||
		!maps.Equal(stored, current) {
		fatalf(
			rt,
			"after %s, collection differs: listed=%v stored=%v model=%v",
			op,
			actual,
			stored,
			current,
		)
	}
}

func listedUserIDs(current map[string]string) string {
	ids := slices.Collect(maps.Values(current))
	slices.SortFunc(ids, func(a, b string) int {
		if len(a) != len(b) {
			return cmp.Compare(len(a), len(b))
		}

		return strings.Compare(a, b)
	})

	expected := "ID\n"
	if len(ids) > 0 {
		expected += strings.Join(ids, "\n") + "\n"
	}

	return expected
}

func TestAbsentNumericUser(t *testing.T) {
	f := newFixture(t, true)

	created := f.run(t, cliCase{args: "users create alice"})
	if created.code != 0 {
		t.Fatal(created.stderr)
	}

	got := f.run(t, cliCase{args: "users get 999"})
	if got.code != 1 || got.stdout != "" ||
		got.stderr != "Error: no user matches \"999\".\n" {
		t.Fatalf("code=%d stdout=%q stderr=%q", got.code, got.stdout, got.stderr)
	}
}
