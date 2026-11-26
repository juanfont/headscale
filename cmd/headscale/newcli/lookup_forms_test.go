package newcli

import (
	"encoding/json"
	"strconv"
	"strings"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

// Bound: the email in the CLI's JSON is not checked, only the stored one.
func TestRapidUserLookupForms(t *testing.T) {
	for _, shape := range []string{"numeric", "transferred-email"} {
		t.Run(shape, func(t *testing.T) {
			f := newFixture(t, true)

			var padded, transfers int

			rapid.Check(t, func(rt *rapid.T) {
				first, second := "alice", "bob"
				if rapid.Bool().Draw(rt, "reverse users") {
					first, second = second, first
				}

				padding := 0
				address := ""

				if shape == "numeric" {
					padding = rapid.IntRange(0, 4).Draw(rt, "leading zeroes")
				} else {
					local := rapid.StringMatching(`[a-z][a-z0-9]{0,8}`).
						Draw(rt, "email local part")
					address = local + "@example.org"
				}

				resetCollectionUsers(rt, f)
				left := f.srv.CreateUser(t, first)
				right := f.srv.CreateUser(t, second)
				owner := collectionRow{
					ID:   strconv.FormatUint(uint64(left.ID), 10),
					Name: first,
				}
				next := collectionRow{
					ID:   strconv.FormatUint(uint64(right.ID), 10),
					Name: second,
				}

				state := map[string]string{first: owner.ID, second: next.ID}
				if shape == "numeric" {
					word := strings.Repeat("0", padding) + owner.ID
					expected := owner

					if padding != 0 {
						padded++
						expected = collectionRow{}
					}

					checkLookupWord(t, rt, f, word, expected)
				} else {
					change := func(target, field, value string, want collectionRow) {
						rt.Helper()

						got := f.run(
							t,
							cliCase{
								args: "users set " + target + " --" + field + "=" + value + " -o json",
							},
						)
						checkResolvedUser(rt, got, want)
					}
					change(owner.ID, "email", address, owner)
					checkLookupWord(t, rt, f, address, owner)
					change(owner.ID, "email", "", owner)
					checkLookupWord(t, rt, f, address, collectionRow{})
					change(next.ID, "email", address, next)
					checkLookupWord(t, rt, f, address, next)
					next.Name = "renamed"
					change(address, "name", next.Name, next)
					delete(state, second)
					state[next.Name] = next.ID
					checkLookupWord(t, rt, f, address, next)

					transfers++

					for _, u := range []struct {
						id    types.UserID
						email string
					}{{types.UserID(left.ID), ""}, {types.UserID(right.ID), address}} {
						stored, err := f.srv.State().GetUserByID(u.id)
						if err != nil || stored.Email != u.email {
							fatalf(
								rt,
								"stored email for %v: user=%v err=%v, want %q",
								u.id,
								stored,
								err,
								u.email,
							)
						}
					}
				}

				verifyUserCollection(t, rt, f, shape, state)
			})
			t.Logf("model classes padded-ids=%d email-transfers=%d", padded, transfers)
		})
	}
}

func checkLookupWord(
	t *testing.T,
	rt *rapid.T,
	f *fixture,
	word string,
	want collectionRow,
) {
	t.Helper()
	rt.Helper()

	got := f.run(t, cliCase{args: "users get " + word + " -o json", pageSize: 1})
	if want.ID != "" {
		checkResolvedUser(rt, got, want)
		return
	}

	msg := "Error: no user matches " + strconv.Quote(word) + ".\n"
	if got.code != 1 || got.stdout != "" || got.stderr != msg {
		fatalf(
			rt,
			"absent selector %q: exit=%d stdout=%q stderr=%q, want %q",
			word,
			got.code,
			got.stdout,
			got.stderr,
			msg,
		)
	}
}

func checkResolvedUser(rt *rapid.T, got result, want collectionRow) {
	rt.Helper()

	var actual collectionRow
	if got.code != 0 || got.stderr != "" ||
		json.Unmarshal([]byte(got.stdout), &actual) != nil ||
		actual != want {
		fatalf(
			rt,
			"expected selected user %+v, got %+v, exit=%d stderr=%q",
			want,
			actual,
			got.code,
			got.stderr,
		)
	}
}
