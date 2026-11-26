package newcli

import (
	"encoding/json"
	"maps"
	"strconv"
	"testing"

	"github.com/juanfont/headscale/hscontrol/types"
	"pgregory.net/rapid"
)

type collectionRow struct {
	ID   string `json:"id"`
	Name string `json:"name"`
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
