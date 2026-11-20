package table

import (
	"bytes"
	"encoding/json"
	"math"
	"reflect"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

type user struct {
	ID        string `json:"id"`
	LoginName string `json:"loginName"`
}

type owner struct {
	User nullable.Nullable[user] `json:"user"`
	Tags []string                `json:"tags"`
}

type row struct {
	ID     string                       `json:"id"`
	Name   string                       `json:"name"`
	Online bool                         `json:"online"`
	Count  int64                        `json:"count"`
	IPs    []string                     `json:"addresses"`
	Seen   time.Time                    `json:"lastSeen"`
	Expiry nullable.Nullable[time.Time] `json:"expiry"`
	Owner  owner                        `json:"owner"`
	Inner  *struct {
		Hint string `json:"hint"`
	} `json:"inner"`
	Version  string            `json:"clientVersion"`
	AuthKey  string            `json:"authKeyId"`
	Nodes    []ref             `json:"nodes"`
	Routes   []string          `json:"enabledRoutes"`
	Attrs    map[string]string `json:"attributes"`
	Untagged string
}

type ref struct {
	ID   string `json:"id"`
	Name string `json:"name"`
}

var now = time.Date(2026, 11, 10, 9, 14, 0, 0, time.UTC)

var cols = Columns[row]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
	{Name: "owner", Field: "owner", Default: true},
	{Name: "ip", Field: "addresses", Default: true},
	{Name: "online", Field: "online", Default: true},
	{Name: "last-seen", Field: "lastSeen", Default: true},
	{Name: "expiry", Field: "expiry", Default: true, Ahead: true},
	{Name: "count", Field: "count"},
	{Name: "hint", Field: "inner.hint"},
}

func rows() []row {
	return []row{
		{
			ID: "12", Name: "mynode", Online: true, IPs: []string{"100.64.0.1", "fd7a::1"},
			Seen: now, Expiry: nullable.NewNullableWithValue(now.Add(89*24*time.Hour + time.Hour)),
			Owner: owner{User: nullable.NewNullableWithValue(user{ID: "3", LoginName: "alice"}), Tags: []string{}},
		},
		{
			ID: "13", Name: "builder", IPs: []string{"100.64.0.2"},
			Seen: now.Add(-3*24*time.Hour - time.Minute), Expiry: nullable.NewNullNullable[time.Time](),
			Owner: owner{Tags: []string{"tag:ci", "tag:build"}},
		},
	}
}

func TestCheck(t *testing.T) {
	t.Parallel()

	require.NoError(t, cols.Check())

	for _, tt := range []struct {
		name string
		col  Column[row]
		want string
	}{
		{"unknown", Column[row]{Name: "x", Field: "nam"}, `column "x": unknown field "nam" in table.row`},
		{"untagged field", Column[row]{Name: "x", Field: "Untagged"}, `column "x": unknown field "Untagged" in table.row`},
		{"into a string", Column[row]{Name: "x", Field: "name.x"}, `column "x": unknown field "name.x": string is no object`},
		{"no field", Column[row]{Name: "x"}, `column "x": unknown field`},
		{"no name", Column[row]{Field: "name"}, `field "name": a column with no name`},
		{"a kind the field cannot have", Column[row]{Name: "x", Field: "online", Kind: Time}, `column "x": kind time cannot show bool`},
		{"a kind of no field", Column[row]{Name: "x", Field: "inner", Kind: Text}, `column "x": kind text cannot show struct { Hint string "json:\"hint\"" }`},
		{"ahead on no time", Column[row]{Name: "x", Field: "name", Ahead: true}, `column "x" is no time, so it cannot look ahead`},
		{"a version with no kind", Column[row]{Name: "x", Field: "clientVersion"}, `column "x": field "clientVersion" is named like an ID or a version: say its Kind, which may be text`},
		{"an ID with no kind", Column[row]{Name: "x", Field: "authKeyId"}, `column "x": field "authKeyId" is named like an ID or a version: say its Kind, which may be text`},
		{"a map with no key", Column[row]{Name: "x", Field: "attributes"}, `column "x": no kind for map[string]string`},
		{"a key into no map", Column[row]{Name: "x", Field: `name["x"]`}, `column "x": field "name[\"x\"]": string is no map with text keys`},
		{"a key not closed", Column[row]{Name: "x", Field: `attributes["x"`}, `column "x": "attributes[\"x\"" is no path: write keys with dots, and a map key as name["key"]`},
		{"a key not quoted", Column[row]{Name: "x", Field: `attributes[x]`}, `column "x": "attributes[x]" is no path: write keys with dots, and a map key as name["key"]`},
		{"a layout on no list", Column[row]{Name: "x", Field: "name", List: Stacked}, `column "x" is no list, so it has no List layout and no Fold`},
		{"a fold on no list", Column[row]{Name: "x", Field: "name", Fold: Exit()}, `column "x" is no list, so it has no List layout and no Fold`},
		{"invalid on no time", Column[row]{Name: "x", Field: "name", Invalid: func(row) bool { return true }}, `column "x" is no time, so it has no Invalid`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.EqualError(t, Columns[row]{tt.col}.Check(), tt.want)
		})
	}
}

func TestCheckTwice(t *testing.T) {
	t.Parallel()

	require.EqualError(t, Columns[row]{{Name: "id", Field: "id"}, {Name: "id", Field: "name"}}.Check(), `column "id" is declared twice`)
	require.NoError(t, Columns[row]{{Name: "v", Field: "name", Kind: Version}, {Name: "i", Field: "name", Kind: ID}}.Check())
}

func TestKinds(t *testing.T) {
	t.Parallel()

	got := map[string]Kind{}

	for _, c := range cols {
		ty, err := fieldType(reflect.TypeFor[row](), c.Field)
		require.NoError(t, err)

		got[c.Name] = c.kind(ty)
	}

	want := map[string]Kind{
		"id": ID, "name": Text, "owner": Owner, "ip": List, "online": Bool,
		"last-seen": Time, "expiry": Time, "count": Number, "hint": Text,
	}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("kinds (-want +got):\n%s", diff)
	}
}

// TestHeader: Header is the table's; the sheet labels by the name, with a
// few words in upper case.
func TestHeader(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{{Name: "public-ip", Field: "name", Header: "Address", Default: true}}

	var b bytes.Buffer
	require.NoError(t, Render(&b, rows()[:1], cs, now, nil))
	require.Equal(t, "ADDRESS\nmynode\n", b.String())

	b.Reset()
	require.NoError(t, Sheet(&b, rows()[0], cs, nil, now))
	require.Equal(t, "Public IP:  mynode\n", b.String())
}

func TestAgo(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		d    time.Duration
		want string
	}{
		{0, "now"},
		{59 * time.Second, "now"},
		{-59 * time.Second, "now"},
		{time.Minute, "in 1m"},
		{-2 * time.Minute, "2m ago"},
		{90 * time.Second, "in 2m"},
		{59*time.Minute + 29*time.Second, "in 59m"},
		{59*time.Minute + 30*time.Second, "in 1h"},
		{23 * time.Hour, "in 23h"},
		{23*time.Hour + 30*time.Minute, "in 1d"},
		{60*24*time.Hour - 5*time.Second, "in 60d"},
		{-24 * time.Hour, "1d ago"},
		{290 * 24 * time.Hour, "in 290d"},
	} {
		require.Equal(t, tt.want, Ago(now.Add(tt.d), now), tt.d)
	}

	// Further than a Duration holds: counted in days, both ways.
	far := time.Date(2999, 8, 27, 0, 0, 0, 0, time.UTC)
	require.Equal(t, "in 355306d", Ago(far, now))
	require.Equal(t, "355306d ago", Ago(now, far))
	require.Equal(t, "in 355306d (2999-08-27 00:00 UTC)", When(far, now))
	require.Equal(t, "in 106752d", Ago(now.Add(math.MaxInt64-time.Hour), now), "no overflow just short of it")

	require.Equal(t, "never", Ago(time.Time{}, now))
	require.Equal(t, "never", When(time.Time{}, now))
	require.Equal(t, "in 60d (2027-01-09 09:14 UTC)", When(now.Add(60*24*time.Hour), now))
}

func TestEntity(t *testing.T) {
	t.Parallel()

	require.Equal(t, "Node 12 (mynode)", Entity("node", "12", "mynode"))
	require.Equal(t, "User 5 (carol@example.com)", Entity("user", "5", "carol@example.com"))
	require.Equal(t, "API key 2 (tr81ys)", Entity("apiKey", "2", "tr81ys"))
	require.Equal(t, "OAuth client c9f2", Entity("oauthClient", "c9f2", "CI"))
	require.Equal(t, "widget 7", Entity("widget", "7", ""))
	require.Equal(t, `User 5 (x\x0afake\u202e)`, Entity("user", "5", "x\nfake\u202e"), "a name of the server is made visible")
}

// TestVisible: text of the server cannot drive the terminal, in a cell of a
// table or a sheet, whatever command shows it.
func TestVisible(t *testing.T) {
	t.Parallel()

	require.Equal(t, `a\x1b[2Jb\u202ec\x07\x9b`, Visible("a\x1b[2Jb\u202ec\a\u009b", ""))
	require.Equal(t, "line\n\ttab", Visible("line\n\ttab", "\n\t"))
	require.Equal(t, `line\x0a`, Visible("line\n", ""))
	require.Equal(t, "plain ünïcode", Visible("plain ünïcode", ""))
	// The text of an escape cannot pass for one.
	require.Equal(t, `a\\x1b`, Visible(`a\x1b`, ""))
	require.Equal(t, `a\x1b\x1b`, Visible("a\\x1b\x1b", "\\"))

	r := rows()[0]
	r.Name = "evil\x1b]0;owned\x07\u2066"

	var b bytes.Buffer
	require.NoError(t, Render(&b, []row{r}, cols[1:2], now, nil))
	require.Equal(t, "NAME\n"+`evil\x1b]0;owned\x07\u2066`+"\n", b.String())

	b.Reset()
	require.NoError(t, Sheet(&b, r, cols[1:2], nil, now))
	require.Equal(t, `Name:  evil\x1b]0;owned\x07\u2066`+"\n", b.String())
}

// TestVisibleJSON: JSON keeps every value, and no control a terminal acts
// on stays raw.
func TestVisibleJSON(t *testing.T) {
	t.Parallel()

	raw := []byte("{\"a\": \"x\u202ey\u0085\u007f\\u001b\u00e9\"}\n")
	got := VisibleJSON(raw)
	require.Equal(t, `{"a": "x\u202ey\u0085\u007f\u001bé"}`+"\n", string(got)) //nolint:testifylint // the bytes, not the values: the escapes are the point

	var a, b map[string]string
	require.NoError(t, json.Unmarshal(raw, &a))
	require.NoError(t, json.Unmarshal(got, &b))
	require.Equal(t, a, b)
}

// TestMapKey: a column reads one key of a map; a missing key is null.
func TestMapKey(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "id", Field: "id", Default: true},
		{Name: "public-ip", Field: `attributes["ip:publicAddress"]`, Default: true},
	}
	require.NoError(t, cs.Check())
	require.Equal(t, Text, cs.Info()[1].Kind)

	r := []row{{ID: "1", Attrs: map[string]string{"ip:publicAddress": "203.0.113.7"}}, {ID: "2", Attrs: map[string]string{}}, {ID: "3"}}

	var b bytes.Buffer
	require.NoError(t, Render(&b, r, cs, now, nil))
	require.Equal(t, "ID  PUBLIC IP\n1   203.0.113.7\n2   -\n3   -\n", b.String())

	f, err := cs.ParseFilter("public-ip=203.0.113.7")
	require.NoError(t, err)

	for i, want := range []bool{true, false, false} {
		got, err := f.Match(r[i], now)
		require.NoError(t, err)
		require.Equal(t, want, got, r[i].ID)
	}

	cs.Sort(r, "-public-ip", now)
	require.Equal(t, "1", r[0].ID)
}

// TestFold: the two exit prefixes are the word exit, after the other
// routes whatever the order they came in; one of them alone is shown as it
// is.
func TestFold(t *testing.T) {
	t.Parallel()

	c := Column[row]{Name: "routes", Field: "enabledRoutes", Fold: Exit(), Default: true}

	for _, tt := range []struct {
		routes []string
		want   string
	}{
		{[]string{"10.0.0.0/8", "0.0.0.0/0", "::/0"}, "10.0.0.0/8, exit"},
		{[]string{"::/0", "10.0.0.0/8", "0.0.0.0/0"}, "10.0.0.0/8, exit"},
		{[]string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "192.168.0.0/24"}, "10.0.0.0/8, 192.168.0.0/24, exit"},
		{[]string{"0.0.0.0/0"}, "0.0.0.0/0"},
		{nil, ""},
	} {
		require.Equal(t, tt.want, c.cell(row{Routes: tt.routes}, now, false), tt.routes)
	}

	require.Equal(t, "exit", c.cell(row{Routes: []string{"0.0.0.0/0", "::/0"}}, now, true))
}

// TestInvalid: a null time that the row says is invalid shows as invalid,
// not never, in a table and a sheet; no time filter finds it, and it sorts
// with the rows that have no value.
func TestInvalid(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "id", Field: "id", Default: true},
		{Name: "expiry", Field: "expiry", Default: true, Ahead: true, Invalid: func(r row) bool { return r.Name == "bad" }},
	}
	require.NoError(t, cs.Check())

	rs := []row{
		{ID: "1", Name: "bad", Expiry: nullable.NewNullNullable[time.Time]()},
		{ID: "2", Expiry: nullable.NewNullNullable[time.Time]()},
		{ID: "3", Expiry: nullable.NewNullableWithValue(now.Add(time.Hour))},
	}

	var b bytes.Buffer
	require.NoError(t, Render(&b, rs, cs, now, nil))
	require.Equal(t, "ID  EXPIRY\n1   invalid\n2   never\n3   in 1h\n", b.String())

	b.Reset()
	require.NoError(t, Sheet(&b, rs[0], cs, nil, now))
	require.Equal(t, "ID:      1\nExpiry:  invalid\n", b.String())

	for text, want := range map[string][]bool{
		"expiry=never": {false, true, false},
		"expiry<7d":    {false, false, true},
		"expiry>1m":    {false, false, true},
	} {
		f, err := cs.ParseFilter(text)
		require.NoError(t, err)

		for i, r := range rs {
			got, err := f.Match(r, now)
			require.NoError(t, err)
			require.Equal(t, want[i], got, "%s on %s", text, r.ID)
		}
	}

	cs.Sort(rs, "-expiry", now)
	require.Equal(t, []string{"3", "1", "2"}, ids(rs))
}

// TestFarTime: a time further than a Duration holds, such as an expiry in
// 2999, reads as far in a cell and a sheet, and a filter of a span finds it
// on the far side, ahead and back.
func TestFarTime(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "id", Field: "id", Default: true},
		{Name: "expiry", Field: "expiry", Default: true, Ahead: true},
		{Name: "last-seen", Field: "lastSeen", Default: true},
	}
	require.NoError(t, cs.Check())

	far := time.Date(2999, 8, 27, 0, 0, 0, 0, time.UTC)
	rs := []row{
		{ID: "1", Expiry: nullable.NewNullableWithValue(far), Seen: time.Date(1700, 1, 1, 0, 0, 0, 0, time.UTC)},
		{ID: "2", Expiry: nullable.NewNullableWithValue(now.Add(time.Hour)), Seen: now.Add(-time.Hour)},
	}

	var b bytes.Buffer
	require.NoError(t, Render(&b, rs, cs, now, nil))
	require.Equal(t, "ID  EXPIRY      LAST SEEN\n1   in 355306d  119382d ago\n2   in 1h       1h ago\n", b.String())

	b.Reset()
	require.NoError(t, Sheet(&b, rs[0], cs, nil, now))
	require.Equal(t, "ID:         1\nExpiry:     in 355306d (2999-08-27 00:00 UTC)\nLast seen:  119382d ago (1700-01-01 00:00 UTC)\n", b.String())

	for text, want := range map[string][]bool{
		"expiry<7d":      {false, true},
		"expiry>90d":     {true, false},
		"last-seen>365d": {true, false},
		"last-seen<1d":   {false, true},
	} {
		f, err := cs.ParseFilter(text)
		require.NoError(t, err)

		for i, r := range rs {
			got, err := f.Match(r, now)
			require.NoError(t, err)
			require.Equal(t, want[i], got, "%s on %s", text, r.ID)
		}
	}
}
