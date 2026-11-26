package table

import (
	"bytes"
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
	Untagged string
}

var now = time.Date(2026, 11, 10, 9, 14, 0, 0, time.UTC)

var cols = Columns[row]{
	{Name: "id", Field: "id", Default: true},
	{Name: "name", Field: "name", Default: true},
	{Name: "owner", Field: "owner", Default: true},
	{Name: "ip", Field: "addresses", Default: true},
	{Name: "online", Field: "online", Default: true},
	{Name: "last-seen", Field: "lastSeen", Default: true},
	{Name: "expiry", Field: "expiry", Default: true},
	{Name: "count", Field: "count"},
	{Name: "hint", Field: "inner.hint"},
}

func rows() []row {
	return []row{
		{
			ID:     "12",
			Name:   "mynode",
			Online: true,
			IPs:    []string{"100.64.0.1", "fd7a::1"},
			Seen:   now,
			Expiry: nullable.NewNullableWithValue(now.Add(89*24*time.Hour + time.Hour)),
			Owner: owner{
				User: nullable.NewNullableWithValue(user{ID: "3", LoginName: "alice"}),
				Tags: []string{},
			},
		},
		{
			ID:   "13",
			Name: "builder",
			IPs:  []string{"100.64.0.2"},
			Seen: now.Add(
				-3*24*time.Hour - time.Minute,
			),
			Expiry: nullable.NewNullNullable[time.Time](),
			Owner:  owner{Tags: []string{"tag:ci", "tag:build"}},
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
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.EqualError(t, Columns[row]{tt.col}.Check(), tt.want)
		})
	}
}

func TestCheckTwice(t *testing.T) {
	t.Parallel()

	require.EqualError(
		t,
		Columns[row]{{Name: "id", Field: "id"}, {Name: "id", Field: "name"}}.Check(),
		`column "id" is declared twice`,
	)
	require.NoError(
		t,
		Columns[row]{
			{Name: "v", Field: "name", Kind: Version},
			{Name: "i", Field: "name", Kind: ID},
		}.Check(),
	)
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

func TestRender(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, Render(&b, rows(), cols, now))

	want := `ID  NAME     OWNER              IP                   ONLINE  LAST SEEN  EXPIRY
12  mynode   alice              100.64.0.1, fd7a::1  yes     now        in 89d
13  builder  tag:ci, tag:build  100.64.0.2           no      3d ago     never
`
	if diff := cmp.Diff(want, b.String()); diff != "" {
		t.Errorf("table (-want +got):\n%s", diff)
	}
}

func TestSheet(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name string
		row  row
		want string
	}{
		{
			name: "user owner",
			row:  rows()[0],
			want: `ID:         12
Name:       mynode
Owner:      User 3 (alice)
IP:         100.64.0.1, fd7a::1
Online:     yes
Last seen:  now (2026-11-10 09:14 UTC)
Expiry:     in 89d (2027-02-07 10:14 UTC)
Count:      0
Hint:       -
`,
		},
		{
			name: "a null field has its line",
			row:  rows()[1],
			want: `ID:         13
Name:       builder
Owner:      tag:ci, tag:build
IP:         100.64.0.2
Online:     no
Last seen:  3d ago (2026-11-07 09:13 UTC)
Expiry:     never
Count:      0
Hint:       -
`,
		},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			var b bytes.Buffer
			require.NoError(t, Sheet(&b, tt.row, cols, now))

			if diff := cmp.Diff(tt.want, b.String()); diff != "" {
				t.Errorf("sheet (-want +got):\n%s", diff)
			}
		})
	}
}

// TestHeader: Header is the table's; the sheet labels by the name, with a
// few words in upper case.
func TestHeader(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{
		{Name: "public-ip", Field: "name", Header: "Address", Default: true},
	}

	var b bytes.Buffer
	require.NoError(t, Render(&b, rows()[:1], cs, now))
	require.Equal(t, "ADDRESS\nmynode\n", b.String())

	b.Reset()
	require.NoError(t, Sheet(&b, rows()[0], cs, now))
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

	require.Equal(t, "never", Ago(time.Time{}, now))
	require.Equal(t, "never", When(time.Time{}, now))
	require.Equal(
		t,
		"in 60d (2027-01-09 09:14 UTC)",
		When(now.Add(60*24*time.Hour), now),
	)
}

func TestEntity(t *testing.T) {
	t.Parallel()

	require.Equal(t, "Node 12 (mynode)", Entity("node", "12", "mynode"))
	require.Equal(
		t,
		"User 5 (carol@example.com)",
		Entity("user", "5", "carol@example.com"),
	)
	require.Equal(t, "API key 2 (tr81ys)", Entity("apiKey", "2", "tr81ys"))
	require.Equal(t, "OAuth client c9f2", Entity("oauthClient", "c9f2", "CI"))
	require.Equal(t, "widget 7", Entity("widget", "7", ""))
}
