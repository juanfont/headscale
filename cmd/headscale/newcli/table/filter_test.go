package table

import (
	"bytes"
	"testing"
	"time"

	"github.com/oapi-codegen/nullable"
	"github.com/stretchr/testify/require"
)

var listCols = append(Columns[row]{
	{Name: "version", Field: "clientVersion", Kind: Version, Help: "Client version"},
	{Name: "nodes", Field: "nodes", Help: "Nodes"},
}, cols...)

// listRows are rows() and a third, whose ID sorts before the others only
// as a number.
func listRows() []row {
	rs := rows()
	rs[0].Version, rs[0].Nodes = "1.82.0-tf0f4a2a8d-g7d0d5a7d3", []ref{{"1", "web"}, {"2", "db"}}
	rs[1].Version = "1.80.2"

	return append(rs, row{
		ID: "9", Name: "edge", Version: "unknown", Online: true, Count: 3,
		Seen:   now.Add(-40 * 24 * time.Hour),
		Expiry: nullable.NewNullableWithValue(now.Add(-time.Hour)),
		Owner:  owner{User: nullable.NewNullableWithValue(user{ID: "4", LoginName: "bob@example.com"}), Tags: []string{}},
	})
}

func ids(rs []row) []string {
	out := make([]string, len(rs))
	for i, r := range rs {
		out[i] = r.ID
	}

	return out
}

func TestFind(t *testing.T) {
	t.Parallel()

	c, err := listCols.Find("last-seen")
	require.NoError(t, err)
	require.Equal(t, "lastSeen", c.Field)

	_, err = listCols.Find("nam")
	require.Equal(t, &ValueError{Text: `unknown column "nam". Did you mean "name"?`, Unknown: true}, err)

	_, err = listCols.Find("colour")
	require.Equal(t, &ValueError{Text: `unknown column "colour".`, Unknown: true}, err)
}

func TestPick(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		words []string
		want  []string
	}{
		{nil, []string{"id", "name", "owner", "ip", "online", "last-seen", "expiry"}},
		{[]string{"name", "id"}, []string{"name", "id"}},
		{[]string{"+count", "+id"}, []string{"id", "name", "owner", "ip", "online", "last-seen", "expiry", "count"}},
		{[]string{"-ip", "-count", "-owner"}, []string{"id", "name", "online", "last-seen", "expiry"}},
	} {
		require.Equal(t, tt.want, listCols.Pick(tt.words).Names(), tt.words)
	}
}

func TestParseFilter(t *testing.T) {
	t.Parallel()

	for text, want := range map[string]string{
		"name":           `"name" is not a filter: write a column, then =, :, < or >, then a value.`,
		"=x":             `"=x" is not a filter: write a column, then =, :, < or >, then a value.`,
		"colour=red":     `unknown column "colour".`,
		"online>true":    `column "online" is a bool. It works with = only.`,
		"name<a":         `column "name" holds text. It works with = and : only.`,
		"id:1":           `column "id" is an ID. It works with =, < and > only.`,
		"count>=0":       `"count>=0": there is no >=. The operators are =, :, < and >.`,
		"count<=0":       `"count<=0": there is no <=. The operators are =, :, < and >.`,
		"owner<x":        `column "owner" is an owner. It works with = and : only.`,
		"ip>1":           `column "ip" is a list. It works with = and : only.`,
		"count=":         `the filter "count=" has no value.`,
		"name:":          `the filter "name:" has no value.`,
		"count>many":     `column "count" holds numbers, not "many".`,
		"id>x":           `column "id" compares IDs as numbers with < and >, not "x".`,
		"online=maybe":   `column "online" takes true, false, yes or no, not "maybe".`,
		"version<new":    `column "version" compares versions such as 1.80, not "new".`,
		"expiry=soon":    `column "expiry" takes = only in expiry=never.`,
		"last-seen>30":   `column "last-seen" takes a duration such as 30d, or a date such as 2026-01-01, not "30".`,
		"last-seen>-1h":  `column "last-seen" takes a duration such as 30d, or a date such as 2026-01-01, not "-1h".`,
		"last-seen>0":    `column "last-seen" takes a duration such as 30d, or a date such as 2026-01-01, not "0".`,
		"last-seen>1.5d": `column "last-seen" takes a duration such as 30d, or a date such as 2026-01-01, not "1.5d".`,
	} {
		_, err := listCols.ParseFilter(text)
		require.EqualError(t, err, want, text)
	}
}

// TestMatch holds each rule of the filter grammar, kind by kind.
func TestMatch(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		filter string
		want   []string
	}{
		{"id=12", []string{"12"}},
		{"id>10", []string{"12", "13"}},
		{"id<10", []string{"9"}},
		{"name=mynode", []string{"12"}},
		{"name=my", nil},
		{"name:e", []string{"12", "13", "9"}},
		{"name:my", []string{"12"}},
		{"hint=", []string{"12", "13", "9"}},
		{"count=3", []string{"9"}},
		{"count>0", []string{"9"}},
		{"count<3", []string{"12", "13"}},
		{"online=true", []string{"12", "9"}},
		{"online=yes", []string{"12", "9"}},
		{"online=no", []string{"13"}},
		{"version=1.80.2", []string{"13"}},
		{"version<1.81", []string{"13"}},
		{"version>1.80", []string{"12", "13"}},
		// A Tailscale build suffix is no prerelease: 1.82.0-t… is 1.82.0.
		{"version<1.82.0", []string{"13"}},
		{"version=1.82", []string{"12"}},
		{"version>1.100", nil},
		{"ip=100.64.0.1", []string{"12"}},
		{"ip:fd7a", []string{"12"}},
		{"nodes=web", []string{"12"}},
		{"nodes:d", []string{"12"}},
		{"last-seen>30d", []string{"9"}},
		{"last-seen<1h", []string{"12"}},
		{"last-seen<2026-11-08", []string{"13", "9"}},
		{"last-seen>2026-11-08T00:00:00Z", []string{"12"}},
		{"expiry<7d", []string{"9"}},
		{"expiry>7d", []string{"12"}},
		{"expiry=never", []string{"13"}},
		{"owner=tag:ci", []string{"13"}},
		{"owner:bob", []string{"9"}},
		{"owner:tag:b", []string{"13"}},
	} {
		f, err := listCols.ParseFilter(tt.filter)
		require.NoError(t, err, tt.filter)

		var got []string

		for _, r := range listRows() {
			ok, err := f.Match(r, now)
			require.NoError(t, err)

			if ok {
				got = append(got, r.ID)
			}
		}

		require.Equal(t, tt.want, got, tt.filter)
	}
}

// TestOwnerUser: owner=<user> matches the rows of the user that the caller
// resolved; a tag needs no resolving.
func TestOwnerUser(t *testing.T) {
	t.Parallel()

	f, err := listCols.ParseFilter("owner=bob")
	require.NoError(t, err)

	word, ok := f.User()
	require.True(t, ok)
	require.Equal(t, "bob", word)

	match := func() []string {
		var got []string

		for _, r := range listRows() {
			if ok, _ := f.Match(r, now); ok {
				got = append(got, r.ID)
			}
		}

		return got
	}
	require.Empty(t, match(), "not resolved")

	f.Resolve("4")
	require.Equal(t, []string{"9"}, match())

	tag, _ := listCols.ParseFilter("owner=tag:ci")
	_, ok = tag.User()
	require.False(t, ok)
}

func TestMatchIDNotNumber(t *testing.T) {
	t.Parallel()

	f, err := listCols.ParseFilter("id>1")
	require.NoError(t, err)

	r := listRows()[0]
	r.ID = "c9f2"
	_, err = f.Match(r, now)
	require.EqualError(t, err, `column "id" holds IDs that are not numbers. It works with = only.`)
}

func TestSort(t *testing.T) {
	t.Parallel()

	for key, want := range map[string][]string{
		"id":        {"9", "12", "13"},
		"-id":       {"13", "12", "9"},
		"name":      {"13", "9", "12"},
		"count":     {"12", "13", "9"},
		"-count":    {"9", "12", "13"},
		"online":    {"13", "12", "9"},
		"last-seen": {"9", "13", "12"},
		// A row with no value comes last both ways: a null time, a version
		// that does not read, an empty list.
		"expiry":     {"9", "12", "13"},
		"-expiry":    {"12", "9", "13"},
		"version":    {"13", "12", "9"},
		"-version":   {"12", "13", "9"},
		"owner":      {"12", "9", "13"},
		"ip":         {"12", "13", "9"},
		"-ip":        {"13", "12", "9"},
		"-last-seen": {"12", "13", "9"},
	} {
		rs := listRows()
		listCols.Sort(rs, key, now)
		require.Equal(t, want, ids(rs), key)
	}

	// IDs that are not all numbers sort as text.
	rs := listRows()
	rs[2].ID = "c9f2"
	listCols.Sort(rs, "id", now)
	require.Equal(t, []string{"12", "13", "c9f2"}, ids(rs))
}

func TestReadTime(t *testing.T) {
	t.Parallel()

	for s, want := range map[string]time.Duration{
		"30m": 30 * time.Minute, "24h": 24 * time.Hour, "90d": 90 * 24 * time.Hour,
		"2w": 14 * 24 * time.Hour, "1d12h": 36 * time.Hour, "1h30m": 90 * time.Minute, "1.5h": 90 * time.Minute,
	} {
		d, _, span, err := ReadTime(s)
		require.NoError(t, err, s)
		require.True(t, span, s)
		require.Equal(t, want, d, s)
	}

	_, at, span, err := ReadTime("2027-08-27")
	require.NoError(t, err)
	require.False(t, span)
	require.Equal(t, time.Date(2027, 8, 27, 0, 0, 0, 0, time.UTC), at)

	_, at, _, err = ReadTime("2027-08-27T10:00:00Z")
	require.NoError(t, err)
	require.Equal(t, time.Date(2027, 8, 27, 10, 0, 0, 0, time.UTC), at)

	for _, s := range []string{"30", "0", "-1h", "1.5d", "soon", "", "1d1y"} {
		_, _, _, err := ReadTime(s)
		require.Error(t, err, s)
		require.NotErrorIs(t, err, ErrTooLong, s)
	}

	// No limit on a time, but on a duration: the parser holds some 292 years.
	for _, s := range []string{"300y", "3000000h"} {
		_, _, _, err := ReadTime(s)
		require.ErrorIs(t, err, ErrTooLong, s)
	}

	d, _, _, err := ReadTime("292y")
	require.NoError(t, err)
	require.Equal(t, 292*365*24*time.Hour, d)
}

func TestDeclaration(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, Declaration(&b, listCols[:4].Info()))
	//nolint:dupword // a column is often named as its field
	require.Equal(t, `COLUMN   FIELD          KIND     DEFAULT  DESCRIPTION
version  clientVersion  version  no       Client version
nodes    nodes          list     no       Nodes
id       id             id       yes
name     name           text     yes
`, b.String())

	require.Equal(t, ColumnInfo{Name: "version", Field: "clientVersion", Kind: Version, Help: "Client version"}, listCols.Info()[0])
}

func TestClosest(t *testing.T) {
	t.Parallel()

	names := []string{"nodes", "users", "version"}
	require.Equal(t, "nodes", Closest("nodse", names))
	require.Equal(t, "users", Closest("user", names))
	require.Empty(t, Closest("policy", names))
	require.Equal(t, 0, distance("", ""))
	require.Equal(t, 3, distance("abc", ""))
}

// TestMatchFold: a route column matches exit as it shows it, and each
// prefix as it is.
func TestMatchFold(t *testing.T) {
	t.Parallel()

	cs := Columns[row]{{Name: "routes", Field: "enabledRoutes", Fold: Exit(), Default: true}}
	gateway := row{Routes: []string{"10.0.0.0/8", "0.0.0.0/0", "::/0"}}
	half := row{Routes: []string{"0.0.0.0/0"}}

	for _, tt := range []struct {
		filter      string
		gateway, hf bool
	}{
		{"routes=exit", true, false},
		{"routes:exi", true, false},
		{"routes=0.0.0.0/0", true, true},
		{"routes=10.0.0.0/8", true, false},
	} {
		f, err := cs.ParseFilter(tt.filter)
		require.NoError(t, err)

		got, err := f.Match(gateway, now)
		require.NoError(t, err)
		require.Equal(t, tt.gateway, got, tt.filter)

		got, err = f.Match(half, now)
		require.NoError(t, err)
		require.Equal(t, tt.hf, got, tt.filter)
	}
}
