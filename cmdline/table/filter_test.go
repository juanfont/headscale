package table

import (
	"bytes"
	"slices"
	"strconv"
	"strings"
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
	rs[0].Version, rs[0].Nodes = "1.82.0-tf0f4a2a8d-g7d0d5a7d3", []ref{
		{"1", "web"},
		{"2", "db"},
	}
	rs[1].Version = "1.80.2"

	return append(rs, row{
		ID:      "9",
		Name:    "edge",
		Version: "unknown",
		Online:  true,
		Count:   3,
		Seen:    now.Add(-40 * 24 * time.Hour),
		Expiry:  nullable.NewNullableWithValue(now.Add(-time.Hour)),
		Owner: owner{
			User: nullable.NewNullableWithValue(
				user{ID: "4", LoginName: "bob@example.com"},
			),
			Tags: []string{},
		},
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
	require.Equal(
		t,
		&ValueError{Text: `unknown column "nam". Did you mean "name"?`, Unknown: true},
		err,
	)

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

// TestSortMissingID: a row with no ID leaves the others in numeric order.
func TestSortMissingID(t *testing.T) {
	t.Parallel()

	type item struct {
		ID *string `json:"id"`
	}

	cols := Columns[item]{{Name: "id", Field: "id"}}
	low, high := item{new("2")}, item{new("10")}

	for _, key := range []string{"id", "-id"} {
		rs := []item{high, {}, low}
		cols.Sort(rs, key, now)
		rs = slices.DeleteFunc(rs, func(i item) bool { return i.ID == nil })

		want := []item{low, high}
		if key == "-id" {
			want = []item{high, low}
		}

		require.Equal(t, want, rs, key)
	}
}

// TestAdjacentLargeIDs: IDs beyond 2^53 that round to one float64 still
// sort and filter as the integers they are.
func TestAdjacentLargeIDs(t *testing.T) {
	t.Parallel()

	const lower, upper = "9007199254740992", "9007199254740993"

	rs := []row{{ID: upper}, {ID: lower}}
	listCols.Sort(rs, "id", now)
	require.Equal(t, []string{lower, upper}, ids(rs))

	listCols.Sort(rs, "-id", now)
	require.Equal(t, []string{upper, lower}, ids(rs))

	for condition, id := range map[string]string{"id>" + lower: upper, "id<" + upper: lower, "id>0.99999999999999999": "1"} {
		f, err := listCols.ParseFilter(condition)
		require.NoError(t, err)
		match, err := f.Match(row{ID: id}, now)
		require.NoError(t, err)
		require.True(t, match, condition)
	}
}

// TestRelativeDurationBoundary: a span longer than 2^53 nanoseconds still
// tells one nanosecond apart.
func TestRelativeDurationBoundary(t *testing.T) {
	t.Parallel()

	limit := 105 * 24 * time.Hour
	f, err := listCols.ParseFilter("last-seen>105d")
	require.NoError(t, err)

	got, err := f.Match(row{Seen: now.Add(-limit - time.Nanosecond)}, now)
	require.NoError(t, err)
	require.True(t, got, "one nanosecond beyond")

	got, err = f.Match(row{Seen: now.Add(-limit)}, now)
	require.NoError(t, err)
	require.False(t, got, "at the limit")
}

// TestNonFiniteThreshold: NaN and Inf parse as floats but compare with
// nothing, so a filter of them is a mistake, not an empty list.
func TestNonFiniteThreshold(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"count<NaN", "count>Inf", "count>-inf", "id<NaN", "id>+Inf"} {
		_, err := listCols.ParseFilter(text)
		require.Error(t, err, text)
	}

	_, err := listCols.ParseFilter("count<1.5")
	require.NoError(t, err)
}

// TestZeroDurationFilter: a span of zero is refused, as the expiry flag
// refuses it.
func TestZeroDurationFilter(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"last-seen<0d", "last-seen>0s", "expiry<0m"} {
		_, err := listCols.ParseFilter(text)
		require.Error(t, err, text)
	}

	_, err := listCols.ParseFilter("last-seen<1m")
	require.NoError(t, err)
}

// TestVersionFilterWhole: the value of a version filter is one version,
// with a build suffix at most.
func TestVersionFilterWhole(t *testing.T) {
	t.Parallel()

	for _, text := range []string{"version>1.80<1.82", "version<1.82 ", "version=1.80,1.82", "version>1.80x"} {
		_, err := listCols.ParseFilter(text)
		require.Error(t, err, text)
	}

	for _, text := range []string{"version<1.82", "version>v1.80.2", "version=1.82.0-tf0f4a2a8d-g7d0d5a7d3"} {
		_, err := listCols.ParseFilter(text)
		require.NoError(t, err, text)
	}
}

// TestReadTimeStrict: what time.Parse takes beyond RFC 3339 is refused.
func TestReadTimeStrict(t *testing.T) {
	t.Parallel()

	for _, s := range []string{
		"2026-07-22T00:30:00+00:60", "2026-07-22T00:30:00+24:00",
		"2026-07-22T1:30:00Z", "2026-07-22T01:30:00,5Z", "2026-07-22T01:30:00.Z",
	} {
		_, _, _, err := ReadTime(s)
		require.Error(t, err, s)
	}

	for s, want := range map[string]time.Time{
		"2026-07-22T00:30:00+01:00": time.Date(2026, 7, 21, 23, 30, 0, 0, time.UTC),
		"2026-07-22T23:59:59-23:59": time.Date(2026, 7, 23, 23, 58, 59, 0, time.UTC),
		"2026-07-22T00:30:00Z":      time.Date(2026, 7, 22, 0, 30, 0, 0, time.UTC),
		"2026-07-22T00:30:00.123Z":  time.Date(2026, 7, 22, 0, 30, 0, 123e6, time.UTC),
	} {
		_, at, _, err := ReadTime(s)
		require.NoError(t, err, s)
		require.True(t, want.Equal(at), s)
	}
}

// TestIntegerColumnExact: a number column of integers sorts and filters by
// the integers, also where two of them, or one and the threshold, round to
// the same float64.
func TestIntegerColumnExact(t *testing.T) {
	t.Parallel()

	type item struct {
		Count  int64  `json:"count"`
		Ucount uint64 `json:"ucount"`
	}

	cols := Columns[item]{
		{Name: "count", Field: "count"},
		{Name: "ucount", Field: "ucount"},
	}

	rs := []item{{1<<53 + 1, 1<<64 - 1}, {1 << 53, 1<<64 - 2}}
	cols.Sort(rs, "count", time.Time{})
	require.Equal(t, int64(1<<53), rs[0].Count)
	cols.Sort(rs, "ucount", time.Time{})
	require.Equal(t, uint64(1<<64-2), rs[0].Ucount)

	for _, tt := range []struct {
		filter string
		row    item
		want   bool
	}{
		{"count>0.99999999999999999", item{Count: 1}, true},
		{"count<1.00000000000000001", item{Count: 1}, true},
		{"count>1.00000000000000001", item{Count: 1}, false},
		{"count>9007199254740992", item{Count: 1<<53 + 1}, true},
		{"count<9007199254740993", item{Count: 1 << 53}, true},
		{"ucount>18446744073709551614", item{Ucount: 1<<64 - 1}, true},
		{"count<1e-2147483650", item{}, true},
		{"count>-1e-2147483650", item{}, true},
		{"count>1e-2147483650", item{}, false},
		{"count=1", item{Count: 1}, true},
		{"count=-0x1p-2147483650", item{}, false},
		{"count<-0x1p-2147483650", item{}, false},
		{"count>-0x1p-2147483650", item{}, true},
		{"count<0x1p-2147483650", item{}, true},
		{"count>0x1p-1100", item{}, false},
		{"count<0x1p-1100", item{}, true},
		{"count>0x0p-2147483650", item{}, false},
		{"count=0x0p-2147483650", item{}, true},
	} {
		f, err := cols.ParseFilter(tt.filter)
		require.NoError(t, err, tt.filter)

		got, err := f.Match(tt.row, time.Time{})
		require.NoError(t, err)
		require.Equal(t, tt.want, got, tt.filter)
	}
}

// TestIDOrderGrid: IDs compare with < and > and sort by their exact value,
// also where two of them round to the same float64 or to zero, in decimal
// and in hexadecimal alike. Each value is a row and a threshold against
// each other; a group holds spellings of one value.
func TestIDOrderGrid(t *testing.T) {
	t.Parallel()

	type item struct {
		ID string `json:"id"`
	}

	groups := [][]string{
		{"-9007199254740993"},
		{"-9007199254740992", "-0x1p53"},
		{"-1", "-1.0", "-10e-1", "-0x1p0", "-0x.8p1"},
		{"-1e-325"},
		{"-1e-326"},
		{"-0x1p-1099"},
		{"-0x1p-1100", "-0x2p-1101"},
		{"-0x1p-2147483650"},
		{"-1e-2147483648"},
		{"0", "-0", "0.0", "0e5", "0x0p0", "-0x0p-2147483650"},
		{"1e-2147483648"},
		{"0x1p-2147483650", "0x2p-2147483651"},
		{"0x1p-1101"},
		{"0x1p-1100", "0x.8p-1099"},
		{"0x1p-1099"},
		{"1e-326"},
		{"1e-325", "10e-326", "0.1e-324"},
		{"0.1", "1e-1"},
		{"1", "1.0", "10e-1", "0x1p0", "0x.8p1"},
		{"9007199254740992", "0x1p53", "0x20000000000000p0"},
		{"9007199254740993", "0x20000000000001p0"},
		{"1e308"},
	}

	cols := Columns[item]{{Name: "id", Field: "id"}}

	for i, rows := range groups {
		for j, thresholds := range groups {
			for _, row := range rows {
				for _, th := range thresholds {
					for op, want := range map[string]bool{"<": i < j, ">": i > j} {
						f, err := cols.ParseFilter("id" + op + th)
						require.NoError(t, err, th)

						got, err := f.Match(item{row}, time.Time{})
						require.NoError(t, err)
						require.Equal(t, want, got, "%s %s %s", row, op, th)
					}
				}
			}
		}
	}

	want := make([]item, 0, len(groups))
	for _, g := range groups {
		want = append(want, item{g[0]})
	}

	rows := slices.Clone(want)
	slices.Reverse(rows)

	cols.Sort(rows, "id", time.Time{})
	require.Equal(t, want, rows)
}

// TestIDMixedBaseBound holds examples of the shortcut of exact.log2, a
// decimal ID against a hexadecimal threshold beyond big.Float's exponents:
// each row is a neighbour that compares exactly or ties today. Where a tie
// starts depends on how near the neighbour is.
func TestIDMixedBaseBound(t *testing.T) {
	t.Parallel()

	type item struct {
		ID string `json:"id"`
	}

	cols := Columns[item]{{Name: "id", Field: "id"}}

	for _, tt := range []struct {
		id, threshold string
		less, greater bool
	}{
		{"1e-1" + strings.Repeat("0", 60), "0x1p-3321928094887362347870319429489390175864831393024580612054750", true, false},
		{"1e-1" + strings.Repeat("0", 60), "0x1p-3321928094887362347870319429489390175864831393024580612054756", false, false},
		{"1e-1" + strings.Repeat("0", 65), "0x1p-332192809488736234787031942948939017586483139302458061205475639575", false, false},
	} {
		for op, want := range map[string]bool{"<": tt.less, ">": tt.greater} {
			f, err := cols.ParseFilter("id" + op + tt.threshold)
			require.NoError(t, err)

			got, err := f.Match(item{tt.id}, time.Time{})
			require.NoError(t, err)
			require.Equal(t, want, got, "%s %s", op, tt.threshold[:12])
		}
	}
}

// TestSortKeepsTies: rows with the same value keep the order of the API,
// in both directions.
func TestSortKeepsTies(t *testing.T) {
	t.Parallel()

	for _, key := range []string{"count", "-count"} {
		rs := make([]row, 72)
		for i := range rs {
			rs[i] = row{ID: strconv.Itoa(i), Count: int64(i % 3)}
		}

		listCols.Sort(rs, key, now)

		last := map[int64]int{}

		for _, r := range rs {
			at, _ := strconv.Atoi(r.ID)
			if before, ok := last[r.Count]; ok {
				require.Less(t, before, at, "%s: tie of %d out of order", key, r.Count)
			}

			last[r.Count] = at
		}
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

// TestMatchNeverIsNull: never is a time the API sends as null, not one it
// sends as the year 1, which is a time long past.
func TestMatchNeverIsNull(t *testing.T) {
	t.Parallel()

	never, err := listCols.ParseFilter("expiry=never")
	require.NoError(t, err)

	past, err := listCols.ParseFilter("expiry<7d")
	require.NoError(t, err)

	for _, tt := range []struct {
		expiry       nullable.Nullable[time.Time]
		never, ended bool
	}{
		{nullable.NewNullNullable[time.Time](), true, false},
		{nullable.NewNullableWithValue(time.Time{}), false, true},
	} {
		r := row{ID: "1", Expiry: tt.expiry}

		ok, err := never.Match(r, now)
		require.NoError(t, err)
		require.Equal(t, tt.never, ok, "expiry=never on %v", tt.expiry)

		ok, err = past.Match(r, now)
		require.NoError(t, err)
		require.Equal(t, tt.ended, ok, "expiry<7d on %v", tt.expiry)
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
	require.EqualError(
		t,
		err,
		`column "id" holds IDs that are not numbers. It works with = only.`,
	)
}

func TestSort(t *testing.T) {
	t.Parallel()

	for key, want := range map[string][]string{
		"id":         {"9", "12", "13"},
		"-id":        {"13", "12", "9"},
		"name":       {"13", "9", "12"},
		"count":      {"12", "13", "9"},
		"-count":     {"9", "12", "13"},
		"online":     {"13", "12", "9"},
		"last-seen":  {"9", "13", "12"},
		"expiry":     {"13", "9", "12"},
		"version":    {"9", "13", "12"}, // unknown does not read, so it comes first
		"-version":   {"12", "13", "9"},
		"owner":      {"12", "9", "13"},
		"ip":         {"9", "12", "13"},
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

	for _, s := range []string{"30", "0", "-1h", "1.5d", "soon", ""} {
		_, _, _, err := ReadTime(s)
		require.Error(t, err, s)
	}
}

func TestDeclaration(t *testing.T) {
	t.Parallel()

	var b bytes.Buffer
	require.NoError(t, Declaration(&b, listCols[:4].Info()))
	require.Equal(t, `COLUMN   FIELD          KIND     DEFAULT  DESCRIPTION
version  clientVersion  version  no       Client version
nodes    nodes          list     no       Nodes
id       id             id       yes
name     name           text     yes
`, b.String())

	require.Equal(
		t,
		ColumnInfo{
			Name:  "version",
			Field: "clientVersion",
			Kind:  Version,
			Help:  "Client version",
		},
		listCols.Info()[0],
	)
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
