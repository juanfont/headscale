package table

import (
	"cmp"
	"errors"
	"fmt"
	"io"
	"math"
	"math/big"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/cmdline/duration"
)

// ValueError is a value of --columns, --filter or --sort that the declaration
// refuses. Its text is the CLI's sentence; Unknown marks a column name that
// is not declared, after which the CLI points to --list-columns.
type ValueError struct {
	Text    string
	Unknown bool
}

func (m *ValueError) Error() string { return m.Text }

func mistake(format string, a ...any) *ValueError {
	return &ValueError{Text: fmt.Sprintf(format, a...)}
}

// Find is the column of that name.
func (cs Columns[R]) Find(name string) (Column[R], error) {
	names := make([]string, len(cs))

	for i, c := range cs {
		if c.Name == name {
			return c, nil
		}

		names[i] = c.Name
	}

	text := "unknown column " + strconv.Quote(name) + "."
	if near := Closest(name, names); near != "" {
		text = "unknown column " + strconv.Quote(
			name,
		) + ". Did you mean " + strconv.Quote(
			near,
		) + "?"
	}

	return Column[R]{}, &ValueError{Text: text, Unknown: true}
}

// Names are the names of the columns, in the order declared.
func (cs Columns[R]) Names() []string {
	out := make([]string, len(cs))
	for i, c := range cs {
		out[i] = c.Name
	}

	return out
}

// Pick is the columns that a value of --columns shows: the list as given,
// or the defaults with each +name added and each -name taken away. Adding
// a column that is shown, or taking away one that is not, changes nothing.
// The names are checked already; a mixed list is the caller's mistake.
func (cs Columns[R]) Pick(words []string) Columns[R] {
	if len(words) == 0 {
		return cs.defaults()
	}

	if w := words[0]; w[0] != '+' && w[0] != '-' {
		out := make(Columns[R], 0, len(words))
		for _, w := range words {
			c, _ := cs.Find(w)
			out = append(out, c)
		}

		return out
	}

	out := cs.defaults()

	for _, w := range words {
		name := w[1:]
		at := slices.IndexFunc(out, func(c Column[R]) bool { return c.Name == name })

		switch {
		case w[0] == '+' && at < 0:
			c, _ := cs.Find(name)
			out = append(out, c)
		case w[0] == '-' && at >= 0:
			out = slices.Delete(out, at, at+1)
		}
	}

	return out
}

// Showing is the default columns, and each other column whose field is
// word in one of rows.
func (cs Columns[R]) Showing(rows []R, word string) Columns[R] {
	var out Columns[R]

	for _, c := range cs {
		if c.Default || slices.ContainsFunc(rows, func(r R) bool {
			v, ok := field(reflect.ValueOf(r), c.Field)

			return ok && v.Kind() == reflect.String && v.String() == word
		}) {
			out = append(out, c)
		}
	}

	return out
}

// Shown is the declaration with the column of that name among the
// defaults; the declaration itself does not change.
func (cs Columns[R]) Shown(name string) Columns[R] {
	out := slices.Clone(cs)
	for i := range out {
		out[i].Default = out[i].Default || out[i].Name == name
	}

	return out
}

func (cs Columns[R]) defaults() Columns[R] {
	var out Columns[R]

	for _, c := range cs {
		if c.Default {
			out = append(out, c)
		}
	}

	return out
}

// ColumnInfo is a column as --list-columns -o json prints it. It is an
// object of the CLI, not of the API, so its keys are Go field names.
type ColumnInfo struct {
	Name    string
	Field   string
	Kind    Kind
	Default bool
	Help    string
}

// Info is the declaration as data.
func (cs Columns[R]) Info() []ColumnInfo {
	out := make([]ColumnInfo, len(cs))

	for i, c := range cs {
		t, _ := fieldType(reflect.TypeFor[R](), c.Field)
		out[i] = ColumnInfo{
			Name:    c.Name,
			Field:   c.Field,
			Kind:    c.kind(t),
			Default: c.Default,
			Help:    c.Help,
		}
	}

	return out
}

// Declaration writes the declaration as --list-columns prints it: the
// column, the API field behind it, its kind, whether it is shown by
// default and what it holds.
func Declaration(w io.Writer, cols []ColumnInfo) error {
	lines := make([][]string, 0, 1+len(cols))
	lines = append(lines, []string{"COLUMN", "FIELD", "KIND", "DEFAULT", "DESCRIPTION"})

	for _, c := range cols {
		lines = append(
			lines,
			[]string{c.Name, c.Field, string(c.Kind), yesNo(c.Default), c.Help},
		)
	}

	return aligned(w, lines)
}

func yesNo(b bool) string {
	if b {
		return "yes"
	}

	return "no"
}

// Filter is one condition of --filter: a column, an operator and a value.
type Filter[R any] struct {
	col  Column[R]
	kind Kind
	op   byte
	text string

	num  float64
	yes  bool
	dur  time.Duration
	at   time.Time
	span bool // the time is a duration from now, not a point in time

	// user is the ID of the user that owner=<user> names, once resolved.
	user string
}

// operators are the operators of a kind; the first line of each kind of
// the table in the proposal.
func operators(k Kind) string {
	switch k {
	case Text, List, Owner:
		return "=:"
	case Bool:
		return "="
	case ID, Number, Time, Version:
	}

	return "=<>"
}

// ParseFilter reads one condition: the column name, the first of = : < >
// after it, and the value. It checks what can be checked without a call:
// the column, the operator for its kind, and the form of the value.
func (cs Columns[R]) ParseFilter(text string) (Filter[R], error) {
	at := strings.IndexAny(text, "=:<>")
	if at <= 0 {
		return Filter[R]{}, mistake(
			"%q is not a filter: write a column, then =, :, < or >, then a value.",
			text,
		)
	}

	c, err := cs.Find(text[:at])
	if err != nil {
		return Filter[R]{}, err
	}

	t, _ := fieldType(reflect.TypeFor[R](), c.Field)
	f := Filter[R]{col: c, kind: c.kind(t), op: text[at], text: text[at+1:]}

	if (f.op == '<' || f.op == '>') && strings.HasPrefix(f.text, "=") {
		return f, mistake(
			"%q: there is no %c=. The operators are =, :, < and >.",
			text,
			f.op,
		)
	}

	if !strings.ContainsRune(operators(f.kind), rune(f.op)) {
		return f, mistake(
			"column %q %s. It works with %s only.",
			c.Name,
			article(f.kind),
			ops(operators(f.kind)),
		)
	}

	if f.text == "" && (f.kind != Text || f.op != '=') {
		return f, mistake("the filter %q has no value.", text)
	}

	return f, f.read()
}

// read checks the value of f for its kind.
func (f *Filter[R]) read() error {
	name := f.col.Name

	switch f.kind { //nolint:exhaustive // text, list and owner take any value
	case Number:
		n, err := strconv.ParseFloat(f.text, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return mistake("column %q holds numbers, not %q.", name, f.text)
		}

		f.num = n
	case ID:
		if f.op == '=' {
			return nil
		}

		n, err := strconv.ParseFloat(f.text, 64)
		if err != nil || math.IsNaN(n) || math.IsInf(n, 0) {
			return mistake(
				"column %q compares IDs as numbers with < and >, not %q.",
				name,
				f.text,
			)
		}

		f.num = n
	case Bool:
		switch f.text {
		case "true", "yes":
			f.yes = true
		case "false", "no":
		default:
			return mistake(
				"column %q takes true, false, yes or no, not %q.",
				name,
				f.text,
			)
		}
	case Version:
		// versionOf stops at the first other character: a build suffix may
		// follow, a second condition such as >1.80<1.82 may not.
		rest := strings.TrimLeft(strings.TrimPrefix(f.text, "v"), "0123456789.")
		suffix := rest == "" ||
			rest[0] == '-' &&
				strings.Trim(
					rest,
					"-.0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ",
				) == ""

		if _, ok := versionOf(f.text); !ok || !suffix {
			return mistake(
				"column %q compares versions such as 1.80, not %q.",
				name,
				f.text,
			)
		}
	case Time:
		if f.op == '=' {
			if f.text != "never" {
				return mistake("column %q takes = only in %s=never.", name, name)
			}

			return nil
		}

		d, t, span, err := ReadTime(f.text)
		if err != nil || span && d == 0 {
			return mistake(
				"column %q takes a duration such as 30d, or a date such as 2026-01-01, not %q.",
				name,
				f.text,
			)
		}

		f.dur, f.at, f.span = d, t, span
	}

	return nil
}

// Column is the name of the column the condition reads.
func (f Filter[R]) Column() string { return f.col.Name }

// User is the word of an owner=<user> condition, which the caller resolves
// to a user ID like a target; false for every other condition.
func (f Filter[R]) User() (string, bool) {
	return f.text, f.kind == Owner && f.op == '=' && !strings.HasPrefix(f.text, "tag:")
}

// Resolve sets the ID of the user that User names.
func (f *Filter[R]) Resolve(id string) { f.user = id }

// Match reports whether row passes the condition. It fails only on an ID
// that is not a number, which < and > cannot compare.
func (f Filter[R]) Match(row R, now time.Time) (bool, error) {
	v, ok := field(reflect.ValueOf(row), f.col.Field)

	if f.kind == Time {
		// An invalid time is neither never nor a time to compare.
		return !f.col.invalid(row) && f.matchTime(v, ok, now), nil
	}

	if f.kind == Owner {
		return ok && f.matchOwner(v), nil
	}

	if !ok {
		// A null text shows as empty, so text= finds it.
		return f.kind == Text && f.op == '=' && f.text == "", nil
	}

	switch f.kind { //nolint:exhaustive // time and owner are above
	case ID:
		if f.op == '=' {
			return v.String() == f.text, nil
		}

		n, err := strconv.ParseFloat(v.String(), 64)
		if err != nil {
			return false, mistake(
				"column %q holds IDs that are not numbers. It works with = only.",
				f.col.Name,
			)
		}

		if n == f.num {
			return compare(float64(compareTiedIDs(v.String(), f.text)), 0, f.op), nil
		}

		return compare(n, f.num, f.op), nil
	case Number:
		return f.matchNumber(v), nil
	case Bool:
		return v.Bool() == f.yes, nil
	case Version:
		row, ok := versionOf(v.String())
		want, _ := versionOf(f.text)

		return ok && compare(float64(compareVersions(row, want)), 0, f.op), nil
	case List:
		// A route list matches exit as the table shows it, and each prefix.
		return slices.ContainsFunc(
			append(f.col.entries(v), items(v)...),
			f.textMatch,
		), nil
	}

	return f.textMatch(v.String()), nil
}

// matchNumber: an integer and a threshold that round to the same float64
// compare exactly, by their digits, as an ID does.
func (f Filter[R]) matchNumber(v reflect.Value) bool {
	n := number(v)
	if n != f.num || !v.CanInt() && !v.CanUint() {
		return compare(n, f.num, f.op)
	}

	var digits string
	if v.CanInt() {
		digits = strconv.FormatInt(v.Int(), 10)
	} else {
		digits = strconv.FormatUint(v.Uint(), 10)
	}

	return compare(float64(compareTiedIDs(digits, f.text)), 0, f.op)
}

func (f Filter[R]) textMatch(s string) bool {
	if f.op == ':' {
		return strings.Contains(s, f.text)
	}

	return s == f.text
}

// matchTime: =never finds a null time. A duration compares how far the
// time is from now, back for an age and ahead for an expiry, a time on the
// other side of now being a distance of zero; a point compares moments.
// No time never matches < or >.
func (f Filter[R]) matchTime(v reflect.Value, ok bool, now time.Time) bool {
	var t time.Time
	if ok {
		t, _ = reflect.TypeAssert[time.Time](v)
	}

	if f.op == '=' {
		return !ok
	}

	if !ok {
		return false
	}

	if !f.span {
		return compare(float64(t.Compare(f.at)), 0, f.op)
	}

	// The distance compares as the moment it puts the cutoff at: Sub
	// saturates some 292 years away, Add does not. f.dur is above zero, so
	// a time on the other side of now is nearer.
	cutoff := now.Add(-f.dur)
	farther, nearer := t.Before(cutoff), t.After(cutoff)

	if f.col.Ahead {
		cutoff = now.Add(f.dur)
		farther, nearer = t.After(cutoff), t.Before(cutoff)
	}

	if f.op == '>' {
		return farther
	}

	return nearer
}

// matchOwner: tag:x finds the rows that have the tag, a user the rows it
// owns, and : looks into the text the table shows.
func (f Filter[R]) matchOwner(v reflect.Value) bool {
	switch {
	case f.op == ':':
		return strings.Contains(ownerCell(v, false), f.text)
	case strings.HasPrefix(f.text, "tag:"):
		tags, _ := field(v, "tags")

		return slices.Contains(items(tags), f.text)
	}

	id, ok := field(v, "user.id")

	return ok && f.user != "" && id.String() == f.user
}

func compare(a, b float64, op byte) bool {
	if op == '<' {
		return a < b
	}

	if op == '>' {
		return a > b
	}

	return a == b
}

// Sort orders rows by the column key names, reversed when key starts with
// "-". A row with no value, which the table shows as "-", "never", empty or
// "invalid", comes last in both directions, so --sort expiry starts with
// what expires next. Ties keep the order of the API. The key is checked
// already.
func (cs Columns[R]) Sort(rows []R, key string, now time.Time) {
	name, reverse := strings.CutPrefix(key, "-")
	c, _ := cs.Find(name)
	t, _ := fieldType(reflect.TypeFor[R](), c.Field)
	kind := c.kind(t)

	numeric := kind == Number ||
		kind == ID && !slices.ContainsFunc(rows, func(r R) bool {
			v, ok := field(reflect.ValueOf(r), c.Field)
			if !ok {
				return false
			}

			_, err := strconv.ParseFloat(v.String(), 64)

			return err != nil
		})

	none := func(r R) bool {
		v, ok := field(reflect.ValueOf(r), c.Field)
		if !ok {
			return true
		}

		switch kind { //nolint:exhaustive // the other kinds always hold a value
		case Text:
			return v.String() == ""
		case Time:
			at, _ := reflect.TypeAssert[time.Time](v)

			return at.IsZero()
		case Version:
			_, ok := versionOf(v.String())

			return !ok
		case List:
			return v.Len() == 0
		}

		return false
	}

	by := func(a, b R) int {
		va, _ := field(reflect.ValueOf(a), c.Field)
		vb, _ := field(reflect.ValueOf(b), c.Field)

		switch {
		case numeric && kind == ID:
			x, _ := strconv.ParseFloat(va.String(), 64)
			y, _ := strconv.ParseFloat(vb.String(), 64)

			if x == y {
				return compareTiedIDs(va.String(), vb.String())
			}

			return cmp.Compare(x, y)
		case numeric && va.CanInt():
			// float64 holds 53 bits: compare integers as integers.
			return cmp.Compare(va.Int(), vb.Int())
		case numeric && va.CanUint():
			return cmp.Compare(va.Uint(), vb.Uint())
		case numeric:
			return cmp.Compare(number(va), number(vb))
		case kind == Bool:
			return cmp.Compare(btoi(va.Bool()), btoi(vb.Bool()))
		case kind == Time:
			x, _ := reflect.TypeAssert[time.Time](va)
			y, _ := reflect.TypeAssert[time.Time](vb)

			return x.Compare(y)
		case kind == Version:
			x, _ := versionOf(va.String())
			y, _ := versionOf(vb.String())

			return compareVersions(x, y)
		}

		return strings.Compare(c.cell(a, now, false), c.cell(b, now, false))
	}

	slices.SortStableFunc(rows, func(a, b R) int {
		na, nb := none(a), none(b)

		switch {
		case na || nb:
			return cmp.Compare(btoi(na), btoi(nb))
		case reverse:
			return by(b, a)
		}

		return by(a, b)
	})
}

// Distinct IDs and thresholds can round to the same float64, or to zero.
// They compare by their exact value instead, in decimal or hexadecimal,
// with exponents beyond what float64 or big.Float hold.
func compareTiedIDs(a, b string) int {
	x, okX := exactOf(a)
	y, okY := exactOf(b)

	if !okX || !okY {
		return strings.Compare(a, b)
	}

	if x.base != y.base && x.sign == y.sign && x.sign != 0 {
		// Four bits per input digit hold a decimal and a binary number apart,
		// where big.Float holds their exponents.
		precision := uint(64 + 4*max(len(a), len(b)))
		fx, _, errX := big.ParseFloat(a, 0, precision, big.ToNearestEven)
		fy, _, errY := big.ParseFloat(b, 0, precision, big.ToNearestEven)

		if errX == nil && errY == nil {
			return fx.Cmp(fy)
		}
	}

	return x.cmp(y)
}

// exact is a number as written: sign × 0.digits × base^exp, the digits in
// base 10 or 2 with no leading or trailing zero, empty for zero.
type exact struct {
	sign   int
	base   int
	digits string
	exp    *big.Int
}

// exactOf reads s in either spelling strconv.ParseFloat takes for a finite
// number; false for any other.
func exactOf(s string) (exact, bool) {
	x := exact{sign: 1, base: 10, exp: new(big.Int)}

	s = strings.ToLower(strings.ReplaceAll(s, "_", ""))
	if s != "" && (s[0] == '+' || s[0] == '-') {
		if s[0] == '-' {
			x.sign = -1
		}

		s = s[1:]
	}

	marker, set, width := "e", "0123456789", 1

	if hex, ok := strings.CutPrefix(s, "0x"); ok {
		s, marker, set, width, x.base = hex, "p", "0123456789abcdef", 4, 2
	}

	mantissa, e, ok := strings.Cut(s, marker)
	if ok {
		if _, ok := x.exp.SetString(e, 10); !ok {
			return x, false
		}
	}

	whole, frac, _ := strings.Cut(mantissa, ".")

	digits := whole + frac
	if digits == "" || strings.Trim(digits, set) != "" {
		return x, false
	}

	// A hexadecimal digit is four binary digits.
	if x.base == 2 {
		var bits strings.Builder

		for _, r := range digits {
			n, _ := strconv.ParseUint(string(r), 16, 8)
			fmt.Fprintf(&bits, "%04b", n)
		}

		digits = bits.String()
	}

	trimmed := strings.TrimLeft(digits, "0")
	point := width*len(whole) - (len(digits) - len(trimmed))

	x.digits = strings.TrimRight(trimmed, "0")
	if x.digits == "" {
		x.sign = 0

		return x, true
	}

	x.exp.Add(x.exp, big.NewInt(int64(point)))

	return x, true
}

func (x exact) cmp(y exact) int {
	if x.sign != y.sign || x.sign == 0 {
		return cmp.Compare(x.sign, y.sign)
	}

	if x.base != y.base {
		return x.sign * x.log2().Cmp(y.log2())
	}

	c := x.exp.Cmp(y.exp)
	if c == 0 {
		c = strings.Compare(x.digits, y.digits)
	}

	return x.sign * c
}

// log2 is log2 of |x|, to order a decimal against a binary number beyond
// big.Float's exponents. shortcut: it works at 200 bits with a float64
// mantissa, so two numbers whose log2 differ by less than its rounding
// compare as equal. That rounding grows with the exponent: the larger the
// exponent, the farther apart a tie can be (TestIDMixedBaseBound holds
// examples). A real fix needs log2(10) to as many bits as the exponent has.
func (x exact) log2() *big.Float {
	const prec = 200

	m, _, _ := big.ParseFloat("0."+x.digits, 10, prec, big.ToNearestEven)
	if x.base == 2 {
		m, _, _ = big.ParseFloat("0b0."+x.digits, 0, prec, big.ToNearestEven)
	}

	mant := new(big.Float).SetPrec(prec)
	e := m.MantExp(mant)
	f, _ := mant.Float64()

	l := new(big.Float).SetPrec(prec).SetInt(x.exp)
	if x.base == 10 {
		log2of10, _, _ := big.ParseFloat(
			"3.3219280948873623478703194294893901758648313930245806120547563958159347766",
			10,
			prec,
			big.ToNearestEven,
		)
		l.Mul(l, log2of10)
	}

	l.Add(l, new(big.Float).SetPrec(prec).SetInt64(int64(e)))

	return l.Add(l, new(big.Float).SetPrec(prec).SetFloat64(math.Log2(f)))
}

func btoi(b bool) int {
	if b {
		return 1
	}

	return 0
}

// number is a numeric field as a float.
func number(v reflect.Value) float64 {
	switch {
	case v.CanInt():
		return float64(v.Int())
	case v.CanUint():
		return float64(v.Uint())
	case v.CanFloat():
		return v.Float()
	}

	return 0
}

// items are the entries of a list field as text: a reference to an entity
// is its name.
func items(v reflect.Value) []string {
	out := make([]string, 0, v.Len())

	for i := range v.Len() {
		e := v.Index(i)
		if name, ok := field(e, "name"); ok && e.Kind() == reflect.Struct {
			out = append(out, name.String())

			continue
		}

		out = append(out, fmt.Sprint(e.Interface()))
	}

	return out
}

// versionOf is the numbers of a Tailscale version: 1.82.5 of
// 1.82.5-tf0f4a2a8d-g7d0d5a7d3, whose suffix names a build, not an older
// release as it would in semver. false for a text that starts with no
// number.
func versionOf(s string) ([]int, bool) {
	s = strings.TrimPrefix(s, "v")
	if end := strings.IndexFunc(
		s,
		func(r rune) bool { return r != '.' && (r < '0' || r > '9') },
	); end >= 0 {
		s = s[:end]
	}

	var out []int

	for part := range strings.SplitSeq(s, ".") {
		n, err := strconv.Atoi(part)
		if err != nil {
			return nil, false
		}

		out = append(out, n)
	}

	return out, true
}

// compareVersions compares by number, a missing number being 0, so 1.80
// equals 1.80.0.
func compareVersions(a, b []int) int {
	for i := range max(len(a), len(b)) {
		var x, y int
		if i < len(a) {
			x = a[i]
		}

		if i < len(b) {
			y = b[i]
		}

		if c := cmp.Compare(x, y); c != 0 {
			return c
		}
	}

	return 0
}

// article is how a sentence says what a column holds.
func article(k Kind) string {
	switch k { //nolint:exhaustive // the others take a or an
	case Text:
		return "holds text"
	case ID:
		return "is an ID"
	case Owner:
		return "is an owner"
	}

	return "is a " + string(k)
}

// ops names the operators of a kind: "=", "= and :", "=, < and >".
func ops(s string) string {
	words := strings.Split(s, "")
	if len(words) == 1 {
		return words[0]
	}

	return strings.Join(words[:len(words)-1], ", ") + " and " + words[len(words)-1]
}

// ReadTime reads a time value as every flag of the CLI does: a duration
// from now (30m, 24h, 90d, 2w, 1d12h), a timestamp in RFC 3339, or a date,
// which is midnight UTC. A duration is read by the parser of the config
// file; the CLI refuses on top of it a number without a unit, such as 0,
// and a negative duration.
func ReadTime(s string) (time.Duration, time.Time, bool, error) {
	t, err := time.Parse(time.RFC3339, s)
	if err == nil && strictTime(s) {
		return 0, t, false, nil
	}

	t, err = time.Parse(time.DateOnly, s)
	if err == nil {
		return 0, t, false, nil
	}

	_, err = strconv.ParseFloat(s, 64)
	if err == nil {
		return 0, time.Time{}, false, errNoUnit
	}

	d, ok := duration.Parse(s)
	if !ok {
		// A duration the parser takes once its digits are zeros is in its
		// form, in any unit and with a fraction, and too long for it; a
		// date has no such limit.
		zeros := strings.Map(func(r rune) rune {
			if r >= '0' && r <= '9' {
				return '0'
			}

			return r
		}, s)

		_, zok := duration.Parse(zeros)
		if zok && !strings.HasPrefix(s, "-") {
			return 0, time.Time{}, false, ErrTooLong
		}

		return 0, time.Time{}, false, errNotDuration
	}

	if d < 0 {
		return 0, time.Time{}, false, errNegative
	}

	return d, time.Time{}, true, nil
}

// strictTime: time.Parse takes more than RFC 3339 does, a one-digit hour,
// a comma before the fraction and an offset beyond 23:59, which moves the
// date.
func strictTime(s string) bool {
	// upTo: two digits, at most top.
	upTo := func(s, top string) bool {
		return len(s) == 2 && strings.Trim(s, "0123456789") == "" && s <= top
	}

	if len(s) < 20 || !upTo(s[11:13], "23") {
		return false
	}

	zone := s[19:]
	if frac, ok := strings.CutPrefix(zone, "."); ok {
		zone = strings.TrimLeft(frac, "0123456789")
		if len(zone) == len(frac) {
			return false
		}
	}

	return zone == "Z" || len(zone) == 6 && (zone[0] == '+' || zone[0] == '-') &&
		upTo(zone[1:3], "23") && zone[3] == ':' && upTo(zone[4:6], "59")
}

var (
	errNoUnit      = errors.New("a duration needs a unit")
	errNotDuration = errors.New("it is not a duration")
	errNegative    = errors.New("a duration cannot be negative")
	// ErrTooLong is a duration longer than the parser holds, some 292 years.
	ErrTooLong = errors.New(
		"a duration from now is at most 292y; a later time is written as a date, such as 2999-08-27",
	)
)

// Closest is the name nearest to word, within two edits, for "Did you
// mean"; "" when none is that near.
func Closest(word string, names []string) string {
	best, dist := "", 3

	for _, n := range names {
		if d := distance(word, n); d < dist {
			best, dist = n, d
		}
	}

	return best
}

// distance is the Levenshtein distance of a and b. No implementation is
// exported in the module graph (cobra has one, unexported), and
// these lines cost less than a dependency to pin, vet and bump.
func distance(a, b string) int {
	prev := make([]int, len(b)+1)
	for j := range prev {
		prev[j] = j
	}

	for i := range len(a) {
		cur := make([]int, len(b)+1)
		cur[0] = i + 1

		for j := range len(b) {
			cost := 1
			if a[i] == b[j] {
				cost = 0
			}

			cur[j+1] = min(prev[j+1]+1, cur[j]+1, prev[j]+cost)
		}

		prev = cur
	}

	return prev[len(b)]
}
