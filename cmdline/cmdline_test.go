package cmdline

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os/exec"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

// The rule IDs in this file are those of rules-typed.md.

var (
	errWantLevel = errors.New("want L and a number")
	errNoColor   = errors.New("no color")
	errNoPeer    = errors.New("no peer")
	errWantYesNo = errors.New("want yes or no")
)

// level reads itself (Y2).
type level int

func (l *level) UnmarshalText(b []byte) error {
	n, err := strconv.Atoi(strings.TrimPrefix(string(b), "L"))
	if err != nil || !strings.HasPrefix(string(b), "L") {
		return errWantLevel
	}

	*l = level(n)

	return nil
}

// upper has a method and gets a Reader too; the Reader wins (Y3).
type upper string

func (u *upper) UnmarshalText(
	b []byte,
) error {
	*u = upper("method:" + string(b))
	return nil
}

// color reads itself and offers its words on Tab (T19).
type color string

func (c *color) UnmarshalText(b []byte) error {
	if !slices.Contains([]string{"red", "green", "blue"}, string(b)) {
		return errNoColor
	}

	*c = color(b)

	return nil
}

func (color) Complete(_ *Line, prefix string) ([]string, Directive) {
	return Words(prefix, "red\tWarm", "green", "blue"), NoFiles
}

// echo shows what a Completer is handed (T14); its method is on the pointer.
type echo string

func (e *echo) UnmarshalText(b []byte) error { *e = echo(b); return nil }

func (*echo) Complete(l *Line, prefix string) ([]string, Directive) {
	_, filled := Get[common](l)

	return []string{
		fmt.Sprintf(
			"at=%s;flags=%v;args=%q;prefix=%q;filled=%v",
			strings.Join(l.Command.Path, "/"),
			l.Flags,
			l.Args,
			prefix,
			filled,
		),
	}, NoFiles | NoSpace
}

// peer is looked up late (N1).
type peer struct {
	ID   int
	Name string
}

type lookups struct {
	mu    sync.Mutex
	calls []string
}

type lookupKey struct{}

func findPeer(ctx context.Context, word string) (peer, error) {
	if l, ok := ctx.Value(lookupKey{}).(*lookups); ok {
		l.mu.Lock()
		l.calls = append(l.calls, word)
		l.mu.Unlock()
	}

	id, err := strconv.Atoi(word)
	if err != nil {
		return peer{}, fmt.Errorf("%w %q", errNoPeer, word)
	}

	return peer{id, "peer" + word}, nil
}

type setIn struct {
	Peer   peer            `arg:"peer"    help:"The peer to change"`
	Routes []netip.Prefix  `arg:"routes"`
	File   Opt[Path]       `arg:"file"`
	Name   Opt[string]     `flag:"name"   help:"New name"           short:"n"`
	Count  int             `default:"3"   flag:"count"`
	Ratio  float64         `flag:"ratio"`
	Size   uint8           `flag:"size"`
	Wait   time.Duration   `default:"1m"  flag:"wait"               help:"How long to wait"`
	Level  level           `flag:"level"`
	Upper  upper           `flag:"upper"`
	Colors []color         `flag:"colors" help:"Colors to use"`
	Tag    Repeat[string]  `flag:"tag"`
	Rule   Repeat[[]color] `flag:"rule"`
	Force  bool            `flag:"force"`
	Dry    Opt[bool]       `flag:"dry"`
	Others []peer          `flag:"others"`
	Owner  Opt[peer]       `flag:"owner"`
	Note   echo            `flag:"note"`
}

type listIn struct {
	Which Opt[color] `arg:"which"`
}

type (
	common struct {
		Help   bool `flag:"help"   help:"Show help"   short:"h"`
		Config Path `flag:"config" help:"Config file" short:"c"`
	}
	rootOnly struct {
		Version bool `flag:"version"`
	}
	verbose struct {
		Verbose Repeat[bool] `flag:"verbose" short:"v"`
	}
)

type ran struct {
	mu sync.Mutex
	in any
}

type ranKey struct{}

func record[In any](ctx context.Context, in In) error {
	if r, ok := ctx.Value(ranKey{}).(*ran); ok {
		r.mu.Lock()
		r.in = in
		r.mu.Unlock()
	}

	return nil
}

func root() Node {
	return Group{
		Name:  "prog",
		Help:  "A program",
		Flags: []any{common{}, rootOnly{}},
		Commands: []Node{
			Group{
				Name:  "peers",
				Help:  "Manage peers",
				Flags: []any{common{}},
				Commands: []Node{
					Command[setIn]{
						Name:    "set",
						Aliases: []string{"change"},
						Help:    "Change a peer",
						Flags:   []any{common{}},
						Run:     record[setIn],
					},
					Command[listIn]{
						Name:    "list",
						Aliases: []string{"ls"},
						Help:    "List peers",
						Flags:   []any{common{}, verbose{}},
						Run:     record[listIn],
					},
				},
			},
			Command[struct{}]{
				Name: "version",
				Help: "Print the version",
				Run:  record[struct{}],
			},
		},
	}
}

func opts() []Option {
	return []Option{
		Reader(time.ParseDuration),
		Reader(func(s string) (upper, error) { return upper(strings.ToUpper(s)), nil }),
		LateReader(findPeer),
	}
}

var testTree = sync.OnceValue(func() *Tree {
	t, err := New(root(), opts()...)
	if err != nil {
		panic(err)
	}

	return t
})

func argv(line string) []string {
	if line == "" {
		return nil
	}

	w := strings.Split(line, " ")
	for i := range w {
		if w[i] == "''" {
			w[i] = ""
		}
	}

	return w
}

// errText prints a mistake as its fields.
func errText(err error) string {
	var e *UsageError
	if !errors.As(err, &e) {
		return fmt.Sprint(err)
	}

	kind := [...]string{"", "unknown-command", "unknown-flag", "missing-value", "repeated", "bad-value", "arg-count", "unresolved"}[e.Kind]

	s := fmt.Sprintf(
		"%s [%s] @%d word=%q",
		kind,
		strings.Join(e.Path, " "),
		e.At,
		e.Word,
	)
	if e.Flag != "" {
		s += " flag=" + e.Flag
	}

	if e.Arg != "" {
		s += " arg=" + e.Arg
	}

	if e.Err != nil {
		s += fmt.Sprintf(" value=%q err=%v", e.Value, e.Err)
	}

	return s
}

// run parses and runs a line and returns the input struct the command got.
func run(t *testing.T, line string) (any, *lookups, error) {
	t.Helper()

	l, err := testTree().Parse(argv(line))
	if err != nil {
		return nil, nil, err
	}

	r, look := &ran{}, &lookups{}
	ctx := context.WithValue(
		context.WithValue(context.Background(), ranKey{}, r),
		lookupKey{},
		look,
	)
	err = l.Run(ctx)

	return r.in, look, err
}

// TestValues: how each type of field is read (rules Y1–Y12).
func TestValues(t *testing.T) {
	in, _, err := run(
		t,
		"peers set 7 10.0.0.0/8,fd00::/8 --name= --count=-12 --ratio 1.5 --size 255 --wait 90s --level L4 --upper abc --colors red,blue --tag a,b --tag '' --rule red --rule green,blue --force --dry=false",
	)
	if err != nil {
		t.Fatal(err)
	}

	got := in.(setIn) //nolint:forcetypeassert // a wrong type fails the test
	name, given := got.Name.Get()
	dry, dryGiven := got.Dry.Get()

	want := setIn{
		Peer: peer{
			7,
			"peer7",
		},
		Routes: []netip.Prefix{
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("fd00::/8"),
		},
		Name: Some(
			"",
		),
		Count: -12,
		Ratio: 1.5,
		Size:  255,
		Wait:  90 * time.Second,
		Level: 4,
		Upper: "ABC",
		Colors: []color{
			"red",
			"blue",
		},
		Tag:   Repeat[string]{"a,b", ""},
		Rule:  Repeat[[]color]{{"red"}, {"green", "blue"}},
		Force: true,
		Dry:   Some(false),
	}
	if !reflect.DeepEqual(got, want) || name != "" || !given || dry || !dryGiven {
		t.Errorf("Y1–Y10:\n got %+v\nwant %+v", got, want)
	}

	// Y7, Y9: nothing given: Opt says so, the defaults are read, the rest is zero.
	in, _, err = run(t, "peers set 7 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}

	got = in.(setIn) //nolint:forcetypeassert // a wrong type fails the test
	if _, given := got.Name.Get(); given || got.Count != 3 || got.Wait != time.Minute ||
		got.Force ||
		got.Tag != nil ||
		got.Colors != nil {
		t.Errorf("Y7 Y9: %+v", got)
	}

	if _, given := got.File.Get(); given {
		t.Error("Y7: an optional argument that is left out is not given")
	}

	for _, tc := range []struct{ id, line, want string }{
		{"Y1", "peers set 7 ::/0 --count 1.5", `bad-value [peers set] @4 word="--count" flag=count value="1.5" err=strconv.ParseInt: parsing "1.5": invalid syntax`},
		{"Y1", "peers set 7 ::/0 --count 0x10", `bad-value [peers set] @4 word="--count" flag=count value="0x10" err=strconv.ParseInt: parsing "0x10": invalid syntax`},
		{"Y1", "peers set 7 ::/0 --count=", `bad-value [peers set] @4 word="--count" flag=count value="" err=strconv.ParseInt: parsing "": invalid syntax`},
		{"Y1", "peers set 7 ::/0 --size 256", `bad-value [peers set] @4 word="--size" flag=size value="256" err=strconv.ParseUint: parsing "256": value out of range`},
		{"Y1", "peers set 7 ::/0 --size -1", `bad-value [peers set] @4 word="--size" flag=size value="-1" err=strconv.ParseUint: parsing "-1": invalid syntax`},
		{"Y1", "peers set 7 ::/0 --ratio x", `bad-value [peers set] @4 word="--ratio" flag=ratio value="x" err=strconv.ParseFloat: parsing "x": invalid syntax`},
		{"Y2", "peers set 7 ::/0 --level 4", `bad-value [peers set] @4 word="--level" flag=level value="4" err=want L and a number`},
		{"Y3", "peers set 7 ::/0 --wait 5", `bad-value [peers set] @4 word="--wait" flag=wait value="5" err=time: missing unit in duration "5"`},
		{"Y5", "peers set 7 10.0.0.0/8,x", `bad-value [peers set] @3 word="10.0.0.0/8,x" arg=routes value="10.0.0.0/8,x" err=netip.ParsePrefix("x"): no '/'`},
		{"Y6", "peers set 7 ''", `bad-value [peers set] @3 word="" arg=routes value="" err=the list is empty`},
		{"Y6", "peers set 7 ::/0 --colors=", `bad-value [peers set] @4 word="--colors" flag=colors value="" err=the list is empty`},
		{"Y6", "peers set 7 ::/0 --colors red,,blue", `bad-value [peers set] @4 word="--colors" flag=colors value="red,,blue" err=the list has an empty item`},
		{"Y6", "peers set 7 ::/0 --colors red,", `bad-value [peers set] @4 word="--colors" flag=colors value="red," err=the list has an empty item`},
		{"Y6", "peers set 7 ::/0 --rule red --rule ''", `bad-value [peers set] @6 word="--rule" flag=rule value="" err=the list is empty`},
		{"Y6", "peers set 7 ::/0 --others 1,,2", `bad-value [peers set] @4 word="--others" flag=others value="1,,2" err=the list has an empty item`},
		{"Y10", "peers set 7 ::/0 --force=1", `bad-value [peers set] @4 word="--force" flag=force value="1" err=not true or false`},
		{"Y10", "peers set 7 ::/0 --force=TRUE", `bad-value [peers set] @4 word="--force" flag=force value="TRUE" err=not true or false`},
		{"Y10", "peers set 7 ::/0 --force=", `bad-value [peers set] @4 word="--force" flag=force value="" err=not true or false`},
		{"Y10", "peers set 7 ::/0 --dry=t", `bad-value [peers set] @4 word="--dry" flag=dry value="t" err=not true or false`},
		{"Y10", "-h=yes", `bad-value [] @0 word="-h" flag=help value="yes" err=not true or false`},
		{"Y10", "peers set 7 ::/0 f --force true", `arg-count [peers set] @7 word=""`}, // a bool takes no value word: "true" is a fourth argument
	} {
		_, _, err := run(t, tc.line)
		if errText(err) != tc.want {
			t.Errorf("%s %q:\n got %s\nwant %s", tc.id, tc.line, errText(err), tc.want)
		}
	}
	// Y10: Repeat[bool] counts; Opt[bool] given bare is true.
	l, err := testTree().Parse(argv("peers list -v --verbose=false -v"))
	if v, _ := Get[verbose](
		l,
	); err != nil ||
		!slices.Equal(v.Verbose, []bool{true, false, true}) {
		t.Errorf("Y8 Y10: %v %v", v, err)
	}
	// Y11: a value reaches its reader byte for byte.
	l, err = testTree().Parse([]string{"peers", "set", "7", "::/0", "--tag", " x\t", "--tag=\xff", "-n", "--"})
	if in, _ := Get[setIn](
		l,
	); err != nil || !slices.Equal(in.Tag, []string{" x\t", "\xff"}) ||
		in.Name != Some("--") {
		t.Errorf("Y11: %+v %v", in, err)
	}
	// M6: a mistake found by the library's own readers is known by its cause.
	_, _, err = run(t, "peers set 7 ::/0 --force=x")
	if !errors.Is(err, ErrBool) {
		t.Errorf("M6: errors.Is(ErrBool): %v", err)
	}
	// M6: the error of a reader comes through.
	_, _, err = run(t, "peers set 7 ::/0 --count x")
	if _, ok := errors.AsType[*strconv.NumError](err); !ok {
		t.Errorf("M6: the reader's error is wrapped: %v", err)
	}
}

// TestLate: late readers (rules N1–N4).
func TestLate(t *testing.T) {
	in, look, err := run(t, "peers set --owner 3 9 --others 5,6 ::/0")
	if err != nil {
		t.Fatal(err)
	}

	got := in.(setIn) //nolint:forcetypeassert // a wrong type fails the test
	if o, ok := got.Owner.Get(); got.Peer.ID != 9 || !ok || o.ID != 3 ||
		len(got.Others) != 2 ||
		got.Others[1].Name != "peer6" {
		t.Errorf("N2: %+v", got)
	}

	if !slices.Equal(look.calls, []string{"3", "9", "5", "6"}) {
		t.Errorf("N2: lookups in the order typed: %v", look.calls)
	}

	// N1: Parse does not call the reader.
	l, err := testTree().Parse(argv("peers set nobody ::/0"))
	if in, ok := Get[setIn](l); err != nil || !ok || in.Peer != (peer{}) {
		t.Errorf("N1: %+v %v", in, err)
	}
	// N3: the first that fails stops the run, with its place on the line.
	r, look := &ran{}, &lookups{}

	err = l.Run(
		context.WithValue(
			context.WithValue(context.Background(), ranKey{}, r),
			lookupKey{},
			look,
		),
	)
	if want := `unresolved [peers set] @2 word="nobody" arg=peer value="nobody" err=no peer "nobody"`; errText(
		err,
	) != want ||
		r.in != nil {
		t.Errorf("N3:\n got %s\nwant %s", errText(err), want)
	}

	_, look, err = run(t, "peers set 1 ::/0 --others=2,x,3 --owner y")
	if want := `unresolved [peers set] @4 word="--others" flag=others value="2,x,3" err=no peer "x"`; errText(
		err,
	) != want ||
		!slices.Equal(look.calls, []string{"1", "2", "x"}) {
		t.Errorf("N3:\n got %s %v\nwant %s", errText(err), look.calls, want)
	}
	// N4: with a mistake on the line no reader runs, and Run gives the mistake back.
	l, err = testTree().Parse(argv("peers set nobody ::/0 --bogus"))

	look = &lookups{}

	err2 := l.Run(context.WithValue(context.Background(), lookupKey{}, look))
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err == nil || err2 != err || look.calls != nil {
		t.Errorf("N4: %v / %v, lookups %v", err, err2, look.calls)
	}
}

// TestMistakes: the kinds, their fields and their places (rules U1, R2, X1–X3, M6, A1–A4).
func TestMistakes(t *testing.T) {
	for _, tc := range []struct{ id, line, want string }{
		{"U1", "peer", `unknown-command [] @0 word="peer"`},
		{"U1", "peers set 7 ::/0 --bogus=1", `unknown-flag [peers set] @4 word="--bogus"`},
		{"U1", "peers set 7 ::/0 -n", `missing-value [peers set] @4 word="-n" flag=name`},
		{"U1", "--version peers list", `unknown-flag [peers list] @0 word="--version"`},
		{"R2", "peers set 7 ::/0 --name x -n=y", `repeated [peers set] @6 word="-n" flag=name`},
		{"R2", "-c a peers list -c b", `repeated [peers list] @4 word="-c" flag=config`},
		{"R2", "peers set 7 ::/0 --force --force=false", `repeated [peers set] @5 word="--force" flag=force`},
		{"R2", "peers set 7 ::/0 --colors red --colors blue", `repeated [peers set] @6 word="--colors" flag=colors`},
		{"R2", "-c a -c b peer", `repeated [] @2 word="-c" flag=config`},
		{"X2", "peers list mauve", `bad-value [peers list] @2 word="mauve" arg=which value="mauve" err=no color`},
		{"X2", "peers set 7 -- -x", `bad-value [peers set] @4 word="-x" arg=routes value="-x" err=netip.ParsePrefix("-x"): no '/'`},
		{"X1", "peers set 7 ::/0 --count x --bogus", `bad-value [peers set] @4 word="--count" flag=count value="x" err=strconv.ParseInt: parsing "x": invalid syntax`},
		{"X1", "peers set 7 ::/0 --bogus --count x", `unknown-flag [peers set] @4 word="--bogus"`},
		{"X1", "peers set 7 x --count y", `bad-value [peers set] @3 word="x" arg=routes value="x" err=netip.ParsePrefix("x"): no '/'`},
		{"X1", "peers set --count y 7 x", `bad-value [peers set] @2 word="--count" flag=count value="y" err=strconv.ParseInt: parsing "y": invalid syntax`},
		{"X1", "-h=x peers lst", `bad-value [peers] @0 word="-h" flag=help value="x" err=not true or false`},
		{"X1", "peers set 7 ::/0 --name x --name y --wait", `repeated [peers set] @6 word="--name" flag=name`},
		{"X3", "peers set 7 ::/0 --force --force=x", `repeated [peers set] @5 word="--force" flag=force`},
		{"X3", "peers set 7 ::/0 --name x --name", `missing-value [peers set] @6 word="--name" flag=name`}, // the reader stops at the last word and never hands it over
		{"A2", "peers set 7", `arg-count [peers set] @3 word=""`},
		{"A2", "peers set 7 ::/0 f extra", `arg-count [peers set] @6 word=""`},
		{"A2", "version x", `arg-count [version] @2 word=""`},
		{"A2", "peers list red blue", `arg-count [peers list] @4 word=""`},
		{"A3", "peers set 7 ::/0 f extra --count x", `bad-value [peers set] @6 word="--count" flag=count value="x" err=strconv.ParseInt: parsing "x": invalid syntax`},
		{"A3", "peers set --bogus", `unknown-flag [peers set] @2 word="--bogus"`},
		{"A3", "peers set 7 x f extra", `bad-value [peers set] @3 word="x" arg=routes value="x" err=netip.ParsePrefix("x"): no '/'`},
	} {
		l, err := testTree().Parse(argv(tc.line))
		if errText(err) != tc.want {
			t.Errorf("%s %q:\n got %s\nwant %s", tc.id, tc.line, errText(err), tc.want)
		}

		e, _ := errors.AsType[*UsageError](err)
		if e != nil && e.Kind != ArgCount {
			if _, ok := Get[common](l); ok {
				t.Errorf("G2 %q: a struct is readable next to a mistake", tc.line)
			}
		}
	}
	// A1: arguments fill the arg fields in order, flags anywhere between.
	in, _, err := run(t, "peers set --force 7 -n x 10.0.0.0/8 -- -f")
	if got, _ := in.(setIn); err != nil || got.Peer.ID != 7 || len(got.Routes) != 1 ||
		got.File != Some(Path("-f")) {
		t.Errorf("A1: %+v %v", in, err)
	}
	// A4: next to a wrong count the flags are filled, so a caller sees --help.
	l, err := testTree().Parse(argv("peers set -h -c /x"))
	if c, ok := Get[common](
		l,
	); errText(err) != `arg-count [peers set] @5 word=""` || !ok || !c.Help ||
		c.Config != "/x" {
		t.Errorf("A4: %+v %v %v", c, ok, err)
	}

	err2 := l.Run(context.Background())
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err2 != err {
		t.Errorf("G5: Run gives the mistake back: %v", err2)
	}
	// M6: the default texts.
	for line, want := range map[string]string{
		"peer":                           `unknown command "peer"`,
		"peers lst":                      `unknown command "lst" for "peers"`,
		"peers list --x":                 `unknown flag --x for "peers list"`,
		"peers list -c":                  `flag -c needs a value`,
		"peers list -c a --config b":     `flag --config is given more than once`,
		"peers list mauve":               `argument which: "mauve": no color`,
		"peers set 7 ::/0 --level 9":     `flag --level: "9": want L and a number`,
		"peers list red blue":            `wrong number of arguments for "peers list"`,
		"peers set 7 ::/0 --force=maybe": `flag --force: "maybe": not true or false`,
	} {
		_, err := testTree().Parse(argv(line))
		if err == nil || err.Error() != want {
			t.Errorf("M6 %q: got %v, want %s", line, err, want)
		}
	}
}

// TestStructs: which structs a line fills (rules G1–G5).
func TestStructs(t *testing.T) {
	tree := testTree()
	// G1, G4: a flag before the subcommand lands in the struct of the command reached.
	l, err := tree.Parse(argv("-c /x peers -h list red"))
	c, ok := Get[common](l)

	in, ok2 := Get[listIn](l)
	if err != nil || !ok || !ok2 || c.Config != "/x" || !c.Help ||
		in.Which != Some(color("red")) {
		t.Errorf("G1 G4: %+v %+v %v", c, in, err)
	}

	if _, ok := Get[rootOnly](l); ok {
		t.Error("G2: peers list has no rootOnly")
	}

	if _, ok := Get[setIn](l); ok {
		t.Error("G2: peers list has no setIn")
	}

	if want := []Given{
		{"config", "/x", 0},
		{"help", "true", 3},
	}; !slices.Equal(l.Flags, want) || !slices.Equal(l.Args, []string{"red"}) ||
		!slices.Equal(l.ArgAt, []int{5}) {
		t.Errorf("M2 M3: %v %v %v", l.Flags, l.Args, l.ArgAt)
	}
	// G3: at a group, the structs of the group and of the groups above it.
	l, err = tree.Parse(argv("--version -c /y peers"))
	c, ok = Get[common](l)

	v, ok2 := Get[rootOnly](l)
	if err != nil || !ok || !ok2 || c.Config != "/y" || !v.Version ||
		l.Command.Name != "peers" {
		t.Errorf("G3: %+v %+v %v", c, v, err)
	}
	// M5: next to a repeat or a bad value the Line holds all the reader read,
	// also what stands after the mistake; the reader's own mistake ends it.
	l, err = tree.Parse(argv("peers list -c a -c b -v red"))
	if errText(err) != `repeated [peers list] @4 word="-c" flag=config` ||
		len(l.Flags) != 3 ||
		l.Flags[2] != (Given{"verbose", "true", 6}) ||
		!slices.Equal(l.Args, []string{"red"}) {
		t.Errorf("M5: %v %v %v", err, l.Flags, l.Args)
	}

	l, err = tree.Parse(argv("peers list -c a -c b -v --bogus red"))
	if errText(err) != `repeated [peers list] @4 word="-c" flag=config` ||
		len(l.Flags) != 3 ||
		l.Args != nil {
		t.Errorf("M5: %v %v %v", err, l.Flags, l.Args)
	}

	l, _ = tree.Parse(argv("--version -c /y peers"))
	// G5: a group does not run.

	err = l.Run(context.Background())
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err != ErrGroup {
		t.Errorf("G5: %v", err)
	}
	// G1: two lines share nothing.
	a, _ := tree.Parse(argv("peers list -v"))
	b, _ := tree.Parse(argv("peers list"))
	va, _ := Get[verbose](a)

	vb, _ := Get[verbose](b)
	if len(va.Verbose) != 1 || len(vb.Verbose) != 0 {
		t.Errorf("G1: %v %v", va, vb)
	}
}

// TestInfo: the tree as data (rules I1, I2).
func TestInfo(t *testing.T) {
	r := testTree().Root()

	set := r.Commands[0].Commands[0]
	if r.Name != "prog" || r.Usage != "prog" || len(r.Path) != 0 ||
		len(r.Commands) != 2 ||
		r.Commands[0].Help != "Manage peers" ||
		!slices.Equal(set.Path, []string{"peers", "set"}) ||
		!slices.Equal(set.Aliases, []string{"change"}) ||
		len(set.Commands) != 0 {
		t.Errorf("I1: %+v", r)
	}

	if set.Usage != "prog peers set <peer> <routes> [file]" ||
		r.Commands[0].Commands[1].Usage != "prog peers list [which]" ||
		r.Commands[1].Usage != "prog version" {
		t.Errorf("I1 (D47): %q", set.Usage)
	}

	wantArgs := []Arg{
		{
			Name: "peer",
			Help: "The peer to change",
			Type: reflect.TypeFor[peer](),
			Late: true,
		},
		{Name: "routes", Type: reflect.TypeFor[netip.Prefix](), List: true},
		{Name: "file", Type: reflect.TypeFor[Path](), Optional: true},
	}
	if !reflect.DeepEqual(set.Args, wantArgs) {
		t.Errorf("I2: args %+v", set.Args)
	}

	flags := map[string]Flag{}

	order := make([]string, 0, len(set.Flags))

	for _, f := range set.Flags {
		flags[f.Name] = f
		order = append(order, f.Name)
	}

	if want := "name count ratio size wait level upper colors tag rule force dry others owner note help config"; strings.Join(
		order,
		" ",
	) != want {
		t.Errorf("I1: flags in field order, the input struct first: %v", order)
	}

	for name, want := range map[string]Flag{
		"name":   {Name: "name", Short: "n", Help: "New name", Type: reflect.TypeFor[string](), Optional: true},
		"wait":   {Name: "wait", Help: "How long to wait", Type: reflect.TypeFor[time.Duration](), Default: "1m"},
		"colors": {Name: "colors", Help: "Colors to use", Type: reflect.TypeFor[color](), List: true},
		"rule":   {Name: "rule", Type: reflect.TypeFor[color](), List: true, Repeat: true},
		"tag":    {Name: "tag", Type: reflect.TypeFor[string](), Repeat: true},
		"force":  {Name: "force", Type: reflect.TypeFor[bool](), Bool: true},
		"dry":    {Name: "dry", Type: reflect.TypeFor[bool](), Bool: true, Optional: true},
		"others": {Name: "others", Type: reflect.TypeFor[peer](), List: true, Late: true},
		"owner":  {Name: "owner", Type: reflect.TypeFor[peer](), Optional: true, Late: true},
		"help":   {Name: "help", Short: "h", Help: "Show help", Type: reflect.TypeFor[bool](), Bool: true},
	} {
		if flags[name] != want {
			t.Errorf("I2 --%s:\n got %+v\nwant %+v", name, flags[name], want)
		}
	}

	if len(r.Flags) != 3 || len(r.Commands[0].Flags) != 2 {
		t.Errorf(
			"I1: a group lists its own flags: %d %d",
			len(r.Flags),
			len(r.Commands[0].Flags),
		)
	}
}

// TestNew: what New refuses (rules K1–K18), and that it names every problem.
func TestNew(t *testing.T) {
	leaf := func(n Node) Node { return Group{Name: "prog", Commands: []Node{n}} }

	type (
		noTag struct{ X string }
		both  struct {
			X string `arg:"x" flag:"x"`
		}
		unknown struct {
			X string `flag:"x" hlep:"typo"`
		}
		private struct {
			x string `flag:"x"` //nolint:unused // K: New refuses an unexported field
		}
		noReader struct {
			X time.Month `flag:"x"`
		}
		noReader2 struct {
			X []chan int `flag:"x"`
		}
		nested struct {
			X Opt[Repeat[string]] `flag:"x"`
		}
		nested2 struct {
			X []Opt[string] `flag:"x"`
		}
		ptrOpt struct {
			X *Opt[int] `flag:"x"`
		}
		ptrRepeat struct {
			X *Repeat[int] `flag:"x"`
		}
		short2 struct {
			X string `flag:"x" short:"xy"`
		}
		shortArg struct {
			X string `arg:"x" short:"x"`
		}
		defArg struct {
			X string `arg:"x" default:"1"`
		}
		defOpt struct {
			X Opt[string] `default:"1" flag:"x"`
		}
		defLate struct {
			X peer `default:"1" flag:"x"`
		}
		defBad struct {
			X int `default:"one" flag:"x"`
		}
		repArg struct {
			X Repeat[string] `arg:"x"`
		}
		argHelp struct {
			X string `arg:"x" help:"one\ntwo"`
		}
		argName struct {
			X string `arg:"a b"`
		}
		argTwice struct {
			X string `arg:"x"`
			Y string `arg:"x"`
		}
		optFirst struct {
			X Opt[string] `arg:"x"`
			Y string      `arg:"y"`
		}
		flagTwice struct {
			X string `flag:"x"`
			Y string `flag:"x"`
		}
		argFlags struct {
			X string `arg:"x"`
		}
		other struct {
			Help string `flag:"help" short:"h"`
		}
		other2 struct {
			Help bool `flag:"help" short:"h"`
		}
		ok struct {
			X string `flag:"x"`
		}
		Outer struct {
			Y string `flag:"y"`
		}
		inner struct {
			Y string `flag:"y"`
		}
		embedded struct {
			Outer

			Z string `flag:"z"`
		}
		embedded2 struct{ inner }
		embedded3 struct {
			Outer `flag:"o"`
		}
	)

	nop := func(context.Context, ok) error { return nil }
	for _, tc := range []struct {
		id   string
		root Node
		opts []Option
		want string
	}{
		{"K9", leaf(Command[int]{Name: "c", Run: func(context.Context, int) error { return nil }}), nil, "prog c: the input type int is no struct"},
		{"K9", leaf(Command[ok]{Name: "c", Flags: []any{7}, Run: nop}), nil, "prog c: Flags holds int, which is no struct"},
		{"K9", leaf(Command[ok]{Name: "c", Flags: []any{&ok{}}, Run: nop}), nil, "which is no struct"},
		{"K10", leaf(Command[noTag]{Name: "c", Run: record[noTag]}), nil, "prog c: cmdline.noTag.X: has no arg or flag tag"},
		{"K10", leaf(Command[both]{Name: "c", Run: record[both]}), nil, "X: has an arg and a flag tag"},
		{"K10", leaf(Command[private]{Name: "c", Run: record[private]}), nil, "x: is not exported"},
		{"K10", leaf(Command[embedded]{Name: "c", Run: record[embedded]}), nil, "Outer: has no arg or flag tag"},
		{"K10", leaf(Command[embedded2]{Name: "c", Run: record[embedded2]}), nil, "inner: is not exported"},
		{"K12", leaf(Command[embedded3]{Name: "c", Run: record[embedded3]}), nil, "Outer: cmdline.Outer cannot be read"},
		{"K11", leaf(Command[unknown]{Name: "c", Run: record[unknown]}), nil, `X: unknown tag "hlep"`},
		{"K12", leaf(Command[noReader]{Name: "c", Run: record[noReader]}), nil, "X: time.Month cannot be read"},
		{"K12", leaf(Command[noReader2]{Name: "c", Run: record[noReader2]}), nil, "X: chan int cannot be read"},
		{"K12", leaf(Command[setIn]{Name: "c", Run: record[setIn]}), nil, "Peer: cmdline.peer cannot be read"},
		{"K12", leaf(Command[nested]{Name: "c", Run: record[nested]}), nil, "Opt and Repeat do not nest"},
		{"K12", leaf(Command[nested2]{Name: "c", Run: record[nested2]}), nil, "cannot be read"},
		{"K12", leaf(Command[ptrOpt]{Name: "c", Run: record[ptrOpt]}), nil, "X: *cmdline.Opt[int] is a pointer"},
		{"K12", leaf(Command[ptrRepeat]{Name: "c", Run: record[ptrRepeat]}), nil, "X: *cmdline.Repeat[int] is a pointer"},
		{"K13", leaf(Command[short2]{Name: "c", Run: record[short2]}), nil, `short "xy" is not one letter`},
		{"K13", leaf(Command[shortArg]{Name: "c", Run: record[shortArg]}), nil, "an argument takes no short and no default"},
		{"K13", leaf(Command[defArg]{Name: "c", Run: record[defArg]}), nil, "an argument takes no short and no default"},
		{"K14", leaf(Command[defOpt]{Name: "c", Run: record[defOpt]}), nil, "an Opt or a late value takes no default"},
		{"K14", leaf(Command[defLate]{Name: "c", Run: record[defLate]}), opts(), "an Opt or a late value takes no default"},
		{"K14", leaf(Command[defBad]{Name: "c", Run: record[defBad]}), nil, `default "one": strconv.ParseInt`},
		{"K15", leaf(Command[repArg]{Name: "c", Run: record[repArg]}), nil, "an argument cannot repeat"},
		{"K15", leaf(Command[argName]{Name: "c", Run: record[argName]}), nil, `argument name "a b" cannot be shown`},
		{"K15", leaf(Command[argHelp]{Name: "c", Run: record[argHelp]}), nil, "X: help text holds a line break"},
		{"K9", leaf(Command[ok]{Name: "c", Flags: []any{nil}, Run: nop}), nil, "Flags holds <nil>, which is no struct"},
		{"K15", leaf(Command[argTwice]{Name: "c", Run: record[argTwice]}), nil, `argument "x" declared twice`},
		{"K15", leaf(Command[optFirst]{Name: "c", Run: record[optFirst]}), nil, "a needed argument after an optional one"},
		{"K15", leaf(Command[ok]{Name: "c", Flags: []any{argFlags{}}, Run: nop}), nil, "an argument outside the input struct"},
		{"K5", leaf(Command[flagTwice]{Name: "c", Run: record[flagTwice]}), nil, "prog c: flag --x declared twice"},
		{"K5", leaf(Command[ok]{Name: "c", Flags: []any{ok{}}, Run: nop}), nil, "prog c: flag --x declared twice"},
		{"K16", leaf(Command[ok]{Name: "c"}), nil, "prog c: Run is missing"},
		{"K16", leaf(Group{Name: "g"}), nil, "prog g: a group needs a command"},
		{"K16", Group{Commands: []Node{Command[ok]{Name: "c", Run: nop}}}, nil, "the root has no name"},
		{"K16", Group{Name: "prog", Commands: []Node{nil}}, nil, "prog: a command is nil"},
		{"K16", Group{Name: "prog", Commands: []Node{(*Group)(nil)}}, nil, "prog: a command is nil"},
		{"K16", Group{Name: "prog", Commands: []Node{(*Command[ok])(nil)}}, nil, "prog: a command is nil"},
		{"K17", leaf(Command[ok]{Name: "c", Run: nop}), []Option{Reader(time.ParseDuration), Reader(time.ParseDuration)}, "time.Duration has two readers"},
		{"K17", leaf(Command[ok]{Name: "c", Run: nop}), []Option{Reader(func(string) (peer, error) { return peer{}, nil }), LateReader(findPeer)}, "cmdline.peer has two readers"},
		{"K18", Group{Name: "prog", Flags: []any{other2{}}, Commands: []Node{Group{Name: "g", Flags: []any{common{}}, Commands: []Node{Command[ok]{Name: "c", Run: nop}}}}}, nil, "prog g: --help is declared by cmdline.common here and by cmdline.other2 above"},
		{"K6", Group{Name: "prog", Flags: []any{common{}}, Commands: []Node{Command[ok]{Name: "c", Flags: []any{other{}}, Run: nop}}}, nil, "prog c: --help and --help: one spelling, two flags"},
		{"K1", Group{Name: "prog", Commands: []Node{Command[ok]{Name: "c", Run: nop}, Command[ok]{Name: "d", Aliases: []string{"c"}, Run: nop}}}, nil, `prog: "c" names two commands`},
		{"K7", leaf(Command[ok]{Name: "__complete", Run: nop}), nil, "Serve's entry point"},
	} {
		tree, err := New(tc.root, tc.opts...)
		if err == nil || tree != nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: got %v, want %q", tc.id, err, tc.want)
		}
	}

	for _, tag := range []string{`flag:x`, `flag`, `flag:"x`, `flag:"x" flag:"y"`, `:"x"`} { // K11: a tag the library cannot read
		_, err := parseTag(reflect.StructTag(tag))
		if err == nil {
			t.Errorf("K11: tag `%s` was read", tag)
		}
	}

	tags, err := parseTag(`flag:"a\"b"  help:"x: y"`)
	if err != nil || tags["flag"] != `a"b` || tags["help"] != "x: y" {
		t.Errorf("K11: %v %v", tags, err)
	}

	_, err = New(nil)
	if err == nil {
		t.Error("K16: no root")
	}

	_, err = New((*Group)(nil))
	if err == nil {
		t.Error("K16: a nil *Group root")
	}
	// Every problem is named, not only the first.
	_, err = New(Group{Name: "prog", Commands: []Node{
		Command[noTag]{Name: "a", Run: record[noTag]},
		Command[unknown]{Name: "b"},
		Command[ok]{Name: "-c", Run: nop},
	}})
	for _, want := range []string{"has no arg or flag tag", `unknown tag "hlep"`, "prog b: Run is missing", `"-c" cannot be typed as a command word`} {
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("New names every problem: %q is missing in %v", want, err)
		}
	}
	// K19: one problem a line: the readers, then the structs and commands in
	// the order declared, then the names and spellings in the same order.
	_, err = New(Group{Name: "prog", Flags: []any{common{}}, Commands: []Node{
		Command[noTag]{Name: "a", Aliases: []string{"a"}, Run: record[noTag]},
		Group{
			Name:     "g",
			Flags:    []any{7},
			Commands: []Node{Command[unknown]{Name: "b"}},
		},
		Command[ok]{Name: "-c", Flags: []any{other{}}, Run: nop},
	}}, Reader(time.ParseDuration), Reader(time.ParseDuration))

	want := strings.Join([]string{
		`time.Duration has two readers`,
		`prog a: cmdline.noTag.X: has no arg or flag tag`,
		`prog g: Flags holds int, which is no struct`,
		`prog g b: cmdline.unknown.X: unknown tag "hlep"`,
		`prog g b: Run is missing`,
		`prog: "a" names two commands`,
		`prog: "-c" cannot be typed as a command word`,
		`prog -c: --help and --help: one spelling, two flags`,
	}, "\n")
	if err == nil || err.Error() != want {
		t.Errorf("K19:\n got %v\nwant %s", err, want)
	}
	// A root that runs, and pointers to the declarations, are trees too.
	one, err := New(&Command[listIn]{Name: "one", Run: record[listIn]})
	if err != nil {
		t.Fatal(err)
	}

	l, err := one.Parse([]string{"red"})
	if err != nil || l.Run(context.Background()) != nil {
		t.Errorf("a root that runs: %v", err)
	}
}

type commandAliases struct{ color }

func (commandAliases) Complete(line *Line, _ string) ([]string, Directive) {
	return line.Command.Aliases, NoFiles
}

func TestListCompletionPreservesWords(t *testing.T) {
	type in struct {
		Colors []commandAliases `flag:"colors"`
	}

	tree, err := New(
		Command[in]{
			Name:    "app",
			Aliases: []string{"red", "blue"},
			Run:     func(context.Context, in) error { return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	got, _ := tree.Complete([]string{"--colors"}, "red,")
	if !slices.Equal(got, []string{"red,red", "red,blue"}) {
		t.Fatalf("completion = %q", got)
	}

	if words := tree.Root().Aliases; !slices.Equal(words, []string{"red", "blue"}) {
		t.Fatalf("declared aliases after completion = %q", words)
	}
}

func TestSealedListSeparator(t *testing.T) {
	type input struct {
		Colors []color `flag:"colors"`
	}

	tree, err := New(
		Command[input]{
			Name: "paint",
			Run:  func(context.Context, input) error { return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	words, dir := tree.Complete([]string{"--colors"}, "red\r,")
	if len(words) != 0 || dir != NoFiles {
		t.Fatalf("completion after carriage return = %q, directive %d", words, dir)
	}
}

type fileLookup struct{ color }

func (fileLookup) Complete(_ *Line, prefix string) ([]string, Directive) {
	if prefix == "dir" {
		return []string{"fixtures"}, FilterDirs
	}

	return []string{"json"}, FilterExt
}

func TestListFileMetadata(t *testing.T) {
	type input struct {
		Files []fileLookup `flag:"files"`
	}

	tree, err := New(
		Command[input]{
			Name: "app",
			Run:  func(context.Context, input) error { return nil },
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		suffix, word string
		dir          Directive
	}{
		{"ext", "json", FilterExt},
		{"dir", "fixtures", FilterDirs},
	} {
		words, dir := tree.Complete([]string{"--files"}, "red,"+tc.suffix)
		if !slices.Equal(words, []string{tc.word}) || dir != tc.dir|NoSpace {
			t.Errorf("red,%s: got %q directive %d", tc.suffix, words, dir)
		}
	}
}

// TestTabRunsNoReader: Tab checks the items before the cursor by their
// split only; the reader may be slow or have effects (T16).
func TestTabRunsNoReader(t *testing.T) {
	type input struct {
		Colors []color `flag:"colors"`
	}

	calls := 0
	read := Reader(func(s string) (color, error) { calls++; return color(s), nil })

	tree, err := New(
		Command[input]{
			Name: "paint",
			Run:  func(context.Context, input) error { return nil },
		},
		read,
	)
	if err != nil {
		t.Fatal(err)
	}

	calls = 0

	if words, _ := tree.Complete(
		[]string{"--colors"},
		"red,blue,g",
	); !slices.Equal(words, []string{"red,blue,green"}) ||
		calls != 0 {
		t.Errorf("red,blue,g: got %q with %d reader calls", words, calls)
	}
}

// TestTab: what the types offer (rules T14, T19–T22); the line is split on
// spaces and the last word is under the cursor.
func TestTab(t *testing.T) {
	for _, tc := range []struct{ id, line, want string }{
		{"T19", "peers list ", "red\tWarm | green | blue | :4"},
		{"T19", "peers list g", "green | :4"},
		{"T19", "peers set 7 ::/0 --colors ", "red\tWarm | green | blue | :4"},
		{"T19", "peers set 7 ::/0 --colors=b", "blue | :4"},
		{"T20", "peers set 7 ::/0 --colors red,", "red,red\tWarm | red,green | red,blue | :6"},
		{"T20", "peers set 7 ::/0 --colors red,blue,g", "red,blue,green | :6"},
		{"T20", "peers set 7 ::/0 --colors=red,g", "red,green | :6"},
		{"T20", "peers set 7 ::/0 --rule red --rule green,b", "green,blue | :6"},
		// Nothing after an empty item: the run refuses the list.
		{"T20", "peers set 7 ::/0 --colors ,", ":4"},
		{"T20", "peers set 7 ::/0 --colors=,b", ":4"},
		{"T20", "peers set 7 ::/0 --colors=red,,b", ":4"},
		{"T21", "peers set ", ":4"},                // a late type offers nothing
		{"T21", "peers set 7 ", ":4"},              // netip.Prefix has no Complete
		{"T21", "peers set 7 ::/0 --name ", ":4"},  // nor has string
		{"T21", "peers set 7 ::/0 --owner ", ":4"}, // late
		{"T21", "peers set 7 ::/0 --force=", ":4"}, // no words for a bool
		{"T21", "peers list red ", ":4"},           // no argument is left
		{"T22", "peers set 7 ::/0 ", ":0"},         // Opt[Path]: the shell offers files
		{"T22", "-c ", ":0"},                       //
		{"T22", "peers list --config=", ":0"},      //
		{"T12", "peers ", "set\tChange a peer | list\tList peers | :4"},
		{"T12", "peers list --", "--help\tShow help | --config\tConfig file | --verbose | :4"},
		{"T7", "peers list -v --", "--help\tShow help | --config\tConfig file | --verbose | :4"}, // a Repeat is offered again
		{"T7", "peers set 7 ::/0 --colors red --co", "--count | --config\tConfig file | :4"},
		{"T14", "-c /x peers set 7 --tag a --note p", `at=peers/set;flags=[{config /x 0} {tag a 5}];args=["7"];prefix="p";filled=false | :6`},
	} {
		words := strings.Split(tc.line, " ")

		var b bytes.Buffer
		if !testTree().Serve(&b, append([]string{"__complete"}, words...)) {
			t.Fatal("Serve refused __complete")
		}

		if got := strings.Join(
			strings.Split(strings.TrimSuffix(b.String(), "\n"), "\n"),
			" | ",
		); got != tc.want {
			t.Errorf("%s %q:\n got %q\nwant %q", tc.id, tc.line, got, tc.want)
		}
	}

	if w, d := testTree().Complete([]string{"peers"}, "l"); !slices.Equal(
		w,
		[]string{"list\tList peers"},
	) ||
		d != NoFiles {
		t.Errorf("Complete: %q %d", w, d)
	}

	var b bytes.Buffer
	if testTree().Serve(&b, []string{"peers"}) || b.Len() != 0 {
		t.Error("S1: Serve answered a line that is no completion request")
	}
}

// TestShared: one Tree serves many lines at once (rule M7); run it with -race.
func TestShared(t *testing.T) {
	var wg sync.WaitGroup
	for i := range 64 {
		wg.Go(func() {
			in, _, err := run(
				t,
				fmt.Sprintf("peers set %d 10.0.0.0/8 --count %d --tag x", i, i),
			)
			if got, _ := in.(setIn); err != nil || got.Peer.ID != i || got.Count != i ||
				len(got.Tag) != 1 {
				t.Errorf("line %d: %+v %v", i, in, err)
			}

			testTree().Complete([]string{"peers", "set", "7", "a", "--colors"}, "r")
		})
	}

	wg.Wait()
}

// TestStdlibOnly: the core, with the reader under it, imports nothing
// outside Go's standard library (D25).
func TestStdlibOnly(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps", "-f", "{{if not .Standard}}{{.ImportPath}}{{end}}", ".").
		Output()
	if err != nil {
		t.Fatal("go list must run for this guard (D25):", err)
	}

	if deps := strings.Fields(
		string(out),
	); !slices.Equal(
		deps,
		[]string{
			"github.com/juanfont/headscale/cmdline/reader",
			"github.com/juanfont/headscale/cmdline",
		},
	) {
		t.Errorf("non-standard imports: %v", deps)
	}
}

// FuzzParse: the typed layer on any argv. No panic; the same answer twice;
// a mistake has a place on the line, and the words before that place hold no
// mistake of their own but a wrong count (D35: the first mistake is the one
// reported); a line without a mistake runs, once.
func FuzzParse(f *testing.F) {
	for _, s := range []string{
		"peers|set|7|10.0.0.0/8|--count|3|--tag|a|--tag|b", "peers|set|7|a|--force=maybe|--bogus", "-c|x|peers|list|-v|-v|red",
		"peers|set|7|a,,b|--colors|red,|--wait|5", "-h|peers|set|--others|1,2|--owner|x|--|-", "version|--help", "peers|set|7|a|--name",
	} {
		f.Add(s)
	}

	tree := testTree()

	f.Fuzz(func(t *testing.T, s string) {
		argv := strings.Split(s, "|")
		if len(argv) > 64 {
			t.Skip()
		}

		l, err := tree.Parse(argv)

		_, err2 := tree.Parse(argv)
		if errText(err) != errText(err2) {
			t.Fatalf("%q: %v, then %v", argv, err, err2)
		}

		tree.Complete(argv[:len(argv)-1], argv[len(argv)-1])

		e, _ := errors.AsType[*UsageError](err)
		switch {
		case err != nil && e == nil:
			t.Fatalf("%q: an error that is no UsageError: %v", argv, err)
		case e != nil:
			if e.At < 0 || e.At > len(argv) ||
				(e.At == len(argv)) != (e.Kind == ArgCount) {
				t.Fatalf("%q: %s is off the line", argv, errText(err))
			}

			_, before := tree.Parse(argv[:e.At])
			if before != nil {
				b, _ := errors.AsType[*UsageError](before)
				if b == nil || b.Kind != ArgCount {
					t.Fatalf(
						"%q: reported %s, but the words before it hold %s",
						argv,
						errText(e),
						errText(before),
					)
				}
			}

			//nolint:err113,errorlint // identity is the rule: Run returns this very value
			if l.Run(context.Background()) != err {
				t.Fatalf("%q: Run ran a line with a mistake", argv)
			}
		case len(l.Command.Commands) > 0:
			//nolint:err113,errorlint // identity is the rule: Run returns this very value
			if l.Run(context.Background()) != ErrGroup {
				t.Fatalf("%q: a group ran", argv)
			}
		default:
			err := l.Run(context.Background())
			if err != nil {
				u, _ := errors.AsType[*UsageError](err)
				if u == nil || u.Kind != Unresolved {
					t.Fatalf("%q: Run: %v", argv, err)
				}
			}

			err = l.Run(context.Background())
			//nolint:err113,errorlint // identity is the rule: Run returns this very value
			if err != ErrRan {
				t.Fatalf("%q: a second Run: %v", argv, err)
			}

			seen := map[string]bool{}
			for _, g := range l.Flags {
				if seen[g.Name] && g.Name != "tag" && g.Name != "rule" &&
					g.Name != "verbose" {
					t.Fatalf("%q: --%s twice on a line without a mistake", argv, g.Name)
				}

				seen[g.Name] = true
			}
		}
	})
}

// set is a slice that reads itself, cut at "+" (Y5).
type set []string

func (s *set) UnmarshalText(
	b []byte,
) error {
	*s = strings.Split(string(b), "+")
	return nil
}

// yesno is a named bool that reads itself (Y10).
type yesno bool

func (y *yesno) UnmarshalText(b []byte) error {
	switch string(b) {
	case "yes", "true":
		*y = true
	case "no":
		*y = false
	default:
		return errWantYesNo
	}

	return nil
}

type oddIn struct {
	Set   set            `flag:"set"`
	Sets  []set          `flag:"sets"`
	YN    yesno          `flag:"yn"`
	Label Repeat[string] `default:"x"   flag:"label"`
	Lists Repeat[[]int]  `default:"1,2" flag:"lists"`
	Rest  Opt[string]    `arg:"rest"`
}

// TestOddTypes: a slice and a bool that read themselves, and a Repeat with
// a default (rules Y5, Y9, Y10).
func TestOddTypes(t *testing.T) {
	tree, err := New(Command[oddIn]{Name: "odd", Run: record[oddIn]})
	if err != nil {
		t.Fatal(err)
	}

	get := func(line string) oddIn {
		t.Helper()

		l, err := tree.Parse(argv(line))
		if err != nil {
			t.Fatalf("%q: %v", line, err)
		}

		in, _ := Get[oddIn](l)

		return in
	}
	// Y5: a type that reads itself gets the whole word, commas and all; a
	// list of such a type is cut at the commas and each item reads itself.
	in := get("--set a,b+c --sets a+b,c")
	if want := (set{"a,b", "c"}); !slices.Equal(in.Set, want) || len(in.Sets) != 2 ||
		!slices.Equal(in.Sets[0], set{"a", "b"}) ||
		!slices.Equal(in.Sets[1], set{"c"}) {
		t.Errorf("Y5: %q %q", in.Set, in.Sets)
	}

	if in = get("--set="); !slices.Equal(in.Set, set{""}) {
		t.Errorf("Y5: an empty word is the type's to judge, not a list's: %q", in.Set)
	}
	// Y10: a named bool that reads itself is a bool flag: it takes no value
	// word, bare it is handed "true", and after "=" its own words count.
	if in = get("--yn rest"); !bool(in.YN) || in.Rest != Some("rest") {
		t.Errorf("Y10: %+v", in)
	}

	if in = get("--yn=no"); bool(in.YN) {
		t.Errorf("Y10: %+v", in)
	}

	_, err = tree.Parse(argv("--yn=false"))
	if errText(
		err,
	) != `bad-value [] @0 word="--yn" flag=yn value="false" err=want yes or no` {
		t.Errorf("Y10: the type's words, not the library's: %s", errText(err))
	}
	// Y9: a Repeat that is not given holds its default as one occurrence;
	// given, it holds only what was given.
	if in = get(
		"",
	); !slices.Equal(in.Label, []string{"x"}) || len(in.Lists) != 1 ||
		!slices.Equal(in.Lists[0], []int{1, 2}) {
		t.Errorf("Y9: %+v", in)
	}

	if in = get(
		"--label a --label b --lists 3",
	); !slices.Equal(in.Label, []string{"a", "b"}) || len(in.Lists) != 1 ||
		!slices.Equal(in.Lists[0], []int{3}) {
		t.Errorf("Y9: %+v", in)
	}

	for _, f := range tree.Root().Flags {
		got := fmt.Sprintf(
			"%s bool=%v list=%v repeat=%v type=%v default=%q",
			f.Name,
			f.Bool,
			f.List,
			f.Repeat,
			f.Type,
			f.Default,
		)

		want := map[string]string{
			"set":   `set bool=false list=false repeat=false type=cmdline.set default=""`,
			"sets":  `sets bool=false list=true repeat=false type=cmdline.set default=""`,
			"yn":    `yn bool=true list=false repeat=false type=cmdline.yesno default=""`,
			"label": `label bool=false list=false repeat=true type=string default="x"`,
			"lists": `lists bool=false list=true repeat=true type=int default="1,2"`,
		}[f.Name]
		if got != want {
			t.Errorf("I2:\n got %s\nwant %s", got, want)
		}
	}
}

// runner calls Run on the Line its Complete method gets.
type runner string

func (r *runner) UnmarshalText(b []byte) error { *r = runner(b); return nil }

func (runner) Complete(l *Line, _ string) ([]string, Directive) {
	return []string{fmt.Sprint(l.Run(context.Background()))}, NoFiles
}

// TestRun: the lines that do not run, and that a line runs once (rules G5–G7).
func TestRun(t *testing.T) {
	// G6: a second Run calls no reader and no command.
	l, err := testTree().Parse(argv("peers set 7 ::/0"))
	if err != nil {
		t.Fatal(err)
	}

	r, look := &ran{}, &lookups{}

	ctx := context.WithValue(
		context.WithValue(context.Background(), ranKey{}, r),
		lookupKey{},
		look,
	)

	err = l.Run(ctx)
	if err != nil || r.in == nil {
		t.Fatalf("G6: first Run: %v", err)
	}

	r.in = nil

	err = l.Run(ctx)
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err != ErrRan || r.in != nil || len(look.calls) != 1 {
		t.Errorf("G6: second Run: %v, ran %v, lookups %v", err, r.in, look.calls)
	}
	// G6: also when the first Run stopped at a late reader.
	l, _ = testTree().Parse(argv("peers set nobody ::/0"))
	look = &lookups{}

	ctx = context.WithValue(context.Background(), lookupKey{}, look)

	e, _ := errors.AsType[*UsageError](l.Run(ctx))
	if e == nil || e.Kind != Unresolved {
		t.Fatal("G6: the first Run must stop at the lookup")
	}

	err = l.Run(ctx)
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err != ErrRan || len(look.calls) != 1 {
		t.Errorf("G6: Run after a failed lookup: %v, lookups %v", err, look.calls)
	}
	// G5: a mistake and a group answer the same every time.
	l, err = testTree().Parse(argv("peers set"))

	first, second := l.Run(ctx), l.Run(ctx)
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if first != err || second != err {
		t.Error("G5: Run gives the mistake back every time")
	}

	l, _ = testTree().Parse(argv("peers"))

	first, second = l.Run(ctx), l.Run(ctx)
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if first != ErrGroup || second != ErrGroup {
		t.Error("G5: a group never runs")
	}
	// G7: the Line a Complete method gets does not run, at a command or at
	// a group; nor does a Line made by hand.
	type above struct {
		R runner `flag:"r"`
	}

	type in struct {
		R runner      `flag:"r"`
		A Opt[runner] `arg:"a"`
	}

	ranIt := false

	tree, err := New(Group{Name: "prog", Flags: []any{above{}}, Commands: []Node{
		Command[in]{
			Name: "c",
			Run:  func(context.Context, in) error { ranIt = true; return nil },
		},
	}})
	if err != nil {
		t.Fatal(err)
	}

	for _, words := range [][]string{{"c"}, {"c", "--r"}, {"--r"}} {
		if got, _ := tree.Complete(
			words,
			"",
		); !slices.Equal(got, []string{ErrNotParsed.Error()}) ||
			ranIt {
			t.Errorf("G7: Tab %q: %q, ran %v", words, got, ranIt)
		}
	}

	err = new(Line).Run(ctx)
	//nolint:err113,errorlint // identity is the rule: Run returns this very value
	if err != ErrNotParsed {
		t.Errorf("G7: a Line made by hand: %v", err)
	}
}

// TestReuseDeclaredAlias: the tree owns its aliases; neither the caller's
// slice nor the one Info hands out changes dispatch.
func TestReuseDeclaredAlias(t *testing.T) {
	t.Parallel()

	aliases := []string{"ls"}
	cmd := func(name string, aliases []string) Node {
		return Command[struct{}]{
			Name:    name,
			Aliases: aliases,
			Run:     func(context.Context, struct{}) error { return nil },
		}
	}

	tree, err := New(
		Group{Name: "tool", Commands: []Node{cmd("list", aliases), cmd("count", nil)}},
	)
	if err != nil {
		t.Fatal(err)
	}

	aliases[0] = "count"
	tree.Root().Commands[0].Aliases[0] = "count"

	line, err := tree.Parse([]string{"count"})
	if err != nil || line.Command.Name != "count" {
		t.Fatalf("count selected %q: %v", line.Command.Name, err)
	}
}

// TestRunAfterArgvReuse: a late error names the word as it was typed, even
// when the caller reuses argv after Parse, and a positional word keeps
// its "=".
func TestRunAfterArgvReuse(t *testing.T) {
	for _, tt := range []struct {
		line  string
		at    int
		word  string
		value string
	}{
		{"peers set nobody ::/0", 2, "nobody", "nobody"},
		{"peers set no=body ::/0", 2, "no=body", "no=body"},
		{"peers set -- --no=body ::/0", 3, "--no=body", "--no=body"},
		{"peers set --owner=nobody 7 ::/0", 2, "--owner", "nobody"},
	} {
		t.Run(tt.line, func(t *testing.T) {
			words := argv(tt.line)

			line, err := testTree().Parse(words)
			if err != nil {
				t.Fatal(err)
			}

			words[tt.at] = "reused"

			e, ok := errors.AsType[*UsageError](line.Run(t.Context()))
			if !ok || e.Kind != Unresolved || e.At != tt.at || e.Word != tt.word ||
				e.Value != tt.value {
				t.Fatalf(
					"late error after argv reuse = %#v, want word %q at %d",
					e,
					tt.word,
					tt.at,
				)
			}
		})
	}
}

// TestOptNil: a reader may return nil for an Opt of an interface; the flag
// is given, its value nil (Y3, Y7).
func TestOptNil(t *testing.T) {
	type input struct {
		X Opt[any] `flag:"x"`
	}

	var got Opt[any]

	//nolint:nilnil // a nil value is the case
	tree, err := New(
		Command[input]{
			Name: "c",
			Run:  func(_ context.Context, in input) error { got = in.X; return nil },
		},
		Reader(func(string) (any, error) { return nil, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}

	l, err := tree.Parse([]string{"--x=1"})
	if err != nil {
		t.Fatal(err)
	}

	err = l.Run(t.Context())
	if v, ok := got.Get(); err != nil || v != nil || !ok {
		t.Errorf("Opt[any] read as nil: got %v %v, run %v", v, ok, err)
	}
}
