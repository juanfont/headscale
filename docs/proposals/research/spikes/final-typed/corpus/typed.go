package main

import (
	"fmt"

	"spike/cmdline"
	hs "spike/final-headscale"
	"spike/kit"
)

// typed holds, for each kit tree of the corpus, the same tree as typed
// specs, which is what the typed build runs. twins fails the run when a
// pair differs.
var typed = map[string]func() *hs.Tree{"": hs.KitTree}

type (
	abcRow   struct{}
	abWords  struct{}
	xyzWords struct{}
	oneTwo   struct{}
	svcWords struct{}
	works    struct{}
)

func (abcRow) Columns() []string { return []string{"a", "b", "c"} }
func (abWords) Words() []string  { return []string{"alpha", "beta"} }
func (xyzWords) Words() []string { return []string{"x", "y", "z"} }
func (oneTwo) Words() []string   { return []string{"one", "two"} }
func (svcWords) Words() []string { return []string{"service", "1-123", "11-123"} }
func (works) Words() []string    { return []string{"works"} }

type pfTyped struct {
	A       cmdline.Opt[string]           `arg:"a"`
	B       cmdline.Opt[string]           `arg:"b"`
	C       cmdline.Opt[string]           `arg:"c"`
	Bool    bool                          `flag:"bool" short:"b"`
	Verbose bool                          `flag:"verbose" short:"v"`
	String  cmdline.Opt[hs.Text[abWords]] `flag:"string" short:"s"`
	List    []hs.Text[xyzWords]           `flag:"list" short:"l"`
	File    string                        `flag:"file" short:"f"`
}

type pfSubTyped struct {
	A cmdline.Opt[hs.Text[oneTwo]] `arg:"a"`
}

type ccTyped struct {
	A      cmdline.Opt[hs.Text[svcWords]] `arg:"a"`
	B      cmdline.Opt[hs.Text[svcWords]] `arg:"b"`
	C      cmdline.Opt[hs.Text[svcWords]] `arg:"c"`
	Short  bool                           `flag:"short" short:"s"`
	Short2 bool                           `flag:"short2" short:"d"`
	Short3 hs.Text[works]                 `flag:"short3" short:"f"`
}

type othersTyped struct {
	A     cmdline.Opt[string] `arg:"a"`
	B     cmdline.Opt[string] `arg:"b"`
	C     cmdline.Opt[string] `arg:"c"`
	D     cmdline.Opt[string] `arg:"d"`
	E     cmdline.Opt[string] `arg:"e"`
	Aflag bool                `flag:"aflag" short:"a"`
	Bflag bool                `flag:"bflag" short:"b"`
	Kflag bool                `flag:"kflag" short:"k"`
	Gflag bool                `flag:"gflag" short:"g"`
	Str   cmdline.Opt[string] `flag:"str" short:"s"`
	Ijk   string              `flag:"ijk" short:"i"`
	Xxx   []string            `flag:"xxx" short:"x"`
}

func build(defs ...hs.Def) func() *hs.Tree {
	t, err := hs.Build(kit.Program, map[string]string{"": "Headscale control server"}, defs...)
	if err != nil {
		panic(err)
	}
	return func() *hs.Tree { return t }
}

func init() {
	typed["pf"] = build(
		hs.NewList[pfTyped, abcRow](hs.Spec[pfTyped]{Path: "run", Aliases: []string{"r", "go"}, Output: true, Config: true, Run: kit.Record[pfTyped]}),
		hs.New(hs.Spec[pfSubTyped]{Path: "grp sub", Aliases: []string{"s"}, Run: kit.Record[pfSubTyped]}),
		hs.New(hs.Spec[pfSubTyped]{Path: "grp grp", Run: kit.Record[pfSubTyped]}),
		hs.New(hs.Spec[hs.NoInput]{Path: "grp other", Aliases: []string{"sub2"}, Run: kit.Record[hs.NoInput]}),
	)
	typed["cc"] = build(hs.New(hs.Spec[ccTyped]{Path: "pick", Run: kit.Record[ccTyped]}))
	typed["others"] = build(hs.New(hs.Spec[othersTyped]{Path: "test", Run: kit.Record[othersTyped]}))
}

// twins says where a typed tree is not the kit tree of the same name.
func twins() []string {
	var bad []string
	for name, mk := range trees {
		got, want := hs.Describe(typed[name]()), mk().Commands
		for i := range max(len(got), len(want)) {
			var g, w string
			if i < len(got) {
				g = fmt.Sprintf("%+v", got[i])
			}
			if i < len(want) {
				w = fmt.Sprintf("%+v", want[i])
			}
			if g != w {
				bad = append(bad, fmt.Sprintf("tree %q:\n typed %s\n kit   %s", name, g, w))
			}
		}
	}
	return bad
}
