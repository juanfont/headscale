package main

import "spike/kit"

// trees: "" is the kit's own tree. "pf" is a one-leaf tree for flag-reading
// cases that need shorts the kit's tree lacks (a bool short for grouping, a
// string short with values, a comma list) and up to three positionals.
var trees = map[string]func() *kit.Tree{
	"":   kit.NewTree,
	"pf": func() *kit.Tree { return kit.Build(pfDefs...) },
}

type pfIn struct {
	A       string   `arg:"a"`
	B       string   `arg:"b"`
	C       string   `arg:"c"`
	Bool    bool     `flag:"bool" short:"b"`
	Verbose bool     `flag:"verbose" short:"v"`
	String  *string  `flag:"string" short:"s" complete:"alpha beta"`
	List    []string `flag:"list" short:"l" complete:"x y z"`
	File    string   `flag:"file" short:"f"`
}

type pfSubIn struct {
	A string `arg:"a" complete:"one two"`
}

var pfDefs = []kit.Def{
	kit.New(kit.Spec[pfIn]{Use: "run [a] [b] [c]", Aliases: []string{"r", "go"}, Output: true, Config: true, Columns: []string{"a", "b", "c"}, Run: kit.Record[pfIn]}),
	kit.New(kit.Spec[pfSubIn]{Use: "grp sub [a]", Aliases: []string{"s"}, Run: kit.Record[pfSubIn]}),
	kit.New(kit.Spec[pfSubIn]{Use: "grp grp [a]", Run: kit.Record[pfSubIn]}),
	kit.New(kit.Spec[kit.NoInput]{Use: "grp other", Aliases: []string{"sub2"}, Run: kit.Record[kit.NoInput]}),
}
