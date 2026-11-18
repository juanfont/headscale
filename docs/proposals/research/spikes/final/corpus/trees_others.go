package main

import "spike/kit"

// "others": one leaf for the short-flag tables of urfave/cli and ff, whose
// flags are bools -a -b -c -f and strings -i -s. The kit's root takes -c and
// -o, and -f reads better as a bool here, so upstream -c is -k, -f is -g and
// urfave's -o ("one") is -a.
func init() {
	trees["others"] = func() *kit.Tree { return kit.Build(othersDefs...) }
}

type othersIn struct {
	A     string   `arg:"a"`
	B     string   `arg:"b"`
	C     string   `arg:"c"`
	D     string   `arg:"d"`
	E     string   `arg:"e"`
	Aflag bool     `flag:"aflag" short:"a"`
	Bflag bool     `flag:"bflag" short:"b"`
	Kflag bool     `flag:"kflag" short:"k"`
	Gflag bool     `flag:"gflag" short:"g"`
	Str   *string  `flag:"str" short:"s"`
	Ijk   string   `flag:"ijk" short:"i"`
	Xxx   []string `flag:"xxx" short:"x"`
}

var othersDefs = []kit.Def{
	kit.New(kit.Spec[othersIn]{Use: "test [a] [b] [c] [d] [e]", Run: kit.Record[othersIn]}),
}
