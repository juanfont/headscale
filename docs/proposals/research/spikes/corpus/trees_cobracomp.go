package main

import "spike/kit"

// "cc": cobra's TestMultipleShorthandFlagCompletion and
// TestArgsNotDetectedAsFlagsCompletionInGo need bool shorts, a string short
// with values, and positionals that all have values (some with a dash inside).
type ccPickIn struct {
	A      string `arg:"a" complete:"service 1-123 11-123"`
	B      string `arg:"b" complete:"service 1-123 11-123"`
	C      string `arg:"c" complete:"service 1-123 11-123"`
	Short  bool   `flag:"short" short:"s"`
	Short2 bool   `flag:"short2" short:"d"`
	Short3 string `flag:"short3" short:"f" complete:"works"`
}

func init() {
	trees["cc"] = func() *kit.Tree {
		return kit.Build(kit.New(kit.Spec[ccPickIn]{Use: "pick [a] [b] [c]", Run: kit.Record[ccPickIn]}))
	}
}
