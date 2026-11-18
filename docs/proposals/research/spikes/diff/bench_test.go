package diff

import (
	"runtime"
	"testing"

	cobraadapter "spike/cobra"
	"spike/kit"
	grammar "spike/own-grammar"
	ownpflag "spike/own-pflag"
)

var benchArgv = []string{"nodes", "list", "--columns", "id,name", "-o", "json"}

func BenchmarkProbeGrammar(b *testing.B) {
	for b.Loop() {
		Outcome(grammar.Adapter{}, benchArgv)
	}
}
func BenchmarkProbePflag(b *testing.B) {
	for b.Loop() {
		Outcome(ownpflag.Adapter{}, benchArgv)
	}
}
func BenchmarkProbeCobra(b *testing.B) {
	for b.Loop() {
		Outcome(cobraadapter.Adapter{}, benchArgv)
	}
}
func BenchmarkNewTree(b *testing.B) {
	for b.Loop() {
		kit.NewTree()
	}
}

// TestCobraTabHeap: live heap after many Tab calls through the cobra adapter
// against own-grammar; cobra keeps flag completion funcs in a package map.
func TestCobraTabHeap(t *testing.T) {
	for _, a := range []kit.Adapter{grammar.Adapter{}, cobraadapter.Adapter{}} {
		var m0, m1 runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&m0)
		for range 20000 {
			Tab(a, []string{"nodes", "list", "--sort", ""})
		}
		runtime.GC()
		runtime.ReadMemStats(&m1)
		t.Logf("%T: live heap +%d KiB after 20000 Tab calls", a, (int64(m1.HeapAlloc)-int64(m0.HeapAlloc))/1024)
	}
}
