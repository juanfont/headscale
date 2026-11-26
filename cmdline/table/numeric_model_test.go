package table

import (
	"pgregory.net/rapid"
)

// fatalf fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
