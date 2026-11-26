package newcli

import (
	"pgregory.net/rapid"
)

// fatal fails a draw with its format alone and logs the values: Rapid
// shrinks a failure only while it reads the same on replay, and a value
// the fixture makes, such as a fresh ID or a time, changes between
// replays.
func fatalf(rt rapid.TB, format string, args ...any) {
	rt.Helper()
	rt.Logf(format, args...)
	rt.Fatal(format)
}
