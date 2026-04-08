package zlog

import "github.com/rs/zerolog"

// init pins zerolog to TraceLevel for the zlog test binary.
//
// zlog's tests use zerolog.New(&buf) and assert on Info-level output. zerolog's
// (*Logger).should() gates emission on the global level, so any global level
// above Info would silently break the assertions.
//
// Today zlog does not transitively import hscontrol/types, so the test
// silencing init() in hscontrol/types/testlog.go does not run in this binary.
// This init defends against that changing in the future: if a future import
// chain pulls in hscontrol/types, this file will still ensure trace-level
// output is available for zlog's assertions.
func init() {
	zerolog.SetGlobalLevel(zerolog.TraceLevel)
}
