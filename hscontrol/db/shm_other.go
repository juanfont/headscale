//go:build !unix

package db

// othersHoldWAL cannot ask the locks of another process here: the
// exclusive lock of the write is the only witness.
func othersHoldWAL(string) (bool, error) { return false, nil }
