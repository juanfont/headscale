//go:build !linux && !darwin && !freebsd

package command

// discardInput drops nothing where the CLI knows no way to.
func discardInput(int) {}
