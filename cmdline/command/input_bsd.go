//go:build darwin || freebsd

package command

import "golang.org/x/sys/unix"

// fread is FREAD of sys/fcntl.h, which x/sys does not name: TIOCFLUSH
// drops the input queue only.
const fread = 1

// discardInput drops what was typed on the terminal fd and not yet read.
func discardInput(fd int) {
	_ = unix.IoctlSetPointerInt(fd, unix.TIOCFLUSH, fread)
}
