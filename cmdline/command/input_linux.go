package command

import "golang.org/x/sys/unix"

// discardInput drops what was typed on the terminal fd and not yet read.
func discardInput(fd int) {
	_ = unix.IoctlSetInt(fd, unix.TCFLSH, unix.TCIFLUSH)
}
