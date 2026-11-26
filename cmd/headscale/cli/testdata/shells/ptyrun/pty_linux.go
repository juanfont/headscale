package main

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: unlock the master, then open the
// slave it names.
func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	err = unix.IoctlSetPointerInt(int(master.Fd()), unix.TIOCSPTLCK, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("unlocking the pty: %w", err)
	}

	n, err := unix.IoctlGetInt(int(master.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("naming the pty: %w", err)
	}

	slave, err := os.OpenFile(fmt.Sprintf("/dev/pts/%d", n), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	return master, slave, nil
}
