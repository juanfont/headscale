package main

import (
	"bytes"
	"fmt"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// openPTY opens a pseudo-terminal pair: grant and unlock the master, then
// open the slave it names, as grantpt, unlockpt and ptsname do.
func openPTY() (*os.File, *os.File, error) {
	master, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	fd := master.Fd()

	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, fd, unix.TIOCPTYGRANT, 0)
	if errno != 0 {
		return nil, nil, fmt.Errorf("granting the pty: %w", errno)
	}

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, unix.TIOCPTYUNLK, 0)
	if errno != 0 {
		return nil, nil, fmt.Errorf("unlocking the pty: %w", errno)
	}

	// TIOCPTYGNAME writes the name into a buffer of 128 bytes, which no
	// helper of x/sys/unix hands it. The pointer becomes a uintptr in the
	// call itself, as unsafe.Pointer's rule for syscalls asks.
	name := make([]byte, 128)

	_, _, errno = syscall.Syscall(syscall.SYS_IOCTL, fd, unix.TIOCPTYGNAME, uintptr(unsafe.Pointer(&name[0])))
	if errno != 0 {
		return nil, nil, fmt.Errorf("naming the pty: %w", errno)
	}

	name, _, _ = bytes.Cut(name, []byte{0})

	slave, err := os.OpenFile(string(name), os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, err
	}

	return master, slave, nil
}
