//go:build unix

package db

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"syscall"
)

// shmDMS is the byte of a SQLite -shm file that every connection with the
// write-ahead log holds a read lock on for as long as it is open, which
// SQLite reads to tell whether it is alone: UNIX_SHM_DMS of os_unix.c.
const shmDMS = 128

// othersHoldWAL reports whether another process has the SQLite database
// at path open with the write-ahead log. F_GETLK asks without taking a
// lock, and sees only the locks of other processes.
func othersHoldWAL(path string) (bool, error) {
	f, err := os.Open(path + "-shm")
	if errors.Is(err, fs.ErrNotExist) {
		return false, nil
	}

	if err != nil {
		return false, err
	}

	defer f.Close()

	lk := syscall.Flock_t{Type: syscall.F_WRLCK, Whence: io.SeekStart, Start: shmDMS, Len: 1}

	err = syscall.FcntlFlock(f.Fd(), syscall.F_GETLK, &lk)
	if err != nil {
		return false, err
	}

	return lk.Type != syscall.F_UNLCK, nil
}
