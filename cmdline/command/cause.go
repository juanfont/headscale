package command

import (
	"context"
	"errors"
	"net/url"
	"syscall"
)

// CauseOf is the part of a dial or request error that says what was
// wrong, without the operation and the address that the message already
// names.
func CauseOf(err error) string {
	var (
		errno syscall.Errno
		uerr  *url.Error
	)

	switch {
	case errors.As(err, &errno):
		return errno.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	case errors.As(err, &uerr):
		return uerr.Err.Error()
	}

	return err.Error()
}
