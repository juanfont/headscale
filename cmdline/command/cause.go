package command

import (
	"context"
	"errors"
	"io"
	"net/url"
	"syscall"

	"github.com/juanfont/headscale/cmdline/table"
)

// CauseOf is the part of a dial, request or file error that says what was
// wrong, without the operation and the address that the message already
// names. A TLS error can quote a name from the server's certificate, so it is
// made visible.
func CauseOf(err error) string {
	return table.Visible(cause(err), "")
}

func cause(err error) string {
	var (
		errno syscall.Errno
		uerr  *url.Error
	)

	switch {
	case errors.As(err, &errno):
		return errno.Error()
	case errors.Is(err, context.DeadlineExceeded):
		return "no answer in time"
	// The server, or something on the way, ended the connection.
	case errors.Is(err, io.EOF), errors.Is(err, io.ErrUnexpectedEOF):
		return "the connection was closed"
	case errors.As(err, &uerr):
		return uerr.Err.Error()
	}

	return err.Error()
}
