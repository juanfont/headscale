package types

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"syscall"
)

var errEmptyListenAddr = errors.New("address is empty")

// ListenerBindError is returned when a TCP listener fails to bind. It
// names the listener and the YAML key that drove the address so an
// operator can identify which socket collided. The underlying error
// (typically *net.OpError around syscall.EADDRINUSE / EACCES) is
// preserved via Unwrap, so errors.Is(err, syscall.EADDRINUSE) keeps
// working through any number of fmt.Errorf("%w") wraps.
type ListenerBindError struct {
	Listener string
	YAMLKey  string
	Addr     string
	Err      error
}

func (e *ListenerBindError) Error() string {
	return fmt.Sprintf("binding %s listener (%s=%q): %v",
		e.Listener, e.YAMLKey, e.Addr, e.Err)
}

func (e *ListenerBindError) Unwrap() error { return e.Err }

// PortFromAddr resolves the numeric port of a TCP listen address.
// Accepts host:port form with either a numeric port from 0 to 65535 or one of the named
// services "http" / "https". The named-service table is intentionally
// hardcoded so this stays a pure string->int mapping with no network or
// /etc/services lookups.
func PortFromAddr(addr string) (int, error) {
	if addr == "" {
		return 0, errEmptyListenAddr
	}

	_, port, err := net.SplitHostPort(addr)
	if err != nil {
		return 0, fmt.Errorf("split host/port from %q: %w", addr, err)
	}

	switch port {
	case "http":
		return 80, nil
	case "https":
		return 443, nil
	}

	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return 0, fmt.Errorf("parse port from %q: %w", addr, err)
	}

	return int(p), nil
}

// ExplainBindError augments specific error classes with operator
// hints. The underlying chain is left intact so errors.Is / errors.As
// continue to walk to ListenerBindError, syscall.EADDRINUSE, etc.
func ExplainBindError(err error) error {
	var bindErr *ListenerBindError
	if !errors.As(err, &bindErr) {
		return err
	}

	switch {
	case errors.Is(err, syscall.EADDRINUSE):
		port, perr := PortFromAddr(bindErr.Addr)
		if perr != nil {
			return fmt.Errorf(
				"%w\n\nHint: another process on this host is bound to the same address. "+
					"Find it with: sudo ss -tlnp",
				err)
		}

		return fmt.Errorf(
			"%w\n\nHint: another process on this host is bound to the same address. "+
				"Find it with: sudo ss -tlnp 'sport = :%d'",
			err, port)

	case errors.Is(err, syscall.EACCES):
		return fmt.Errorf(
			"%w\n\nHint: binding to a privileged port (<1024) requires root or "+
				"CAP_NET_BIND_SERVICE. The shipped systemd unit grants this capability; "+
				"if running manually, use sudo or "+
				"`setcap cap_net_bind_service=+ep ./headscale`",
			err)
	}

	return err
}
