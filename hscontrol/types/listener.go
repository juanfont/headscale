package types

import (
	"errors"
	"fmt"
	"net"
	"strconv"
)

var errEmptyListenAddr = errors.New("address is empty")

// portFromAddr resolves the numeric port of a TCP listen address.
// Accepts host:port form with either a numeric port or one of the named
// services "http" / "https". The named-service table is intentionally
// hardcoded so this stays a pure string->int mapping with no network or
// /etc/services lookups.
func portFromAddr(addr string) (int, error) {
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

	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port from %q: %w", addr, err)
	}

	return p, nil
}

// listenersOverlap reports whether two TCP listen addresses would
// compete for the same kernel socket. Mirrors kernel rules:
//   - different ports                              → false
//   - same port + a wildcard host on either side   → true
//   - same port + identical specific host          → true
//   - same port + different specific hosts         → false
func listenersOverlap(a, b string) (bool, error) {
	aPort, err := portFromAddr(a)
	if err != nil {
		return false, err
	}

	bPort, err := portFromAddr(b)
	if err != nil {
		return false, err
	}

	if aPort != bPort {
		return false, nil
	}

	aHost, _, _ := net.SplitHostPort(a)
	bHost, _, _ := net.SplitHostPort(b)

	if isWildcardHost(aHost) || isWildcardHost(bHost) {
		return true, nil
	}

	return aHost == bHost, nil
}

func isWildcardHost(h string) bool {
	switch h {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}

	return false
}
