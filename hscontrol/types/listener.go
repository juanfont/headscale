package types

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/viper"
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
// Accepts host:port form with either a numeric port or one of the named
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

	p, err := strconv.Atoi(port)
	if err != nil {
		return 0, fmt.Errorf("parse port from %q: %w", addr, err)
	}

	return p, nil
}

// listenersOverlap reports whether two parsed TCP listen addresses would
// compete for the same kernel socket. Mirrors kernel rules:
//   - different ports                              → false
//   - same port + a wildcard host on either side   → true
//   - same port + identical specific host          → true
//   - same port + different specific hosts         → false
func listenersOverlap(aHost string, aPort int, bHost string, bPort int) bool {
	if aPort != bPort {
		return false
	}

	if isWildcardHost(aHost) || isWildcardHost(bHost) {
		return true
	}

	return aHost == bHost
}

func isWildcardHost(h string) bool {
	switch h {
	case "", "0.0.0.0", "::", "[::]":
		return true
	}

	return false
}

// validateListenerCollisions records a *ConfigError for each pair of
// configured TCP listeners that would bind the same kernel socket. The
// ACME HTTP-01 challenge listener is only considered when a hostname is
// set and the HTTP-01 challenge is selected.
//
// Parsing happens up-front, once per listener: a malformed address
// produces a ConfigError tied to its own YAML key, so an operator can
// see exactly which value to fix instead of guessing from a paired
// comparison.
func validateListenerCollisions(v *configValidator) {
	type spec struct {
		key, addr string
		host      string
		port      int
		parsed    bool
		active    bool
	}

	listenAddr := viper.GetString("listen_addr")
	grpcAddr := viper.GetString("grpc_listen_addr")
	metricsAddr := viper.GetString("metrics_listen_addr")
	acmeAddr := viper.GetString("tls_letsencrypt_listen")

	listeners := []spec{
		{key: "listen_addr", addr: listenAddr, active: listenAddr != ""},
		{key: "grpc_listen_addr", addr: grpcAddr, active: grpcAddr != ""},
		{key: "metrics_listen_addr", addr: metricsAddr, active: metricsAddr != ""},
		{
			key:  "tls_letsencrypt_listen",
			addr: acmeAddr,
			active: acmeAddr != "" &&
				viper.GetString("tls_letsencrypt_hostname") != "" &&
				viper.GetString("tls_letsencrypt_challenge_type") == HTTP01ChallengeType,
		},
	}

	for i := range listeners {
		l := &listeners[i]
		if !l.active {
			continue
		}

		port, err := PortFromAddr(l.addr)
		if err != nil {
			v.Add(&ConfigError{
				Reason:  "cannot parse " + l.key,
				Current: []KV{{l.key, l.addr}},
				Detail:  err.Error(),
				Hint:    `use host:port form, e.g. "0.0.0.0:8080"`,
			})

			continue
		}

		host, _, _ := net.SplitHostPort(l.addr)
		l.host = host
		l.port = port
		l.parsed = true
	}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			a, b := listeners[i], listeners[j]
			if !a.parsed || !b.parsed {
				continue
			}

			if !listenersOverlap(a.host, a.port, b.host, b.port) {
				continue
			}

			v.Add(&ConfigError{
				Reason:        fmt.Sprintf("%s and %s would bind the same TCP socket", a.key, b.key),
				Current:       []KV{{a.key, a.addr}},
				ConflictsWith: []KV{{b.key, b.addr}},
				Hint:          "give each listener a distinct port, or bind them to different non-wildcard hosts",
				See:           "https://headscale.net/stable/ref/tls/",
			})
		}
	}
}
