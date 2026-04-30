package types

import (
	"errors"
	"fmt"
	"net"
	"strconv"

	"github.com/spf13/viper"
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

// validateListenerCollisions records a *ConfigError for each pair of
// configured TCP listeners that would bind the same kernel socket. The
// ACME HTTP-01 challenge listener is only considered when a hostname is
// set and the HTTP-01 challenge is selected.
func validateListenerCollisions(v *configValidator) {
	type spec struct {
		key, addr string
		active    bool
	}

	listenAddr := viper.GetString("listen_addr")
	grpcAddr := viper.GetString("grpc_listen_addr")
	metricsAddr := viper.GetString("metrics_listen_addr")
	acmeAddr := viper.GetString("tls_letsencrypt_listen")

	listeners := []spec{
		{"listen_addr", listenAddr, listenAddr != ""},
		{"grpc_listen_addr", grpcAddr, grpcAddr != ""},
		{"metrics_listen_addr", metricsAddr, metricsAddr != ""},
		{
			key:  "tls_letsencrypt_listen",
			addr: acmeAddr,
			active: acmeAddr != "" &&
				viper.GetString("tls_letsencrypt_hostname") != "" &&
				viper.GetString("tls_letsencrypt_challenge_type") == HTTP01ChallengeType,
		},
	}

	for i := range listeners {
		for j := i + 1; j < len(listeners); j++ {
			a, b := listeners[i], listeners[j]
			if !a.active || !b.active {
				continue
			}

			overlap, err := listenersOverlap(a.addr, b.addr)
			if err != nil {
				v.Add(&ConfigError{
					Reason:  "cannot parse " + a.key,
					Current: []KV{{a.key, a.addr}},
					Detail:  err.Error(),
					Hint:    `use host:port form, e.g. "0.0.0.0:8080"`,
				})

				continue
			}

			if overlap {
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
}
