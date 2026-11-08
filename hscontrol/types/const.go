package types

import "time"

const (
	HTTPTimeout         = 30 * time.Second
	HTTPShutdownTimeout = 3 * time.Second

	// TLSALPN01ChallengeType has the CA check a special certificate on
	// port 443, answered on `listen_addr`, which must be reachable there.
	TLSALPN01ChallengeType ACMEChallenge = "TLS-ALPN-01"
	// HTTP01ChallengeType has the CA fetch a token over HTTP on port 80,
	// answered on `tls.acme.http_listen`. TLS-ALPN-01 on `listen_addr`
	// stays enabled too.
	HTTP01ChallengeType ACMEChallenge = "HTTP-01"
	// DNS01ChallengeType has the CA look up a TXT record, which headscale
	// writes through `dns.challenge.provider`. It needs no open port.
	DNS01ChallengeType ACMEChallenge = "DNS-01"

	// JSONLogFormat writes one JSON object per line, for log collectors.
	JSONLogFormat LogFormat = "json"
	// TextLogFormat writes human-readable lines, coloured when stderr is a
	// terminal and `NO_COLOR` is unset.
	TextLogFormat LogFormat = "text"

	MaxHostnameLength = 255
)

// Client report limits are above what a stock client sends.
// MaxHostinfoSize applies separately to NetInfo and the remaining fields without routes.
const (
	MaxEndpoints    = 256
	MaxRequestTags  = 256
	MaxRoutableIPs  = 4096
	MaxHostinfoSize = 64 << 10
)
