package types

import "time"

const (
	HTTPTimeout            = 30 * time.Second
	HTTPShutdownTimeout    = 3 * time.Second
	TLSALPN01ChallengeType = "TLS-ALPN-01"
	HTTP01ChallengeType    = "HTTP-01"

	JSONLogFormat = "json"
	TextLogFormat = "text"

	KeepAliveInterval = 60 * time.Second
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
