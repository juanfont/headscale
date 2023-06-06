package types

import "time"

const (
	HTTPReadTimeout        = 30 * time.Second
	HTTPShutdownTimeout    = 3 * time.Second
	TlsALPN01ChallengeType = "TLS-ALPN-01"
	Http01ChallengeType    = "HTTP-01"

	JSONLogFormat = "json"
	TextLogFormat = "text"

	KeepAliveInterval = 60 * time.Second
	MaxHostnameLength = 255
)
