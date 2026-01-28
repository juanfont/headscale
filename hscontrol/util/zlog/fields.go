// Package zlog provides zerolog utilities for safe and consistent logging.
//
// This package contains:
//   - Safe wrapper types for external types (tailcfg.Hostinfo, tailcfg.MapRequest)
//     that implement LogObjectMarshaler with security-conscious field redaction
//
// For field name constants, use the zf subpackage:
//
//	import "github.com/juanfont/headscale/hscontrol/util/zlog/zf"
//
// # Usage Pattern: Sub-Loggers
//
// The recommended pattern is to create sub-loggers at function entry points:
//
//	func (m *mapSession) serve() {
//	    log := log.With().
//	        EmbedObject(m.node).
//	        EmbedObject(zlog.MapRequest(&m.req)).
//	        Logger()
//
//	    log.Info().Msg("Map session started")
//	    log.Debug().Caller().Msg("Processing request")
//	}
//
// # Security Considerations
//
// The wrapper types in this package intentionally redact sensitive information:
//   - Device fingerprinting data (OS version, device model, etc.)
//   - Client endpoints and IP addresses
//   - Full authentication keys (only prefixes are logged)
package zlog
