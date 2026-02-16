package zlog

import (
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"tailscale.com/tailcfg"
)

// SafeHostinfo wraps tailcfg.Hostinfo for safe logging.
//
// SECURITY: This wrapper intentionally redacts device fingerprinting data
// that could be used to identify or track specific devices:
//   - OSVersion, DeviceModel, DistroName, DistroVersion (device fingerprinting)
//   - IPNVersion (client version fingerprinting)
//   - Machine, FrontendLogID (device identifiers)
//
// Only safe fields are logged:
//   - hostname: The device hostname
//   - os: The OS family (e.g., "linux", "windows") without version
//   - routable_ips_count: Number of advertised routes (not the actual routes)
//   - request_tags: Tags requested by the client
//   - derp: Preferred DERP region ID
type SafeHostinfo struct {
	hi *tailcfg.Hostinfo
}

// Hostinfo creates a SafeHostinfo wrapper for safe logging.
func Hostinfo(hi *tailcfg.Hostinfo) SafeHostinfo {
	return SafeHostinfo{hi: hi}
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler.
func (s SafeHostinfo) MarshalZerologObject(e *zerolog.Event) {
	if s.hi == nil {
		return
	}

	// Safe fields only - no device fingerprinting data.
	e.Str(zf.Hostname, s.hi.Hostname)
	e.Str(zf.OS, s.hi.OS) // OS family only, NOT version

	if len(s.hi.RoutableIPs) > 0 {
		e.Int(zf.RoutableIPCount, len(s.hi.RoutableIPs))
	}

	if len(s.hi.RequestTags) > 0 {
		e.Strs(zf.RequestTags, s.hi.RequestTags)
	}

	if s.hi.NetInfo != nil && s.hi.NetInfo.PreferredDERP != 0 {
		e.Int(zf.DERP, s.hi.NetInfo.PreferredDERP)
	}

	// SECURITY: The following fields are intentionally NOT logged:
	// - OSVersion, DistroName, DistroVersion, DistroCodeName: device fingerprinting
	// - DeviceModel: device fingerprinting
	// - IPNVersion: client version fingerprinting
	// - Machine, FrontendLogID: device identifiers
	// - GoArch, GoArchVar, GoVersion: build environment fingerprinting
	// - Userspace, UserspaceRouter: network configuration details
}
