package zlog

import (
	"github.com/juanfont/headscale/hscontrol/util/zlog/zf"
	"github.com/rs/zerolog"
	"tailscale.com/tailcfg"
)

// SafeMapRequest wraps tailcfg.MapRequest for safe logging.
//
// SECURITY: This wrapper does not log sensitive information:
//   - Endpoints: Client IP addresses and ports
//   - Hostinfo: Device fingerprinting data (handled by SafeHostinfo)
//   - DERPForceWebsockets: Network configuration details
//
// Only safe fields are logged:
//   - stream: Whether this is a streaming request
//   - omit_peers: Whether peers should be omitted
//   - version: Client capability version
//   - node.key: Short form of the node key
//   - endpoints_count: Number of endpoints (not the actual endpoints)
type SafeMapRequest struct {
	req *tailcfg.MapRequest
}

// MapRequest creates a SafeMapRequest wrapper for safe logging.
func MapRequest(req *tailcfg.MapRequest) SafeMapRequest {
	return SafeMapRequest{req: req}
}

// MarshalZerologObject implements zerolog.LogObjectMarshaler.
func (s SafeMapRequest) MarshalZerologObject(e *zerolog.Event) {
	if s.req == nil {
		return
	}

	e.Bool(zf.Stream, s.req.Stream)
	e.Bool(zf.OmitPeers, s.req.OmitPeers)
	e.Int(zf.Version, int(s.req.Version))
	e.Str(zf.NodeKey, s.req.NodeKey.ShortString())

	// Log counts only, NOT actual endpoints/IPs.
	if len(s.req.Endpoints) > 0 {
		e.Int(zf.EndpointsCount, len(s.req.Endpoints))
	}

	// SECURITY: The following fields are intentionally NOT logged:
	// - Endpoints: Client IP addresses and ports
	// - Hostinfo: Device fingerprinting data (use SafeHostinfo separately if needed)
	// - DERPForceWebsockets: Network configuration details
}
