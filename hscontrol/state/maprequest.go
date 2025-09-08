// Package state provides pure functions for processing MapRequest data.
// These functions are extracted from UpdateNodeFromMapRequest to improve
// testability and maintainability.

package state

import (
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// NetInfoFromMapRequest determines the correct NetInfo to use.
// Returns the NetInfo that should be used for this request.
func NetInfoFromMapRequest(
	nodeID types.NodeID,
	currentHostinfo *tailcfg.Hostinfo,
	reqHostinfo *tailcfg.Hostinfo,
) *tailcfg.NetInfo {
	// If request has NetInfo, use it
	if reqHostinfo != nil && reqHostinfo.NetInfo != nil {
		return reqHostinfo.NetInfo
	}

	// Otherwise, use current NetInfo if available
	if currentHostinfo != nil && currentHostinfo.NetInfo != nil {
		log.Debug().
			Caller().
			Uint64("node.id", nodeID.Uint64()).
			Int("preferredDERP", currentHostinfo.NetInfo.PreferredDERP).
			Msg("using NetInfo from previous Hostinfo in MapRequest")
		return currentHostinfo.NetInfo
	}

	// No NetInfo available anywhere - log for debugging
	var hostname string
	if reqHostinfo != nil {
		hostname = reqHostinfo.Hostname
	} else if currentHostinfo != nil {
		hostname = currentHostinfo.Hostname
	}

	log.Debug().
		Caller().
		Uint64("node.id", nodeID.Uint64()).
		Str("node.hostname", hostname).
		Msg("node sent update but has no NetInfo in request or database")

	return nil
}
