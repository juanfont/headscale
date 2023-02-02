package headscale

import (
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

func (h *Headscale) generateMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *Machine,
) (*tailcfg.MapResponse, error) {
	log.Trace().
		Str("func", "generateMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		Msg("Creating Map response")
	node, err := h.toNode(*machine, h.cfg.BaseDomain, h.cfg.DNSConfig)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot convert to node")

		return nil, err
	}

	peers, err := h.getValidPeers(machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	profiles := h.getMapResponseUserProfiles(*machine, peers)

	nodePeers, err := h.toNodes(peers, h.cfg.BaseDomain, h.cfg.DNSConfig)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Failed to convert peers to Tailscale nodes")

		return nil, err
	}

	dnsConfig := getMapResponseDNSConfig(
		h.cfg.DNSConfig,
		h.cfg.BaseDomain,
		*machine,
		peers,
	)

	now := time.Now()

	resp := tailcfg.MapResponse{
		KeepAlive: false,
		Node:      node,

		// TODO: Only send if updated
		DERPMap: h.DERPMap,

		// TODO: Only send if updated
		Peers: nodePeers,

		// TODO(kradalby): Implement:
		// https://github.com/tailscale/tailscale/blob/main/tailcfg/tailcfg.go#L1351-L1374
		// PeersChanged
		// PeersRemoved
		// PeersChangedPatch
		// PeerSeenChange
		// OnlineChange

		// TODO: Only send if updated
		DNSConfig: dnsConfig,

		// TODO: Only send if updated
		Domain: h.cfg.BaseDomain,

		// TODO: Only send if updated
		PacketFilter: h.aclRules,

		UserProfiles: profiles,

		// TODO: Only send if updated
		SSHPolicy: h.sshPolicy,

		ControlTime: &now,

		Debug: &tailcfg.Debug{
			DisableLogTail:      !h.cfg.LogTail.Enabled,
			RandomizeClientPort: h.cfg.RandomizeClientPort,
		},
	}

	log.Trace().
		Str("func", "generateMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	return &resp, nil
}
