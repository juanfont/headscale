package hscontrol

import (
	"time"

	"github.com/juanfont/headscale/hscontrol/util"
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
	node, err := h.db.toNode(*machine, h.aclPolicy, h.cfg.BaseDomain, h.cfg.DNSConfig)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot convert to node")

		return nil, err
	}

	peers, err := h.db.getValidPeers(h.aclPolicy, h.aclRules, machine)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	profiles := h.db.getMapResponseUserProfiles(*machine, peers)

	nodePeers, err := h.db.toNodes(peers, h.aclPolicy, h.cfg.BaseDomain, h.cfg.DNSConfig)
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

		// Do not instruct clients to collect services, we do not
		// support or do anything with them
		CollectServices: "false",

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
		Msgf("Generated map response: %s", util.TailMapResponseToString(resp))

	return &resp, nil
}
