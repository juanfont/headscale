package hscontrol

import (
	"time"

	"github.com/rs/zerolog/log"
	"tailscale.com/tailcfg"
)

// generateMapResponse generate a map response message for this machine.
//
// streamState is persistent state maintained across a stream of mapResponse messages.
// For first message in stream, send the address of a zero-initialized struct,
// then send the same address in subsequent messages to enable sending of delta-only messages.
func (h *Headscale) generateMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *Machine,
	streamState *mapResponseStreamState,
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

	toNodes := func(machines Machines) ([]*tailcfg.Node, error) {
		return h.toNodes(machines, h.cfg.BaseDomain, h.cfg.DNSConfig)
	}
	resp, err = applyMapResponseDelta(resp, streamState, peers, toNodes)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "generateMapResponse").
			Err(err).
			Msg("Cannot apply map response deltas")

		return nil, err
	}

	log.Trace().
		Str("func", "generateMapResponse").
		Str("machine", mapRequest.Hostinfo.Hostname).
		// Interface("payload", resp).
		Msgf("Generated map response: %s", tailMapResponseToString(resp))

	return &resp, nil
}

// mapResponseStreamState tracks state associated with a stream of MapResponse messages,
// which may optionally send only deltas from the previous message.
type mapResponseStreamState struct {
	// peersByID is the peers sent in the last stream message,
	// for comparison in generating deltas in the new message.
	peersByID map[uint64]Machine
}

// applyMapResponseDelta returns a modified MapResponse
// with fields modified which make use of delta (send on changes).
//
// mapResponse the current mapResponse with delta fields not set.
//
// streamState is persistent state maintained across a stream of mapResponse messages.
// For first message in stream, send the address of a zero-initialized struct,
// then send the same address in subsequent messages to enable sending of delta-only messages.
//
// currentPeers list of peers currently available for the node that this mapResponse is for.
//
// toNodes a function to convert the Headscale Machines structure to Tailscale Nodes structure.
func applyMapResponseDelta(
	mapResponse tailcfg.MapResponse,
	streamState *mapResponseStreamState,
	currentPeers Machines,
	toNodes func(Machines) ([]*tailcfg.Node, error)) (tailcfg.MapResponse, error,
) {
	// Peer deltas
	currentPeersByID := machinesByID(currentPeers)
	if streamState.peersByID == nil {
		// First message, send full peers list
		nodePeers, err := toNodes(currentPeers)
		if err != nil {
			return tailcfg.MapResponse{}, err
		}
		mapResponse.Peers = nodePeers
	} else {
		// Update PeersChanged with any peers which were removed or changed
		var peersChanged []Machine
		for id, peer := range currentPeersByID {
			previousPeer, hadPrevious := streamState.peersByID[id]
			if !hadPrevious || previousPeer.LastSuccessfulUpdate.Before(*peer.LastSuccessfulUpdate) {
				peersChanged = append(peersChanged, peer)
			}
		}
		nodesChanged, err := toNodes(peersChanged)
		if err != nil {
			return tailcfg.MapResponse{}, err
		}
		mapResponse.PeersChanged = nodesChanged

		// Update PeersRemoved with any peers which are no longer present
		for id := range streamState.peersByID {
			if _, has := currentPeersByID[id]; !has {
				mapResponse.PeersRemoved = append(mapResponse.PeersRemoved, tailcfg.NodeID(id))
			}
		}

		// TODO(kallen): Also Implement the following deltas for even smaller
		// message sizes:
		//
		// PeersChangedPatch
		// PeerSeenChange
		// OnlineChange
	}
	// Update previous peers list for next message in stream
	streamState.peersByID = currentPeersByID

	return mapResponse, nil
}
