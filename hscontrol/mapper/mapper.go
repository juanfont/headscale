package mapper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/views"
	"tailscale.com/util/zstdframe"
)

const (
	nextDNSDoHPrefix           = "https://dns.nextdns.io"
	reservedResponseHeaderSize = 4
	mapperIDLength             = 8
	debugMapResponsePerm       = 0o755
)

var debugDumpMapResponsePath = envknob.String("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH")

// TODO: Optimise
// As this work continues, the idea is that there will be one Mapper instance
// per node, attached to the open stream between the control and client.
// This means that this can hold a state per node and we can use that to
// improve the mapresponses sent.
// We could:
// - Keep information about the previous mapresponse so we can send a diff
// - Store hashes
// - Create a "minifier" that removes info not needed for the node
// - some sort of batching, wait for 5 or 60 seconds before sending

type mapper struct {
	// Configuration
	state   *state.State
	cfg     *types.Config
	batcher Batcher

	created time.Time
}

type patch struct {
	timestamp time.Time
	change    *tailcfg.PeerChange
}

func newMapper(
	cfg *types.Config,
	state *state.State,
) *mapper {
	// uid, _ := util.GenerateRandomStringDNSSafe(mapperIDLength)

	return &mapper{
		state: state,
		cfg:   cfg,

		created: time.Now(),
	}
}

func generateUserProfiles(
	node *types.Node,
	peers types.Nodes,
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.User)
	ids := make([]uint, 0, len(userMap))
	userMap[node.User.ID] = &node.User
	ids = append(ids, node.User.ID)
	for _, peer := range peers {
		userMap[peer.User.ID] = &peer.User
		ids = append(ids, peer.User.ID)
	}

	slices.Sort(ids)
	ids = slices.Compact(ids)
	var profiles []tailcfg.UserProfile
	for _, id := range ids {
		if userMap[id] != nil {
			profiles = append(profiles, userMap[id].TailscaleUserProfile())
		}
	}

	return profiles
}

func generateDNSConfig(
	cfg *types.Config,
	node *types.Node,
) *tailcfg.DNSConfig {
	if cfg.TailcfgDNSConfig == nil {
		return nil
	}

	dnsConfig := cfg.TailcfgDNSConfig.Clone()

	addNextDNSMetadata(dnsConfig.Resolvers, node)

	return dnsConfig
}

// If any nextdns DoH resolvers are present in the list of resolvers it will
// take metadata from the node metadata and instruct tailscale to add it
// to the requests. This makes it possible to identify from which device the
// requests come in the NextDNS dashboard.
//
// This will produce a resolver like:
// `https://dns.nextdns.io/<nextdns-id>?device_name=node-name&device_model=linux&device_ip=100.64.0.1`
func addNextDNSMetadata(resolvers []*dnstype.Resolver, node *types.Node) {
	for _, resolver := range resolvers {
		if strings.HasPrefix(resolver.Addr, nextDNSDoHPrefix) {
			attrs := url.Values{
				"device_name":  []string{node.Hostname},
				"device_model": []string{node.Hostinfo.OS},
			}

			if len(node.IPs()) > 0 {
				attrs.Add("device_ip", node.IPs()[0].String())
			}

			resolver.Addr = fmt.Sprintf("%s?%s", resolver.Addr, attrs.Encode())
		}
	}
}

// fullMapResponse returns a MapResponse for the given node.
func (m *mapper) fullMapResponse(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
	compress string,
	messages ...string,
) ([]byte, error) {
	node, err := m.state.GetNodeByID(nodeID)
	if err != nil {
		return nil, err
	}

	peers, err := m.listPeers(nodeID)
	if err != nil {
		return nil, err
	}

	resp, err := m.baseWithConfigMapResponse(node, capVer)
	if err != nil {
		return nil, err
	}

	err = appendPeerChanges(
		resp,
		true, // full change
		m.state,
		node,
		capVer,
		peers,
		m.cfg,
	)
	if err != nil {
		return nil, err
	}

	return marshalMapResponse(resp, nodeID, compress, messages...)
}

func (m *mapper) derpMapResponse(
	nodeID types.NodeID,
	compress string,
) ([]byte, error) {
	resp := m.baseMapResponse()
	// TODO(kradalby): get this from somewhere, this isnt updated
	resp.DERPMap = m.state.DERPMap()

	return marshalMapResponse(&resp, nodeID, compress)
}

// PeerChangedPatchResponse creates a patch MapResponse with
// incoming update from a state change.
func (m *mapper) peerChangedPatchResponse(
	nodeID types.NodeID,
	compress string,
	changed []*tailcfg.PeerChange,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.PeersChangedPatch = changed

	return marshalMapResponse(&resp, nodeID, compress)
}

// peerRemovedResponse creates a MapResponse indicating that a peer has been removed.
func (m *mapper) peerRemovedResponse(
	nodeID types.NodeID,
	compress string,
	removedNodeID types.NodeID,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.PeersRemoved = []tailcfg.NodeID{removedNodeID.NodeID()}

	return marshalMapResponse(&resp, nodeID, compress)
}

func marshalMapResponse(
	resp *tailcfg.MapResponse,
	nodeID types.NodeID,
	compression string,
	messages ...string,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		return nil, fmt.Errorf("marshalling map response: %w", err)
	}

	if debugDumpMapResponsePath != "" {
		data := map[string]any{
			"Messages":    messages,
			"MapResponse": resp,
		}

		responseType := "keepalive"

		switch {
		case resp.Peers != nil && len(resp.Peers) > 0:
			responseType = "full"
		case resp.Peers == nil && resp.PeersChanged == nil && resp.PeersChangedPatch == nil && resp.DERPMap == nil && !resp.KeepAlive:
			responseType = "self"
		case resp.PeersChanged != nil && len(resp.PeersChanged) > 0:
			responseType = "changed"
		case resp.PeersChangedPatch != nil && len(resp.PeersChangedPatch) > 0:
			responseType = "patch"
		case resp.PeersRemoved != nil && len(resp.PeersRemoved) > 0:
			responseType = "removed"
		}

		body, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			return nil, fmt.Errorf("marshalling map response: %w", err)
		}

		perms := fs.FileMode(debugMapResponsePerm)
		mPath := path.Join(debugDumpMapResponsePath, nodeID.String())
		err = os.MkdirAll(mPath, perms)
		if err != nil {
			panic(err)
		}

		now := time.Now().Format("2006-01-02T15-04-05.999999999")

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf("%s-%s.json", now, responseType),
		)

		log.Trace().Msgf("Writing MapResponse to %s", mapResponsePath)
		err = os.WriteFile(mapResponsePath, body, perms)
		if err != nil {
			panic(err)
		}
	}

	if compression == util.ZstdCompression {
		jsonBody = zstdframe.AppendEncode(nil, jsonBody, zstdframe.FastestCompression)
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(jsonBody)))
	data = append(data, jsonBody...)

	return data, nil
}

// baseMapResponse returns a tailcfg.MapResponse with
// KeepAlive false and ControlTime set to now.
func (m *mapper) baseMapResponse() tailcfg.MapResponse {
	now := time.Now()

	resp := tailcfg.MapResponse{
		KeepAlive:   false,
		ControlTime: &now,
		// TODO(kradalby): Implement PingRequest?
	}

	return resp
}

// baseWithConfigMapResponse returns a tailcfg.MapResponse struct
// with the basic configuration from headscale set.
// It is used in for bigger updates, such as full and lite, not
// incremental.
func (m *mapper) baseWithConfigMapResponse(
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	_, matchers := m.state.Filter()
	tailnode, err := tailNode(
		node.View(), capVer, m.state,
		func(id types.NodeID) []netip.Prefix {
			return policy.ReduceRoutes(node.View(), m.state.GetNodePrimaryRoutes(id), matchers)
		},
		m.cfg)
	if err != nil {
		return nil, err
	}
	resp.Node = tailnode

	resp.DERPMap = m.state.DERPMap()

	resp.Domain = m.cfg.Domain()

	// Do not instruct clients to collect services we do not
	// support or do anything with them
	resp.CollectServices = "false"

	resp.KeepAlive = false

	resp.Debug = &tailcfg.Debug{
		DisableLogTail: !m.cfg.LogTail.Enabled,
	}

	return &resp, nil
}

// listPeers returns peers of node, regardless of any Policy or if the node is expired.
// If no peer IDs are given, all peers are returned.
// If at least one peer ID is given, only these peer nodes will be returned.
func (m *mapper) listPeers(nodeID types.NodeID, peerIDs ...types.NodeID) (types.Nodes, error) {
	peers, err := m.state.ListPeers(nodeID, peerIDs...)
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): Add back online via batcher. This was removed
	// to avoid a circular dependency between the mapper and the notification.
	for _, peer := range peers {
		online := m.batcher.IsConnected(peer.ID)
		peer.IsOnline = &online
	}

	return peers, nil
}

// ListNodes queries the database for either all nodes if no parameters are given
// or for the given nodes if at least one node ID is given as parameter.
func (m *mapper) ListNodes(nodeIDs ...types.NodeID) (types.Nodes, error) {
	nodes, err := m.state.ListNodes(nodeIDs...)
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): Add back online via batcher. This was removed
	// to avoid a circular dependency between the mapper and the notification.
	for _, node := range nodes {
		online := m.batcher.IsConnected(node.ID)
		node.IsOnline = &online
	}

	return nodes, nil
}

// routeFilterFunc is a function that takes a node ID and returns a list of
// netip.Prefixes that are allowed for that node. It is used to filter routes
// from the primary route manager to the node.
type routeFilterFunc func(id types.NodeID) []netip.Prefix

// appendPeerChanges mutates a tailcfg.MapResponse with all the
// necessary changes when peers have changed.
func appendPeerChanges(
	resp *tailcfg.MapResponse,

	fullChange bool,
	state *state.State,
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	changed types.Nodes,
	cfg *types.Config,
) error {
	filter, matchers := state.Filter()

	sshPolicy, err := state.SSHPolicy(node.View())
	if err != nil {
		return err
	}

	// If there are filter rules present, see if there are any nodes that cannot
	// access each-other at all and remove them from the peers.
	var changedViews views.Slice[types.NodeView]
	if len(filter) > 0 {
		changedViews = policy.ReduceNodes(node.View(), changed.ViewSlice(), matchers)
	} else {
		changedViews = changed.ViewSlice()
	}

	profiles := generateUserProfiles(node, changed)

	dnsConfig := generateDNSConfig(cfg, node)

	tailPeers, err := tailNodes(
		changedViews, capVer, state,
		func(id types.NodeID) []netip.Prefix {
			return policy.ReduceRoutes(node.View(), state.GetNodePrimaryRoutes(id), matchers)
		},
		cfg)
	if err != nil {
		return err
	}

	// Peers is always returned sorted by Node.ID.
	sort.SliceStable(tailPeers, func(x, y int) bool {
		return tailPeers[x].ID < tailPeers[y].ID
	})

	if fullChange {
		resp.Peers = tailPeers
	} else {
		resp.PeersChanged = tailPeers
	}
	resp.DNSConfig = dnsConfig
	resp.UserProfiles = profiles
	resp.SSHPolicy = sshPolicy

	// CapVer 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
	// Currently, we do not send incremental package filters, however using the
	// new PacketFilters field and "base" allows us to send a full update when we
	// have to send an empty list, avoiding the hack in the else block.
	resp.PacketFilters = map[string][]tailcfg.FilterRule{
		"base": policy.ReduceFilterRules(node.View(), filter),
	}

	return nil
}
