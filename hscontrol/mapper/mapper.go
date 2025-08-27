package mapper

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/netip"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
)

const (
	nextDNSDoHPrefix     = "https://dns.nextdns.io"
	mapperIDLength       = 8
	debugMapResponsePerm = 0o755
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
	messages ...string,
) (*tailcfg.MapResponse, error) {
	peers, err := m.listPeers(nodeID)
	if err != nil {
		return nil, err
	}

	return m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer).
		WithSelfNode().
		WithDERPMap().
		WithDomain().
		WithCollectServicesDisabled().
		WithDebugConfig().
		WithSSHPolicy().
		WithDNSConfig().
		WithUserProfiles(peers).
		WithPacketFilters().
		WithPeers(peers).
		Build()
}

func (m *mapper) derpMapResponse(
	nodeID types.NodeID,
) (*tailcfg.MapResponse, error) {
	return m.NewMapResponseBuilder(nodeID).
		WithDERPMap().
		Build()
}

// PeerChangedPatchResponse creates a patch MapResponse with
// incoming update from a state change.
func (m *mapper) peerChangedPatchResponse(
	nodeID types.NodeID,
	changed []*tailcfg.PeerChange,
) (*tailcfg.MapResponse, error) {
	return m.NewMapResponseBuilder(nodeID).
		WithPeerChangedPatch(changed).
		Build()
}

// peerChangeResponse returns a MapResponse with changed or added nodes.
func (m *mapper) peerChangeResponse(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
	changedNodeID types.NodeID,
) (*tailcfg.MapResponse, error) {
	peers, err := m.listPeers(nodeID, changedNodeID)
	if err != nil {
		return nil, err
	}

	return m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer).
		WithSelfNode().
		WithUserProfiles(peers).
		WithPeerChanges(peers).
		Build()
}

// peerRemovedResponse creates a MapResponse indicating that a peer has been removed.
func (m *mapper) peerRemovedResponse(
	nodeID types.NodeID,
	removedNodeID types.NodeID,
) (*tailcfg.MapResponse, error) {
	return m.NewMapResponseBuilder(nodeID).
		WithPeersRemoved(removedNodeID).
		Build()
}

func writeDebugMapResponse(
	resp *tailcfg.MapResponse,
	node *types.Node,
) {
	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		panic(err)
	}

	perms := fs.FileMode(debugMapResponsePerm)
	mPath := path.Join(debugDumpMapResponsePath, fmt.Sprintf("%d", node.ID))
	err = os.MkdirAll(mPath, perms)
	if err != nil {
		panic(err)
	}

	now := time.Now().Format("2006-01-02T15-04-05.999999999")

	mapResponsePath := path.Join(
		mPath,
		fmt.Sprintf("%s.json", now),
	)

	log.Trace().Msgf("Writing MapResponse to %s", mapResponsePath)
	err = os.WriteFile(mapResponsePath, body, perms)
	if err != nil {
		panic(err)
	}
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

// routeFilterFunc is a function that takes a node ID and returns a list of
// netip.Prefixes that are allowed for that node. It is used to filter routes
// from the primary route manager to the node.
type routeFilterFunc func(id types.NodeID) []netip.Prefix

func (m *mapper) debugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	if debugDumpMapResponsePath == "" {
		return nil, nil
	}

	nodes, err := os.ReadDir(debugDumpMapResponsePath)
	if err != nil {
		return nil, err
	}

	result := make(map[types.NodeID][]tailcfg.MapResponse)
	for _, node := range nodes {
		if !node.IsDir() {
			continue
		}

		nodeIDu, err := strconv.ParseUint(node.Name(), 10, 64)
		if err != nil {
			log.Error().Err(err).Msgf("Parsing node ID from dir %s", node.Name())
			continue
		}

		nodeID := types.NodeID(nodeIDu)

		files, err := os.ReadDir(path.Join(debugDumpMapResponsePath, node.Name()))
		if err != nil {
			log.Error().Err(err).Msgf("Reading dir %s", node.Name())
			continue
		}

		slices.SortStableFunc(files, func(a, b fs.DirEntry) int {
			return strings.Compare(a.Name(), b.Name())
		})

		for _, file := range files {
			if file.IsDir() || !strings.HasSuffix(file.Name(), ".json") {
				continue
			}

			body, err := os.ReadFile(path.Join(debugDumpMapResponsePath, node.Name(), file.Name()))
			if err != nil {
				log.Error().Err(err).Msgf("Reading file %s", file.Name())
				continue
			}

			var resp tailcfg.MapResponse
			err = json.Unmarshal(body, &resp)
			if err != nil {
				log.Error().Err(err).Msgf("Unmarshalling file %s", file.Name())
				continue
			}

			result[nodeID] = append(result[nodeID], resp)
		}
	}

	return result, nil
}
