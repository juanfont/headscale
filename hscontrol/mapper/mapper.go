package mapper

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/state"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/types/change"
	"github.com/rs/zerolog/log"
	"tailscale.com/envknob"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/views"
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

// generateUserProfiles creates user profiles for MapResponse.
func generateUserProfiles(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)
	ids := make([]uint, 0, len(userMap))
	user := node.Owner()
	userID := user.Model().ID
	userMap[userID] = &user
	ids = append(ids, userID)
	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		peerUserID := peerUser.Model().ID
		userMap[peerUserID] = &peerUser
		ids = append(ids, peerUserID)
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
	node types.NodeView,
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
func addNextDNSMetadata(resolvers []*dnstype.Resolver, node types.NodeView) {
	for _, resolver := range resolvers {
		if strings.HasPrefix(resolver.Addr, nextDNSDoHPrefix) {
			attrs := url.Values{
				"device_name":  []string{node.Hostname()},
				"device_model": []string{node.Hostinfo().OS()},
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
) (*tailcfg.MapResponse, error) {
	peers := m.state.ListPeers(nodeID)

	return m.NewMapResponseBuilder(nodeID).
		WithDebugType(fullResponseDebug).
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

func (m *mapper) selfMapResponse(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	ma, err := m.NewMapResponseBuilder(nodeID).
		WithDebugType(selfResponseDebug).
		WithCapabilityVersion(capVer).
		WithSelfNode().
		Build()
	if err != nil {
		return nil, err
	}

	// Set the peers to nil, to ensure the node does not think
	// its getting a new list.
	ma.Peers = nil

	return ma, err
}

// policyChangeResponse creates a MapResponse for policy changes.
// It sends:
// - PeersRemoved for peers that are no longer visible after the policy change
// - PeersChanged for remaining peers (their AllowedIPs may have changed due to policy)
// - Updated PacketFilters
// - Updated SSHPolicy (SSH rules may reference users/groups that changed)
// This avoids the issue where an empty Peers slice is interpreted by Tailscale
// clients as "no change" rather than "no peers".
func (m *mapper) policyChangeResponse(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
	removedPeers []tailcfg.NodeID,
	currentPeers views.Slice[types.NodeView],
) (*tailcfg.MapResponse, error) {
	builder := m.NewMapResponseBuilder(nodeID).
		WithDebugType(policyResponseDebug).
		WithCapabilityVersion(capVer).
		WithPacketFilters().
		WithSSHPolicy()

	if len(removedPeers) > 0 {
		// Convert tailcfg.NodeID to types.NodeID for WithPeersRemoved
		removedIDs := make([]types.NodeID, len(removedPeers))
		for i, id := range removedPeers {
			removedIDs[i] = types.NodeID(id) //nolint:gosec // NodeID types are equivalent
		}

		builder.WithPeersRemoved(removedIDs...)
	}

	// Send remaining peers in PeersChanged - their AllowedIPs may have
	// changed due to the policy update (e.g., different routes allowed).
	if currentPeers.Len() > 0 {
		builder.WithPeerChanges(currentPeers)
	}

	return builder.Build()
}

// buildFromChange builds a MapResponse from a change.Change specification.
// This provides fine-grained control over what gets included in the response.
func (m *mapper) buildFromChange(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
	resp *change.Change,
) (*tailcfg.MapResponse, error) {
	if resp.IsEmpty() {
		return nil, nil //nolint:nilnil // Empty response means nothing to send, not an error
	}

	// If this is a self-update (the changed node is the receiving node),
	// send a self-update response to ensure the node sees its own changes.
	if resp.OriginNode != 0 && resp.OriginNode == nodeID {
		return m.selfMapResponse(nodeID, capVer)
	}

	builder := m.NewMapResponseBuilder(nodeID).
		WithCapabilityVersion(capVer).
		WithDebugType(changeResponseDebug)

	if resp.IncludeSelf {
		builder.WithSelfNode()
	}

	if resp.IncludeDERPMap {
		builder.WithDERPMap()
	}

	if resp.IncludeDNS {
		builder.WithDNSConfig()
	}

	if resp.IncludeDomain {
		builder.WithDomain()
	}

	if resp.IncludePolicy {
		builder.WithPacketFilters()
		builder.WithSSHPolicy()
	}

	if resp.SendAllPeers {
		peers := m.state.ListPeers(nodeID)
		builder.WithUserProfiles(peers)
		builder.WithPeers(peers)
	} else {
		if len(resp.PeersChanged) > 0 {
			peers := m.state.ListPeers(nodeID, resp.PeersChanged...)
			builder.WithUserProfiles(peers)
			builder.WithPeerChanges(peers)
		}

		if len(resp.PeersRemoved) > 0 {
			builder.WithPeersRemoved(resp.PeersRemoved...)
		}
	}

	if len(resp.PeerPatches) > 0 {
		builder.WithPeerChangedPatch(resp.PeerPatches)
	}

	return builder.Build()
}

func writeDebugMapResponse(
	resp *tailcfg.MapResponse,
	t debugType,
	nodeID types.NodeID,
) {
	body, err := json.MarshalIndent(resp, "", "  ")
	if err != nil {
		panic(err)
	}

	perms := fs.FileMode(debugMapResponsePerm)
	mPath := path.Join(debugDumpMapResponsePath, fmt.Sprintf("%d", nodeID))
	err = os.MkdirAll(mPath, perms)
	if err != nil {
		panic(err)
	}

	now := time.Now().Format("2006-01-02T15-04-05.999999999")

	mapResponsePath := path.Join(
		mPath,
		fmt.Sprintf("%s-%s.json", now, t),
	)

	log.Trace().Msgf("Writing MapResponse to %s", mapResponsePath)
	err = os.WriteFile(mapResponsePath, body, perms)
	if err != nil {
		panic(err)
	}
}

func (m *mapper) debugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	if debugDumpMapResponsePath == "" {
		return nil, nil
	}

	return ReadMapResponsesFromDirectory(debugDumpMapResponsePath)
}

func ReadMapResponsesFromDirectory(dir string) (map[types.NodeID][]tailcfg.MapResponse, error) {
	nodes, err := os.ReadDir(dir)
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

		files, err := os.ReadDir(path.Join(dir, node.Name()))
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

			body, err := os.ReadFile(path.Join(dir, node.Name(), file.Name()))
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
