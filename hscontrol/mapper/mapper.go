package mapper

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/juanfont/headscale/hscontrol/policy"
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
	batcher *Batcher

	created time.Time
}

//nolint:unused
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

// generateUserProfiles creates user profiles for [tailcfg.MapResponse].
func generateUserProfiles(
	node types.NodeView,
	peers views.Slice[types.NodeView],
) []tailcfg.UserProfile {
	userMap := make(map[uint]*types.UserView)
	ids := make([]uint, 0, len(userMap))

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userID := user.Model().ID
	userMap[userID] = &user
	ids = append(ids, userID)

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

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

// nextDNSAttrPrefix is the form Tailscale uses for per-node NextDNS profile
// selection: an "attr" entry of "nextdns:<profile-id>" overrides the resolver
// path, and "nextdns:no-device-info" suppresses the metadata-appending step.
// See https://tailscale.com/docs/integrations/nextdns.
const (
	nextDNSAttrPrefix                        = "nextdns:"
	nextDNSAttrNoInfo tailcfg.NodeCapability = "nextdns:no-device-info"
)

// nextDNSProfileRE bounds the characters accepted in a `nextdns:<profile>`
// suffix. NextDNS profile IDs are short alphanumeric strings; restricting
// to that charset prevents a policy author from injecting `?`, `/`, `@`,
// or `..` into the resolver URL via a crafted cap name.
var nextDNSProfileRE = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

func generateDNSConfig(
	cfg *types.Config,
	node types.NodeView,
	capMap tailcfg.NodeCapMap,
) *tailcfg.DNSConfig {
	dnsConfig := cfg.CloneTailcfgDNSConfig()
	if dnsConfig == nil {
		return nil
	}

	profile := nextDNSProfileFromCapMap(capMap)
	if profile != "" {
		applyNextDNSProfile(dnsConfig.Resolvers, profile)
		applyNextDNSProfile(dnsConfig.FallbackResolvers, profile)

		for suffix, rs := range dnsConfig.Routes {
			applyNextDNSProfile(rs, profile)
			dnsConfig.Routes[suffix] = rs
		}
	}

	if _, suppressMetadata := capMap[nextDNSAttrNoInfo]; !suppressMetadata {
		addNextDNSMetadata(dnsConfig.Resolvers, node)
		addNextDNSMetadata(dnsConfig.FallbackResolvers, node)

		for suffix, rs := range dnsConfig.Routes {
			addNextDNSMetadata(rs, node)
			dnsConfig.Routes[suffix] = rs
		}
	}

	return dnsConfig
}

// nextDNSProfileFromCapMap returns the policy-selected
// `nextdns:<profile>` value on the node, or the empty string when none
// is set or the cap is malformed. The reserved
// `nextdns:no-device-info` string is not a profile — it controls
// metadata appending and is handled separately.
//
// The profile pick is deterministic across reloads: cap keys are
// gathered, sorted, and the first valid profile wins. Map iteration
// order in Go is randomised, so taking the literal first match would
// cause the chosen profile to flip between reloads when a node has
// multiple `nextdns:` caps. The profile string is also validated
// against [nextDNSProfileRE] so a crafted cap cannot inject path or
// query characters into the resolver URL.
func nextDNSProfileFromCapMap(capMap tailcfg.NodeCapMap) string {
	if len(capMap) == 0 {
		return ""
	}

	candidates := make([]string, 0, len(capMap))

	for cap := range capMap {
		if cap == nextDNSAttrNoInfo {
			continue
		}

		profile, ok := strings.CutPrefix(string(cap), nextDNSAttrPrefix)
		if !ok || profile == "" {
			continue
		}

		if !nextDNSProfileRE.MatchString(profile) {
			log.Warn().
				Str("cap", string(cap)).
				Msg("nextdns profile rejected: must match [A-Za-z0-9._-]{1,64}")

			continue
		}

		candidates = append(candidates, profile)
	}

	if len(candidates) == 0 {
		return ""
	}

	slices.Sort(candidates)

	return candidates[0]
}

// nextDNSDoHHost matches a NextDNS DoH resolver address. The check is
// anchored on the host segment so a typo-squatted operator-configured
// resolver such as `https://dns.nextdns.io.attacker.example/x` does
// not slip through.
func nextDNSDoHHost(addr string) bool {
	return addr == nextDNSDoHPrefix ||
		strings.HasPrefix(addr, nextDNSDoHPrefix+"/") ||
		strings.HasPrefix(addr, nextDNSDoHPrefix+"?")
}

// applyNextDNSProfile rewrites every NextDNS DoH resolver to point at
// the given profile, dropping any existing profile path or query. Per
// the Tailscale spec the per-node profile overrides the global value,
// so the rewrite is unconditional rather than additive.
func applyNextDNSProfile(resolvers []*dnstype.Resolver, profile string) {
	for _, resolver := range resolvers {
		if !nextDNSDoHHost(resolver.Addr) {
			continue
		}

		resolver.Addr = nextDNSDoHPrefix + "/" + profile
	}
}

// addNextDNSMetadata appends device metadata as a query string to
// every NextDNS DoH resolver. Existing query parameters on the
// resolver address are preserved by parsing the URL and merging into
// its [url.URL.RawQuery] rather than concatenating with `?`.
func addNextDNSMetadata(resolvers []*dnstype.Resolver, node types.NodeView) {
	for _, resolver := range resolvers {
		if !nextDNSDoHHost(resolver.Addr) {
			continue
		}

		u, err := url.Parse(resolver.Addr)
		if err != nil {
			continue
		}

		q := u.Query()
		q.Set("device_name", node.Hostname())

		// Guard Hostinfo().Valid() before dereferencing OS(): a node loaded
		// from a legacy NULL host_info row has a nil Hostinfo, and OS() would
		// panic. Mirrors the .Valid() guard in RequestTags/TailNode.
		if node.Hostinfo().Valid() {
			q.Set("device_model", node.Hostinfo().OS())
		}

		if ips := node.IPs(); len(ips) > 0 {
			q.Set("device_ip", ips[0].String())
		}

		u.RawQuery = q.Encode()
		resolver.Addr = u.String()
	}
}

// fullMapResponse returns a [tailcfg.MapResponse] for the given node.
//
//nolint:unused
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

// policyChangeResponse creates a [tailcfg.MapResponse] for policy changes.
// It sends:
//   - PeersRemoved for peers that are no longer visible after the policy change
//   - PeersChanged for remaining peers (their AllowedIPs may have changed due to policy)
//   - Updated PacketFilters
//   - Updated SSHPolicy (SSH rules may reference users/groups that changed)
//   - DNSConfig so the client's resolver state stays anchored even when a
//     policy-triggered wgengine reconfigure races a netmon LinkChange (the
//     LinkChange handler reapplies dns.Manager.Set with the engine's
//     lastDNSConfig; if that snapshot is stale, the OS resolver loses the
//     MagicDNS reverse-DNS routes and Nameservers and curl-by-FQDN stops
//     resolving for the rest of the policy window).
//   - Optionally, the node's own self info (when includeSelf is true)
//
// This avoids the issue where an empty Peers slice is interpreted by Tailscale
// clients as "no change" rather than "no peers".
// When includeSelf is true, the node's self info is included so that a node
// whose own attributes changed (e.g., tags via admin API) sees its updated
// self info along with the new packet filters.
func (m *mapper) policyChangeResponse(
	nodeID types.NodeID,
	capVer tailcfg.CapabilityVersion,
	removedPeers []tailcfg.NodeID,
	currentPeers views.Slice[types.NodeView],
	includeSelf bool,
) (*tailcfg.MapResponse, error) {
	builder := m.NewMapResponseBuilder(nodeID).
		WithDebugType(policyResponseDebug).
		WithCapabilityVersion(capVer).
		WithDNSConfig().
		WithPacketFilters().
		WithSSHPolicy()

	if includeSelf {
		builder = builder.WithSelfNode()
	}

	if len(removedPeers) > 0 {
		// Convert [tailcfg.NodeID] to [types.NodeID] for [MapResponseBuilder.WithPeersRemoved]
		removedIDs := make([]types.NodeID, len(removedPeers))
		for i, id := range removedPeers {
			removedIDs[i] = types.NodeID(id) //nolint:gosec // NodeID types are equivalent
		}

		builder.WithPeersRemoved(removedIDs...)
	}

	// Send remaining peers in PeersChanged - their AllowedIPs may have
	// changed due to the policy update (e.g., different routes allowed).
	// Cross-user peers must also carry their user profile, otherwise the
	// client's netmap shows the peer without a UserProfiles[user] entry.
	if currentPeers.Len() > 0 {
		builder.WithUserProfiles(currentPeers)
		builder.WithPeerChanges(currentPeers)
	}

	return builder.Build()
}

// buildFromChange builds a [tailcfg.MapResponse] from a [change.Change] specification.
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
			builder.WithUserProfiles(m.filterVisibleNodes(nodeID, peers))
			builder.WithPeerChanges(peers)
		}

		if len(resp.PeersRemoved) > 0 {
			builder.WithPeersRemoved(resp.PeersRemoved...)
		}
	}

	patches := m.filterVisiblePeerPatches(nodeID, resp.PeerPatches)
	if len(patches) > 0 {
		builder.WithPeerChangedPatch(patches)
	}

	if resp.PingRequest != nil {
		builder.WithPingRequest(resp.PingRequest)
	}

	return builder.Build()
}

// visiblePeerIDs returns the set of peer node IDs the recipient may see under
// the current policy. It is the single visibility decision shared by the
// incremental peer-change and user-profile paths, computed from the same live
// per-node matchers and [policy.ReduceNodes] filter that
// [MapResponseBuilder.buildTailPeers] applies to full peer objects, so the
// paths cannot drift. The snapshot peer map ([NodeStore.ListPeers]) is used
// only as the candidate set, matching buildTailPeers; the live policy decides
// visibility because the snapshot is not rebuilt on policy changes.
//
// ok is false when the node or its matchers cannot be resolved; callers must
// then fail closed (emit nothing) rather than risk leaking forbidden peers.
func (m *mapper) visiblePeerIDs(nodeID types.NodeID) (map[tailcfg.NodeID]struct{}, bool) {
	node, ok := m.state.GetNodeByID(nodeID)
	if !ok {
		return nil, false
	}

	matchers, err := m.state.MatchersForNode(node)
	if err != nil {
		return nil, false
	}

	peers := m.state.ListPeers(nodeID)

	// No matchers means no policy restrictions, so every peer is visible —
	// the same default buildTailPeers applies.
	if len(matchers) > 0 {
		peers = policy.ReduceNodes(node, peers, matchers)
	}

	// Key by tailcfg.NodeID so the peer-patch path can look up by patch.NodeID
	// directly, avoiding an unchecked int64->uint64 conversion.
	visible := make(map[tailcfg.NodeID]struct{}, peers.Len())
	for _, peer := range peers.All() {
		visible[peer.ID().NodeID()] = struct{}{}
	}

	return visible, true
}

// filterVisiblePeerPatches drops peer-change patches whose target peer the
// recipient cannot see under the ACL policy. Without it, online/offline,
// endpoint, and key-expiry patches disclose the existence, presence, and
// addresses of peers the recipient's policy forbids it from accessing.
func (m *mapper) filterVisiblePeerPatches(
	nodeID types.NodeID,
	patches []*tailcfg.PeerChange,
) []*tailcfg.PeerChange {
	if len(patches) == 0 {
		return patches
	}

	visible, ok := m.visiblePeerIDs(nodeID)
	if !ok {
		// Fail closed: if visibility cannot be resolved, send no patches.
		return nil
	}

	var filtered []*tailcfg.PeerChange

	for _, patch := range patches {
		if _, vis := visible[patch.NodeID]; vis {
			filtered = append(filtered, patch)
		}
	}

	return filtered
}

// filterVisibleNodes restricts a peer slice to the nodes the recipient can see
// under the ACL policy. It guards UserProfiles on the incremental PeersChanged
// path, which receives an unfiltered node slice and would otherwise leak the
// identities of users whose nodes the recipient cannot access.
func (m *mapper) filterVisibleNodes(
	nodeID types.NodeID,
	peers views.Slice[types.NodeView],
) views.Slice[types.NodeView] {
	visible, ok := m.visiblePeerIDs(nodeID)
	if !ok {
		// Fail closed: emit no peer user profiles rather than risk a leak.
		return views.SliceOf([]types.NodeView{})
	}

	var filtered []types.NodeView

	for _, peer := range peers.All() {
		if _, vis := visible[peer.ID().NodeID()]; vis {
			filtered = append(filtered, peer)
		}
	}

	return views.SliceOf(filtered)
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

	log.Trace().Msgf("writing MapResponse to %s", mapResponsePath)

	err = os.WriteFile(mapResponsePath, body, perms)
	if err != nil {
		panic(err)
	}
}

func (m *mapper) debugMapResponses() (map[types.NodeID][]tailcfg.MapResponse, error) {
	if debugDumpMapResponsePath == "" {
		return nil, nil //nolint:nilnil // intentional: no data when debug path not set
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
			log.Error().Err(err).Msgf("parsing node ID from dir %s", node.Name())
			continue
		}

		nodeID := types.NodeID(nodeIDu)

		files, err := os.ReadDir(path.Join(dir, node.Name()))
		if err != nil {
			log.Error().Err(err).Msgf("reading dir %s", node.Name())
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
				log.Error().Err(err).Msgf("reading file %s", file.Name())
				continue
			}

			var resp tailcfg.MapResponse

			err = json.Unmarshal(body, &resp)
			if err != nil {
				log.Error().Err(err).Msgf("unmarshalling file %s", file.Name())
				continue
			}

			result[nodeID] = append(result[nodeID], resp)
		}
	}

	return result, nil
}
