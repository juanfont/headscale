package mapper

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"maps"
	"net/url"
	"os"
	"path"
	"regexp"
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
	"tailscale.com/tailcfg/nodecap"
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

	user := node.Owner()
	if !user.Valid() {
		log.Error().
			EmbedObject(node).
			Msg("node has no valid owner, skipping user profile generation")

		return nil
	}

	userMap[user.Model().ID] = &user

	for _, peer := range peers.All() {
		peerUser := peer.Owner()
		if !peerUser.Valid() {
			continue
		}

		userMap[peerUser.Model().ID] = &peerUser
	}

	var profiles []tailcfg.UserProfile

	for _, id := range slices.Sorted(maps.Keys(userMap)) {
		profiles = append(profiles, userMap[id].TailscaleUserProfile())
	}

	return profiles
}

// nextDNSAttrPrefix is the form Tailscale uses for per-node NextDNS profile
// selection: an "attr" entry of "nextdns:<profile-id>" overrides the resolver
// path, and "nextdns:no-device-info" suppresses the metadata-appending step.
// See https://tailscale.com/docs/integrations/nextdns.
const (
	nextDNSAttrPrefix             = "nextdns:"
	nextDNSAttrNoInfo nodecap.Cap = "nextdns:no-device-info"
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

	if domain, ok := node.CertDomain(cfg); ok {
		dnsConfig.CertDomains = []string{domain}
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
	view state.MapView,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	peers := view.Peers()

	return m.NewMapResponseBuilder(view).
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
	view state.MapView,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	ma, err := m.NewMapResponseBuilder(view).
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
// Peers no longer visible after the change are sent separately, see
// [handleNodeChange]. It sends:
//   - PeersChanged for remaining peers (their AllowedIPs may have changed due to policy)
//   - Updated PacketFilters
//   - Updated SSHPolicy (SSH rules may reference users/groups that changed);
//     dropped per connection when unchanged, see [connectionEntry.withSSHPolicyDelta]
//   - The node's own self info, which renders from the same state as peers;
//     dropped per connection when unchanged, see [connectionEntry.withSelfDelta]
//
// DNSConfig is left out: it forces clients into a full netmap rebuild, and
// the node's DNS config inputs arrive with its own [change.SelfUpdate], see
// [state.State.DrainSelfRefreshes].
//
// This avoids the issue where an empty Peers slice is interpreted by Tailscale
// clients as "no change" rather than "no peers".
func (m *mapper) policyChangeResponse(
	view state.MapView,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	currentPeers := view.Peers()
	builder := m.NewMapResponseBuilder(view).
		WithDebugType(policyResponseDebug).
		WithCapabilityVersion(capVer).
		WithPacketFilters().
		WithSSHPolicy().
		WithSelfNode()

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
	view state.MapView,
	capVer tailcfg.CapabilityVersion,
	resp *change.Change,
) (*tailcfg.MapResponse, error) {
	if resp.IsEmpty() {
		return nil, nil //nolint:nilnil // Empty response means nothing to send, not an error
	}

	// If this is a self-update (the changed node is the receiving node),
	// send a self-update response to ensure the node sees its own changes.
	if !resp.IsFull() && resp.OriginNode != 0 && resp.OriginNode == view.Viewer().ID() {
		return m.selfMapResponse(view, capVer)
	}

	builder := m.NewMapResponseBuilder(view).
		WithCapabilityVersion(capVer).
		WithDebugType(changeResponseDebug)

	// Clients forget the logtail instruction when their process restarts, and
	// every stream opens with a full map, so full maps carry it.
	if resp.IsFull() {
		builder.WithDebugConfig()
	}

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
		peers := view.Peers()
		builder.WithUserProfiles(peers)
		builder.WithPeers(peers)
	} else {
		if len(resp.PeersChanged) > 0 {
			peers := view.Peers(resp.PeersChanged...)
			builder.WithUserProfiles(peers)
			builder.WithPeerChanges(peers)
		}

		if len(resp.PeersRemoved) > 0 {
			// Reconnect removals include adjacent peers omitted from the initial
			// render. Only a visible, renderable peer makes a removal hint stale.
			peers, err := builder.buildTailPeers(view.Peers(resp.PeersRemoved...))
			if err != nil {
				return nil, err
			}

			renderable := make(map[tailcfg.NodeID]bool, len(peers))
			for _, peer := range peers {
				renderable[peer.ID] = true
			}

			removed := make([]types.NodeID, 0, len(resp.PeersRemoved))
			for _, id := range resp.PeersRemoved {
				if !renderable[id.NodeID()] {
					removed = append(removed, id)
				}
			}

			builder.WithPeersRemoved(removed...)
		}
	}

	patches := m.filterVisiblePeerPatches(view, resp.PeerPatches)
	if len(patches) > 0 {
		builder.WithPeerChangedPatch(patches)
	}

	if resp.PingRequest != nil {
		builder.WithPingRequest(resp.PingRequest)
	}

	return builder.Build()
}

// filterVisiblePeerPatches drops peer-change patches whose target is not in
// the recipient's NodeStore peer map, the same set
// [MapResponseBuilder.buildTailPeers] is fed from. Without it, online/offline,
// endpoint, and key-expiry patches disclose the existence, presence, and
// addresses of peers the recipient's policy forbids it from accessing.
func (m *mapper) filterVisiblePeerPatches(
	view state.MapView,
	patches []*tailcfg.PeerChange,
) []*tailcfg.PeerChange {
	if len(patches) == 0 {
		return patches
	}

	// Events select fields; values come from the same snapshot as the map.
	peers := view.Peers()

	visible := make(map[tailcfg.NodeID]types.NodeView, peers.Len())
	for _, peer := range peers.All() {
		visible[peer.ID().NodeID()] = peer
	}

	var rendered []*tailcfg.PeerChange

	for _, hint := range patches {
		if hint == nil {
			continue
		}

		peer, ok := visible[hint.NodeID]
		if !ok {
			continue
		}

		patch := &tailcfg.PeerChange{NodeID: hint.NodeID, Cap: hint.Cap, KeySignature: slices.Clone(hint.KeySignature)}
		if hint.DERPRegion != 0 && peer.Hostinfo().Valid() && peer.Hostinfo().NetInfo().Valid() {
			patch.DERPRegion = peer.Hostinfo().NetInfo().PreferredDERP()
		}

		if hint.CapMap != nil {
			patch.CapMap = view.PeerCapMap(peer.ID())
			if patch.CapMap == nil {
				patch.CapMap = tailcfg.NodeCapMap{}
			}
		}

		if len(hint.Endpoints) > 0 {
			patch.Endpoints = peer.Endpoints().AsSlice()
		}

		if hint.Key != nil {
			patch.Key = new(peer.NodeKey())
		}

		if hint.DiscoKey != nil {
			patch.DiscoKey = new(peer.DiscoKey())
		}

		if hint.Online != nil {
			patch.Online = peer.IsOnline().Clone()
		}

		if hint.LastSeen != nil {
			patch.LastSeen = peer.LastSeen().Clone()
		}

		if hint.KeyExpiry != nil {
			patch.KeyExpiry = peer.Expiry().Clone()
			if patch.KeyExpiry == nil {
				patch.KeyExpiry = new(time.Time{})
			}
		}

		rendered = append(rendered, patch)
	}

	return rendered
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
