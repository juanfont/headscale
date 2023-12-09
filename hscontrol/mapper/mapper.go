package mapper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"golang.org/x/exp/maps"
	"tailscale.com/envknob"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
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

type Mapper struct {
	// Configuration
	// TODO(kradalby): figure out if this is the format we want this in
	derpMap          *tailcfg.DERPMap
	baseDomain       string
	dnsCfg           *tailcfg.DNSConfig
	logtail          bool
	randomClientPort bool

	uid     string
	created time.Time
	seq     uint64

	// Map isnt concurrency safe, so we need to ensure
	// only one func is accessing it over time.
	mu      sync.Mutex
	peers   map[uint64]*types.Node
	patches map[uint64][]patch
}

type patch struct {
	timestamp time.Time
	change    *tailcfg.PeerChange
}

func NewMapper(
	node *types.Node,
	peers types.Nodes,
	derpMap *tailcfg.DERPMap,
	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
	logtail bool,
	randomClientPort bool,
) *Mapper {
	log.Debug().
		Caller().
		Str("node", node.Hostname).
		Msg("creating new mapper")

	uid, _ := util.GenerateRandomStringDNSSafe(mapperIDLength)

	return &Mapper{
		derpMap:          derpMap,
		baseDomain:       baseDomain,
		dnsCfg:           dnsCfg,
		logtail:          logtail,
		randomClientPort: randomClientPort,

		uid:     uid,
		created: time.Now(),
		seq:     0,

		// TODO: populate
		peers:   peers.IDMap(),
		patches: make(map[uint64][]patch),
	}
}

func (m *Mapper) String() string {
	return fmt.Sprintf("Mapper: { seq: %d, uid: %s, created: %s }", m.seq, m.uid, m.created)
}

func generateUserProfiles(
	node *types.Node,
	peers types.Nodes,
	baseDomain string,
) []tailcfg.UserProfile {
	userMap := make(map[string]types.User)
	userMap[node.User.Name] = node.User
	for _, peer := range peers {
		userMap[peer.User.Name] = peer.User // not worth checking if already is there
	}

	profiles := []tailcfg.UserProfile{}
	for _, user := range userMap {
		displayName := user.Name

		if baseDomain != "" {
			displayName = fmt.Sprintf("%s@%s", user.Name, baseDomain)
		}

		profiles = append(profiles,
			tailcfg.UserProfile{
				ID:          tailcfg.UserID(user.ID),
				LoginName:   user.Name,
				DisplayName: displayName,
			})
	}

	return profiles
}

func generateDNSConfig(
	base *tailcfg.DNSConfig,
	baseDomain string,
	node *types.Node,
	peers types.Nodes,
) *tailcfg.DNSConfig {
	dnsConfig := base.Clone()

	// if MagicDNS is enabled
	if base != nil && base.Proxied {
		// Only inject the Search Domain of the current user
		// shared nodes should use their full FQDN
		dnsConfig.Domains = append(
			dnsConfig.Domains,
			fmt.Sprintf(
				"%s.%s",
				node.User.Name,
				baseDomain,
			),
		)

		userSet := mapset.NewSet[types.User]()
		userSet.Add(node.User)
		for _, p := range peers {
			userSet.Add(p.User)
		}
		for _, user := range userSet.ToSlice() {
			dnsRoute := fmt.Sprintf("%v.%v", user.Name, baseDomain)
			dnsConfig.Routes[dnsRoute] = nil
		}
	} else {
		dnsConfig = base
	}

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

			if len(node.IPAddresses) > 0 {
				attrs.Add("device_ip", node.IPAddresses[0].String())
			}

			resolver.Addr = fmt.Sprintf("%s?%s", resolver.Addr, attrs.Encode())
		}
	}
}

// fullMapResponse creates a complete MapResponse for a node.
// It is a separate function to make testing easier.
func (m *Mapper) fullMapResponse(
	node *types.Node,
	pol *policy.ACLPolicy,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	peers := nodeMapToList(m.peers)

	resp, err := m.baseWithConfigMapResponse(node, pol, capVer)
	if err != nil {
		return nil, err
	}

	err = appendPeerChanges(
		resp,
		pol,
		node,
		capVer,
		peers,
		peers,
		m.baseDomain,
		m.dnsCfg,
		m.randomClientPort,
	)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// FullMapResponse returns a MapResponse for the given node.
func (m *Mapper) FullMapResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	peers := maps.Keys(m.peers)
	peersWithPatches := maps.Keys(m.patches)
	slices.Sort(peers)
	slices.Sort(peersWithPatches)

	if len(peersWithPatches) > 0 {
		log.Debug().
			Str("node", node.Hostname).
			Uints64("peers", peers).
			Uints64("pending_patches", peersWithPatches).
			Msgf("node requested full map response, but has pending patches")
	}

	resp, err := m.fullMapResponse(node, pol, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, node, mapRequest.Compress)
}

// LiteMapResponse returns a MapResponse for the given node.
// Lite means that the peers has been omitted, this is intended
// to be used to answer MapRequests with OmitPeers set to true.
func (m *Mapper) LiteMapResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	resp, err := m.baseWithConfigMapResponse(node, pol, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, node, mapRequest.Compress)
}

func (m *Mapper) KeepAliveResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.KeepAlive = true

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress)
}

func (m *Mapper) DERPMapResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	derpMap *tailcfg.DERPMap,
) ([]byte, error) {
	m.derpMap = derpMap

	resp := m.baseMapResponse()
	resp.DERPMap = derpMap

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress)
}

func (m *Mapper) PeerChangedResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	changed types.Nodes,
	pol *policy.ACLPolicy,
	messages ...string,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Update our internal map.
	for _, node := range changed {
		if patches, ok := m.patches[node.ID]; ok {
			// preserve online status in case the patch has an outdated one
			online := node.IsOnline

			for _, p := range patches {
				// TODO(kradalby): Figure if this needs to be sorted by timestamp
				node.ApplyPeerChange(p.change)
			}

			// Ensure the patches are not applied again later
			delete(m.patches, node.ID)

			node.IsOnline = online
		}

		m.peers[node.ID] = node
	}

	resp := m.baseMapResponse()

	err := appendPeerChanges(
		&resp,
		pol,
		node,
		mapRequest.Version,
		nodeMapToList(m.peers),
		changed,
		m.baseDomain,
		m.dnsCfg,
		m.randomClientPort,
	)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress, messages...)
}

// PeerChangedPatchResponse creates a patch MapResponse with
// incoming update from a state change.
func (m *Mapper) PeerChangedPatchResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	changed []*tailcfg.PeerChange,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	sendUpdate := false
	// patch the internal map
	for _, change := range changed {
		if peer, ok := m.peers[uint64(change.NodeID)]; ok {
			peer.ApplyPeerChange(change)
			sendUpdate = true
		} else {
			log.Trace().Str("node", node.Hostname).Msgf("Node with ID %s is missing from mapper for Node %s, saving patch for when node is available", change.NodeID, node.Hostname)

			p := patch{
				timestamp: time.Now(),
				change:    change,
			}

			if patches, ok := m.patches[uint64(change.NodeID)]; ok {
				patches := append(patches, p)

				m.patches[uint64(change.NodeID)] = patches
			} else {
				m.patches[uint64(change.NodeID)] = []patch{p}
			}
		}
	}

	if !sendUpdate {
		return nil, nil
	}

	resp := m.baseMapResponse()
	resp.PeersChangedPatch = changed

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress)
}

// TODO(kradalby): We need some integration tests for this.
func (m *Mapper) PeerRemovedResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	removed []tailcfg.NodeID,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Some nodes might have been removed already
	// so we dont want to ask downstream to remove
	// twice, than can cause a panic in tailscaled.
	notYetRemoved := []tailcfg.NodeID{}

	// remove from our internal map
	for _, id := range removed {
		if _, ok := m.peers[uint64(id)]; ok {
			notYetRemoved = append(notYetRemoved, id)
		}

		delete(m.peers, uint64(id))
		delete(m.patches, uint64(id))
	}

	resp := m.baseMapResponse()
	resp.PeersRemoved = notYetRemoved

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress)
}

func (m *Mapper) marshalMapResponse(
	mapRequest tailcfg.MapRequest,
	resp *tailcfg.MapResponse,
	node *types.Node,
	compression string,
	messages ...string,
) ([]byte, error) {
	atomic.AddUint64(&m.seq, 1)

	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal map response")
	}

	if debugDumpMapResponsePath != "" {
		data := map[string]interface{}{
			"Messages":    messages,
			"MapRequest":  mapRequest,
			"MapResponse": resp,
		}

		responseType := "keepalive"

		switch {
		case resp.Peers != nil && len(resp.Peers) > 0:
			responseType = "full"
		case resp.PeersChanged != nil && len(resp.PeersChanged) > 0:
			responseType = "changed"
		case resp.PeersChangedPatch != nil && len(resp.PeersChangedPatch) > 0:
			responseType = "patch"
		case resp.PeersRemoved != nil && len(resp.PeersRemoved) > 0:
			responseType = "removed"
		}

		body, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot marshal map response")
		}

		perms := fs.FileMode(debugMapResponsePerm)
		mPath := path.Join(debugDumpMapResponsePath, node.Hostname)
		err = os.MkdirAll(mPath, perms)
		if err != nil {
			panic(err)
		}

		now := time.Now().UnixNano()

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf("%d-%s-%d-%s.json", now, m.uid, atomic.LoadUint64(&m.seq), responseType),
		)

		log.Trace().Msgf("Writing MapResponse to %s", mapResponsePath)
		err = os.WriteFile(mapResponsePath, body, perms)
		if err != nil {
			panic(err)
		}
	}

	var respBody []byte
	if compression == util.ZstdCompression {
		respBody = zstdEncode(jsonBody)
	} else {
		respBody = jsonBody
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

func zstdEncode(in []byte) []byte {
	encoder, ok := zstdEncoderPool.Get().(*zstd.Encoder)
	if !ok {
		panic("invalid type in sync pool")
	}
	out := encoder.EncodeAll(in, nil)
	_ = encoder.Close()
	zstdEncoderPool.Put(encoder)

	return out
}

var zstdEncoderPool = &sync.Pool{
	New: func() any {
		encoder, err := smallzstd.NewEncoder(
			nil,
			zstd.WithEncoderLevel(zstd.SpeedFastest))
		if err != nil {
			panic(err)
		}

		return encoder
	},
}

// baseMapResponse returns a tailcfg.MapResponse with
// KeepAlive false and ControlTime set to now.
func (m *Mapper) baseMapResponse() tailcfg.MapResponse {
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
func (m *Mapper) baseWithConfigMapResponse(
	node *types.Node,
	pol *policy.ACLPolicy,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	tailnode, err := tailNode(node, capVer, pol, m.dnsCfg, m.baseDomain, m.randomClientPort)
	if err != nil {
		return nil, err
	}
	resp.Node = tailnode

	resp.DERPMap = m.derpMap

	resp.Domain = m.baseDomain

	// Do not instruct clients to collect services we do not
	// support or do anything with them
	resp.CollectServices = "false"

	resp.KeepAlive = false

	resp.Debug = &tailcfg.Debug{
		DisableLogTail: !m.logtail,
	}

	return &resp, nil
}

func nodeMapToList(nodes map[uint64]*types.Node) types.Nodes {
	ret := make(types.Nodes, 0)

	for _, node := range nodes {
		ret = append(ret, node)
	}

	return ret
}

func filterExpiredAndNotReady(peers types.Nodes) types.Nodes {
	return lo.Filter(peers, func(item *types.Node, index int) bool {
		// Filter out nodes that are expired OR
		// nodes that has no endpoints, this typically means they have
		// registered, but are not configured.
		return !item.IsExpired() || len(item.Endpoints) > 0
	})
}

// appendPeerChanges mutates a tailcfg.MapResponse with all the
// necessary changes when peers have changed.
func appendPeerChanges(
	resp *tailcfg.MapResponse,

	pol *policy.ACLPolicy,
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	peers types.Nodes,
	changed types.Nodes,
	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
	randomClientPort bool,
) error {
	fullChange := len(peers) == len(changed)

	rules, sshPolicy, err := policy.GenerateFilterAndSSHRules(
		pol,
		node,
		peers,
	)
	if err != nil {
		return err
	}

	// Filter out peers that have expired.
	changed = filterExpiredAndNotReady(changed)

	// If there are filter rules present, see if there are any nodes that cannot
	// access eachother at all and remove them from the peers.
	if len(rules) > 0 {
		changed = policy.FilterNodesByACL(node, changed, rules)
	}

	profiles := generateUserProfiles(node, changed, baseDomain)

	dnsConfig := generateDNSConfig(
		dnsCfg,
		baseDomain,
		node,
		peers,
	)

	tailPeers, err := tailNodes(changed, capVer, pol, dnsCfg, baseDomain, randomClientPort)
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
	resp.PacketFilter = policy.ReduceFilterRules(node, rules)
	resp.UserProfiles = profiles
	resp.SSHPolicy = sshPolicy

	return nil
}
