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

	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/notifier"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
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
	db      *db.HSDatabase
	cfg     *types.Config
	derpMap *tailcfg.DERPMap
	notif   *notifier.Notifier
	polMan  policy.PolicyManager

	uid     string
	created time.Time
	seq     uint64
}

type patch struct {
	timestamp time.Time
	change    *tailcfg.PeerChange
}

func NewMapper(
	db *db.HSDatabase,
	cfg *types.Config,
	derpMap *tailcfg.DERPMap,
	notif *notifier.Notifier,
	polMan policy.PolicyManager,
) *Mapper {
	uid, _ := util.GenerateRandomStringDNSSafe(mapperIDLength)

	return &Mapper{
		db:      db,
		cfg:     cfg,
		derpMap: derpMap,
		notif:   notif,
		polMan:  polMan,

		uid:     uid,
		created: time.Now(),
		seq:     0,
	}
}

func (m *Mapper) String() string {
	return fmt.Sprintf("Mapper: { seq: %d, uid: %s, created: %s }", m.seq, m.uid, m.created)
}

func generateUserProfiles(
	node *types.Node,
	peers types.Nodes,
) []tailcfg.UserProfile {
	userMap := make(map[uint]types.User)
	userMap[node.User.ID] = node.User
	for _, peer := range peers {
		userMap[peer.User.ID] = peer.User // not worth checking if already is there
	}

	var profiles []tailcfg.UserProfile
	for _, user := range userMap {
		profiles = append(profiles, user.TailscaleUserProfile())
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

// fullMapResponse creates a complete MapResponse for a node.
// It is a separate function to make testing easier.
func (m *Mapper) fullMapResponse(
	node *types.Node,
	peers types.Nodes,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp, err := m.baseWithConfigMapResponse(node, capVer)
	if err != nil {
		return nil, err
	}

	err = appendPeerChanges(
		resp,
		true, // full change
		m.polMan,
		node,
		capVer,
		peers,
		m.cfg,
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
	messages ...string,
) ([]byte, error) {
	peers, err := m.ListPeers(node.ID)
	if err != nil {
		return nil, err
	}

	resp, err := m.fullMapResponse(node, peers, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, node, mapRequest.Compress, messages...)
}

// ReadOnlyMapResponse returns a MapResponse for the given node.
// Lite means that the peers has been omitted, this is intended
// to be used to answer MapRequests with OmitPeers set to true.
func (m *Mapper) ReadOnlyMapResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	messages ...string,
) ([]byte, error) {
	resp, err := m.baseWithConfigMapResponse(node, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, node, mapRequest.Compress, messages...)
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
	changed map[types.NodeID]bool,
	patches []*tailcfg.PeerChange,
	messages ...string,
) ([]byte, error) {
	resp := m.baseMapResponse()

	peers, err := m.ListPeers(node.ID)
	if err != nil {
		return nil, err
	}

	var removedIDs []tailcfg.NodeID
	var changedIDs []types.NodeID
	for nodeID, nodeChanged := range changed {
		if nodeChanged {
			changedIDs = append(changedIDs, nodeID)
		} else {
			removedIDs = append(removedIDs, nodeID.NodeID())
		}
	}

	changedNodes := make(types.Nodes, 0, len(changedIDs))
	for _, peer := range peers {
		if slices.Contains(changedIDs, peer.ID) {
			changedNodes = append(changedNodes, peer)
		}
	}

	err = appendPeerChanges(
		&resp,
		false, // partial change
		m.polMan,
		node,
		mapRequest.Version,
		changedNodes,
		m.cfg,
	)
	if err != nil {
		return nil, err
	}

	resp.PeersRemoved = removedIDs

	// Sending patches as a part of a PeersChanged response
	// is technically not suppose to be done, but they are
	// applied after the PeersChanged. The patch list
	// should _only_ contain Nodes that are not in the
	// PeersChanged or PeersRemoved list and the caller
	// should filter them out.
	//
	// From tailcfg docs:
	// These are applied after Peers* above, but in practice the
	// control server should only send these on their own, without
	// the Peers* fields also set.
	if patches != nil {
		resp.PeersChangedPatch = patches
	}

	// Add the node itself, it might have changed, and particularly
	// if there are no patches or changes, this is a self update.
	tailnode, err := tailNode(node, mapRequest.Version, m.polMan, m.cfg)
	if err != nil {
		return nil, err
	}
	resp.Node = tailnode

	return m.marshalMapResponse(mapRequest, &resp, node, mapRequest.Compress, messages...)
}

// PeerChangedPatchResponse creates a patch MapResponse with
// incoming update from a state change.
func (m *Mapper) PeerChangedPatchResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	changed []*tailcfg.PeerChange,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.PeersChangedPatch = changed

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
		return nil, fmt.Errorf("marshalling map response: %w", err)
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
		mPath := path.Join(debugDumpMapResponsePath, node.Hostname)
		err = os.MkdirAll(mPath, perms)
		if err != nil {
			panic(err)
		}

		now := time.Now().Format("2006-01-02T15-04-05.999999999")

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf("%s-%s-%d-%s.json", now, m.uid, atomic.LoadUint64(&m.seq), responseType),
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
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	tailnode, err := tailNode(node, capVer, m.polMan, m.cfg)
	if err != nil {
		return nil, err
	}
	resp.Node = tailnode

	resp.DERPMap = m.derpMap

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

func (m *Mapper) ListPeers(nodeID types.NodeID) (types.Nodes, error) {
	peers, err := m.db.ListPeers(nodeID)
	if err != nil {
		return nil, err
	}

	for _, peer := range peers {
		online := m.notif.IsLikelyConnected(peer.ID)
		peer.IsOnline = &online
	}

	return peers, nil
}

func nodeMapToList(nodes map[uint64]*types.Node) types.Nodes {
	ret := make(types.Nodes, 0)

	for _, node := range nodes {
		ret = append(ret, node)
	}

	return ret
}

// appendPeerChanges mutates a tailcfg.MapResponse with all the
// necessary changes when peers have changed.
func appendPeerChanges(
	resp *tailcfg.MapResponse,

	fullChange bool,
	polMan policy.PolicyManager,
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	changed types.Nodes,
	cfg *types.Config,
) error {
	filter := polMan.Filter()

	sshPolicy, err := polMan.SSHPolicy(node)
	if err != nil {
		return err
	}

	// If there are filter rules present, see if there are any nodes that cannot
	// access each-other at all and remove them from the peers.
	if len(filter) > 0 {
		changed = policy.FilterNodesByACL(node, changed, filter)
	}

	profiles := generateUserProfiles(node, changed)

	dnsConfig := generateDNSConfig(cfg, node)

	tailPeers, err := tailNodes(changed, capVer, polMan, cfg)
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

	// 81: 2023-11-17: MapResponse.PacketFilters (incremental packet filter updates)
	if capVer >= 81 {
		// Currently, we do not send incremental package filters, however using the
		// new PacketFilters field and "base" allows us to send a full update when we
		// have to send an empty list, avoiding the hack in the else block.
		resp.PacketFilters = map[string][]tailcfg.FilterRule{
			"base": policy.ReduceFilterRules(node, filter),
		}
	} else {
		// This is a hack to avoid sending an empty list of packet filters.
		// Since tailcfg.PacketFilter has omitempty, any empty PacketFilter will
		// be omitted, causing the client to consider it unchanged, keeping the
		// previous packet filter. Worst case, this can cause a node that previously
		// has access to a node to _not_ loose access if an empty (allow none) is sent.
		reduced := policy.ReduceFilterRules(node, filter)
		if len(reduced) > 0 {
			resp.PacketFilter = reduced
		} else {
			resp.PacketFilter = filter
		}
	}

	return nil
}
