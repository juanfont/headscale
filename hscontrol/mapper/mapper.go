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
) *Mapper {
	uid, _ := util.GenerateRandomStringDNSSafe(mapperIDLength)

	return &Mapper{
		db:      db,
		cfg:     cfg,
		derpMap: derpMap,
		notif:   notif,

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
	pol *policy.ACLPolicy,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp, err := m.baseWithConfigMapResponse(node, pol, capVer)
	if err != nil {
		return nil, err
	}

	err = appendPeerChanges(
		resp,
		true, // full change
		pol,
		node,
		capVer,
		peers,
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
	pol *policy.ACLPolicy,
	messages ...string,
) ([]byte, error) {
	peers, err := m.ListPeers(node.ID)
	if err != nil {
		return nil, err
	}

	resp, err := m.fullMapResponse(node, peers, pol, mapRequest.Version)
	if err != nil {
		return nil, err
	}

	return m.marshalMapResponse(mapRequest, resp, node, mapRequest.Compress, messages...)
}

// ReadOnlyResponse returns a MapResponse for the given node.
// Lite means that the peers has been omitted, this is intended
// to be used to answer MapRequests with OmitPeers set to true.
func (m *Mapper) ReadOnlyMapResponse(
	mapRequest tailcfg.MapRequest,
	node *types.Node,
	pol *policy.ACLPolicy,
	messages ...string,
) ([]byte, error) {
	resp, err := m.baseWithConfigMapResponse(node, pol, mapRequest.Version)
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
	pol *policy.ACLPolicy,
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
		pol,
		node,
		mapRequest.Version,
		peers,
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
	tailnode, err := tailNode(node, mapRequest.Version, pol, m.cfg)
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
	pol *policy.ACLPolicy,
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
	pol *policy.ACLPolicy,
	capVer tailcfg.CapabilityVersion,
) (*tailcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	tailnode, err := tailNode(node, capVer, pol, m.cfg)
	if err != nil {
		return nil, err
	}
	resp.Node = tailnode

	resp.DERPMap = m.derpMap

	resp.Domain = m.cfg.BaseDomain

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
	pol *policy.ACLPolicy,
	node *types.Node,
	capVer tailcfg.CapabilityVersion,
	peers types.Nodes,
	changed types.Nodes,
	cfg *types.Config,
) error {

	packetFilter, err := pol.CompileFilterRules(append(peers, node))
	if err != nil {
		return err
	}

	sshPolicy, err := pol.CompileSSHPolicy(node, peers)
	if err != nil {
		return err
	}

	// If there are filter rules present, see if there are any nodes that cannot
	// access eachother at all and remove them from the peers.
	if len(packetFilter) > 0 {
		changed = policy.FilterNodesByACL(node, changed, packetFilter)
	}

	profiles := generateUserProfiles(node, changed, cfg.BaseDomain)

	dnsConfig := generateDNSConfig(
		cfg.DNSConfig,
		cfg.BaseDomain,
		node,
		peers,
	)

	tailPeers, err := tailNodes(changed, capVer, pol, cfg)
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
	resp.PacketFilter = policy.ReduceFilterRules(node, packetFilter)
	resp.UserProfiles = profiles
	resp.SSHPolicy = sshPolicy

	return nil
}
