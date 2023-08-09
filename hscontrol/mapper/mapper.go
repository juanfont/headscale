package mapper

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	mapset "github.com/deckarep/golang-set/v2"
	"github.com/juanfont/headscale/hscontrol/db"
	"github.com/juanfont/headscale/hscontrol/policy"
	"github.com/juanfont/headscale/hscontrol/types"
	"github.com/juanfont/headscale/hscontrol/util"
	"github.com/klauspost/compress/zstd"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"tailscale.com/envknob"
	"tailscale.com/smallzstd"
	"tailscale.com/tailcfg"
	"tailscale.com/types/dnstype"
	"tailscale.com/types/key"
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
// This means that this can hold a state per machine and we can use that to
// improve the mapresponses sent.
// We could:
// - Keep information about the previous mapresponse so we can send a diff
// - Store hashes
// - Create a "minifier" that removes info not needed for the node

type Mapper struct {
	privateKey2019 *key.MachinePrivate
	isNoise        bool

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
	mu    sync.Mutex
	peers map[uint64]*types.Machine
}

func NewMapper(
	machine *types.Machine,
	peers types.Machines,
	privateKey *key.MachinePrivate,
	isNoise bool,
	derpMap *tailcfg.DERPMap,
	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
	logtail bool,
	randomClientPort bool,
) *Mapper {
	log.Debug().
		Caller().
		Bool("noise", isNoise).
		Str("machine", machine.Hostname).
		Msg("creating new mapper")

	uid, _ := util.GenerateRandomStringDNSSafe(mapperIDLength)

	return &Mapper{
		privateKey2019: privateKey,
		isNoise:        isNoise,

		derpMap:          derpMap,
		baseDomain:       baseDomain,
		dnsCfg:           dnsCfg,
		logtail:          logtail,
		randomClientPort: randomClientPort,

		uid:     uid,
		created: time.Now(),
		seq:     0,

		// TODO: populate
		peers: peers.IDMap(),
	}
}

func (m *Mapper) String() string {
	return fmt.Sprintf("Mapper: { seq: %d, uid: %s, created: %s }", m.seq, m.uid, m.created)
}

func generateUserProfiles(
	machine *types.Machine,
	peers types.Machines,
	baseDomain string,
) []tailcfg.UserProfile {
	userMap := make(map[string]types.User)
	userMap[machine.User.Name] = machine.User
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
	machine *types.Machine,
	peers types.Machines,
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
				machine.User.Name,
				baseDomain,
			),
		)

		userSet := mapset.NewSet[types.User]()
		userSet.Add(machine.User)
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

	addNextDNSMetadata(dnsConfig.Resolvers, machine)

	return dnsConfig
}

// If any nextdns DoH resolvers are present in the list of resolvers it will
// take metadata from the machine metadata and instruct tailscale to add it
// to the requests. This makes it possible to identify from which device the
// requests come in the NextDNS dashboard.
//
// This will produce a resolver like:
// `https://dns.nextdns.io/<nextdns-id>?device_name=node-name&device_model=linux&device_ip=100.64.0.1`
func addNextDNSMetadata(resolvers []*dnstype.Resolver, machine *types.Machine) {
	for _, resolver := range resolvers {
		if strings.HasPrefix(resolver.Addr, nextDNSDoHPrefix) {
			attrs := url.Values{
				"device_name":  []string{machine.Hostname},
				"device_model": []string{machine.HostInfo.OS},
			}

			if len(machine.IPAddresses) > 0 {
				attrs.Add("device_ip", machine.IPAddresses[0].String())
			}

			resolver.Addr = fmt.Sprintf("%s?%s", resolver.Addr, attrs.Encode())
		}
	}
}

// fullMapResponse creates a complete MapResponse for a node.
// It is a separate function to make testing easier.
func (m *Mapper) fullMapResponse(
	machine *types.Machine,
	pol *policy.ACLPolicy,
) (*tailcfg.MapResponse, error) {
	peers := machineMapToList(m.peers)

	resp, err := m.baseWithConfigMapResponse(machine, pol)
	if err != nil {
		return nil, err
	}

	// TODO(kradalby): Move this into appendPeerChanges?
	resp.OnlineChange = db.OnlineMachineMap(peers)

	err = appendPeerChanges(
		resp,
		pol,
		machine,
		peers,
		peers,
		m.baseDomain,
		m.dnsCfg,
	)
	if err != nil {
		return nil, err
	}

	return resp, nil
}

// FullMapResponse returns a MapResponse for the given machine.
func (m *Mapper) FullMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	resp, err := m.fullMapResponse(machine, pol)
	if err != nil {
		return nil, err
	}

	if m.isNoise {
		return m.marshalMapResponse(mapRequest, resp, machine, mapRequest.Compress)
	}

	return m.marshalMapResponse(mapRequest, resp, machine, mapRequest.Compress)
}

// LiteMapResponse returns a MapResponse for the given machine.
// Lite means that the peers has been omitted, this is intended
// to be used to answer MapRequests with OmitPeers set to true.
func (m *Mapper) LiteMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	resp, err := m.baseWithConfigMapResponse(machine, pol)
	if err != nil {
		return nil, err
	}

	if m.isNoise {
		return m.marshalMapResponse(mapRequest, resp, machine, mapRequest.Compress)
	}

	return m.marshalMapResponse(mapRequest, resp, machine, mapRequest.Compress)
}

func (m *Mapper) KeepAliveResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.KeepAlive = true

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) DERPMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	derpMap tailcfg.DERPMap,
) ([]byte, error) {
	resp := m.baseMapResponse()
	resp.DERPMap = &derpMap

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) PeerChangedResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	changed types.Machines,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	lastSeen := make(map[tailcfg.NodeID]bool)

	// Update our internal map.
	for _, machine := range changed {
		m.peers[machine.ID] = machine

		// We have just seen the node, let the peers update their list.
		lastSeen[tailcfg.NodeID(machine.ID)] = true
	}

	resp := m.baseMapResponse()

	err := appendPeerChanges(
		&resp,
		pol,
		machine,
		machineMapToList(m.peers),
		changed,
		m.baseDomain,
		m.dnsCfg,
	)
	if err != nil {
		return nil, err
	}

	// resp.PeerSeenChange = lastSeen

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) PeerRemovedResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	removed []tailcfg.NodeID,
) ([]byte, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// remove from our internal map
	for _, id := range removed {
		delete(m.peers, uint64(id))
	}

	resp := m.baseMapResponse()
	resp.PeersRemoved = removed

	return m.marshalMapResponse(mapRequest, &resp, machine, mapRequest.Compress)
}

func (m *Mapper) marshalMapResponse(
	mapRequest tailcfg.MapRequest,
	resp *tailcfg.MapResponse,
	machine *types.Machine,
	compression string,
) ([]byte, error) {
	atomic.AddUint64(&m.seq, 1)

	var machineKey key.MachinePublic
	err := machineKey.UnmarshalText([]byte(util.MachinePublicKeyEnsurePrefix(machine.MachineKey)))
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot parse client key")

		return nil, err
	}

	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal map response")
	}

	if debugDumpMapResponsePath != "" {
		data := map[string]interface{}{
			"MapRequest":  mapRequest,
			"MapResponse": resp,
		}

		body, err := json.Marshal(data)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot marshal map response")
		}

		perms := fs.FileMode(debugMapResponsePerm)
		mPath := path.Join(debugDumpMapResponsePath, machine.Hostname)
		err = os.MkdirAll(mPath, perms)
		if err != nil {
			panic(err)
		}

		now := time.Now().UnixNano()

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf("%d-%s-%d.json", atomic.LoadUint64(&m.seq), m.uid, now),
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
		if !m.isNoise { // if legacy protocol
			respBody = m.privateKey2019.SealTo(machineKey, respBody)
		}
	} else {
		if !m.isNoise { // if legacy protocol
			respBody = m.privateKey2019.SealTo(machineKey, jsonBody)
		} else {
			respBody = jsonBody
		}
	}

	data := make([]byte, reservedResponseHeaderSize)
	binary.LittleEndian.PutUint32(data, uint32(len(respBody)))
	data = append(data, respBody...)

	return data, nil
}

// MarshalResponse takes an Tailscale Response, marhsal it to JSON.
// If isNoise is set, then the JSON body will be returned
// If !isNoise and privateKey2019 is set, the JSON body will be sealed in a Nacl box.
func MarshalResponse(
	resp interface{},
	isNoise bool,
	privateKey2019 *key.MachinePrivate,
	machineKey key.MachinePublic,
) ([]byte, error) {
	jsonBody, err := json.Marshal(resp)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot marshal response")

		return nil, err
	}

	if !isNoise && privateKey2019 != nil {
		return privateKey2019.SealTo(machineKey, jsonBody), nil
	}

	return jsonBody, nil
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
	}

	return resp
}

// baseWithConfigMapResponse returns a tailcfg.MapResponse struct
// with the basic configuration from headscale set.
// It is used in for bigger updates, such as full and lite, not
// incremental.
func (m *Mapper) baseWithConfigMapResponse(
	machine *types.Machine,
	pol *policy.ACLPolicy,
) (*tailcfg.MapResponse, error) {
	resp := m.baseMapResponse()

	tailnode, err := tailNode(machine, pol, m.dnsCfg, m.baseDomain)
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
		DisableLogTail:      !m.logtail,
		RandomizeClientPort: m.randomClientPort,
	}

	return &resp, nil
}

func machineMapToList(machines map[uint64]*types.Machine) types.Machines {
	ret := make(types.Machines, 0)

	for _, machine := range machines {
		ret = append(ret, machine)
	}

	return ret
}

func filterExpiredAndNotReady(peers types.Machines) types.Machines {
	return lo.Filter(peers, func(item *types.Machine, index int) bool {
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
	machine *types.Machine,
	peers types.Machines,
	changed types.Machines,
	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
) error {
	fullChange := len(peers) == len(changed)

	rules, sshPolicy, err := policy.GenerateFilterAndSSHRules(
		pol,
		machine,
		peers,
	)
	if err != nil {
		return err
	}

	// Filter out peers that have expired.
	changed = filterExpiredAndNotReady(changed)

	// If there are filter rules present, see if there are any machines that cannot
	// access eachother at all and remove them from the peers.
	if len(rules) > 0 {
		changed = policy.FilterMachinesByACL(machine, changed, rules)
	}

	profiles := generateUserProfiles(machine, changed, baseDomain)

	dnsConfig := generateDNSConfig(
		dnsCfg,
		baseDomain,
		machine,
		peers,
	)

	tailPeers, err := tailNodes(changed, pol, dnsCfg, baseDomain)
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
	resp.PacketFilter = policy.ReduceFilterRules(machine, rules)
	resp.UserProfiles = profiles
	resp.SSHPolicy = sshPolicy

	return nil
}
