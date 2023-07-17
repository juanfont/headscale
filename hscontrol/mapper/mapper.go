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
)

var debugDumpMapResponsePath = envknob.String("HEADSCALE_DEBUG_DUMP_MAPRESPONSE_PATH")

type Mapper struct {
	db *db.HSDatabase

	privateKey2019 *key.MachinePrivate
	isNoise        bool

	// Configuration
	// TODO(kradalby): figure out if this is the format we want this in
	derpMap          *tailcfg.DERPMap
	baseDomain       string
	dnsCfg           *tailcfg.DNSConfig
	logtail          bool
	randomClientPort bool
}

func NewMapper(
	db *db.HSDatabase,
	privateKey *key.MachinePrivate,
	isNoise bool,
	derpMap *tailcfg.DERPMap,
	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
	logtail bool,
	randomClientPort bool,
) *Mapper {
	return &Mapper{
		db: db,

		privateKey2019: privateKey,
		isNoise:        isNoise,

		derpMap:          derpMap,
		baseDomain:       baseDomain,
		dnsCfg:           dnsCfg,
		logtail:          logtail,
		randomClientPort: randomClientPort,
	}
}

// TODO: Optimise
// As this work continues, the idea is that there will be one Mapper instance
// per node, attached to the open stream between the control and client.
// This means that this can hold a state per machine and we can use that to
// improve the mapresponses sent.
// We could:
// - Keep information about the previous mapresponse so we can send a diff
// - Store hashes
// - Create a "minifier" that removes info not needed for the node

// fullMapResponse is the internal function for generating a MapResponse
// for a machine.
func fullMapResponse(
	pol *policy.ACLPolicy,
	machine *types.Machine,
	peers types.Machines,

	baseDomain string,
	dnsCfg *tailcfg.DNSConfig,
	derpMap *tailcfg.DERPMap,
	logtail bool,
	randomClientPort bool,
) (*tailcfg.MapResponse, error) {
	tailnode, err := tailNode(*machine, pol, dnsCfg, baseDomain)
	if err != nil {
		return nil, err
	}

	rules, sshPolicy, err := policy.GenerateFilterAndSSHRules(
		pol,
		machine,
		peers,
	)
	if err != nil {
		return nil, err
	}

	// Filter out peers that have expired.
	peers = lo.Filter(peers, func(item types.Machine, index int) bool {
		return !item.IsExpired()
	})

	// If there are filter rules present, see if there are any machines that cannot
	// access eachother at all and remove them from the peers.
	if len(rules) > 0 {
		peers = policy.FilterMachinesByACL(machine, peers, rules)
	}

	profiles := generateUserProfiles(machine, peers, baseDomain)

	dnsConfig := generateDNSConfig(
		dnsCfg,
		baseDomain,
		*machine,
		peers,
	)

	tailPeers, err := tailNodes(peers, pol, dnsCfg, baseDomain)
	if err != nil {
		return nil, err
	}

	// Peers is always returned sorted by Node.ID.
	sort.SliceStable(tailPeers, func(x, y int) bool {
		return tailPeers[x].ID < tailPeers[y].ID
	})

	now := time.Now()

	resp := tailcfg.MapResponse{
		Node:  tailnode,
		Peers: tailPeers,

		DERPMap: derpMap,

		DNSConfig: dnsConfig,
		Domain:    baseDomain,

		// Do not instruct clients to collect services we do not
		// support or do anything with them
		CollectServices: "false",

		PacketFilter: policy.ReduceFilterRules(machine, rules),

		UserProfiles: profiles,

		SSHPolicy: sshPolicy,

		ControlTime:  &now,
		KeepAlive:    false,
		OnlineChange: db.OnlineMachineMap(peers),

		Debug: &tailcfg.Debug{
			DisableLogTail:      !logtail,
			RandomizeClientPort: randomClientPort,
		},
	}

	return &resp, nil
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
	machine types.Machine,
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
func addNextDNSMetadata(resolvers []*dnstype.Resolver, machine types.Machine) {
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

// FullMapResponse returns a MapResponse for the given machine.
func (m Mapper) FullMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	peers, err := m.db.ListPeers(machine)
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Msg("Cannot fetch peers")

		return nil, err
	}

	mapResponse, err := fullMapResponse(
		pol,
		machine,
		peers,
		m.baseDomain,
		m.dnsCfg,
		m.derpMap,
		m.logtail,
		m.randomClientPort,
	)
	if err != nil {
		return nil, err
	}

	if m.isNoise {
		return m.marshalMapResponse(mapResponse, machine, mapRequest.Compress)
	}

	return m.marshalMapResponse(mapResponse, machine, mapRequest.Compress)
}

func (m Mapper) KeepAliveResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
) ([]byte, error) {
	resp := m.baseMapResponse(machine)
	resp.KeepAlive = true

	return m.marshalMapResponse(&resp, machine, mapRequest.Compress)
}

func (m Mapper) DERPMapResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	derpMap tailcfg.DERPMap,
) ([]byte, error) {
	resp := m.baseMapResponse(machine)
	resp.DERPMap = &derpMap

	return m.marshalMapResponse(&resp, machine, mapRequest.Compress)
}

func (m Mapper) PeerChangedResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	machineKeys []uint64,
	pol *policy.ACLPolicy,
) ([]byte, error) {
	var err error
	changed := make(types.Machines, len(machineKeys))
	lastSeen := make(map[tailcfg.NodeID]bool)
	for idx, machineKey := range machineKeys {
		peer, err := m.db.GetMachineByID(machineKey)
		if err != nil {
			return nil, err
		}

		changed[idx] = *peer

		// We have just seen the node, let the peers update their list.
		lastSeen[tailcfg.NodeID(peer.ID)] = true
	}

	rules, _, err := policy.GenerateFilterAndSSHRules(
		pol,
		machine,
		changed,
	)
	if err != nil {
		return nil, err
	}

	// Filter out peers that have expired.
	changed = lo.Filter(changed, func(item types.Machine, index int) bool {
		return !item.IsExpired()
	})

	// If there are filter rules present, see if there are any machines that cannot
	// access eachother at all and remove them from the changed.
	if len(rules) > 0 {
		changed = policy.FilterMachinesByACL(machine, changed, rules)
	}

	tailPeers, err := tailNodes(changed, pol, m.dnsCfg, m.baseDomain)
	if err != nil {
		return nil, err
	}

	// Peers is always returned sorted by Node.ID.
	sort.SliceStable(tailPeers, func(x, y int) bool {
		return tailPeers[x].ID < tailPeers[y].ID
	})

	resp := m.baseMapResponse(machine)
	resp.PeersChanged = tailPeers
	resp.PeerSeenChange = lastSeen

	return m.marshalMapResponse(&resp, machine, mapRequest.Compress)
}

func (m Mapper) PeerRemovedResponse(
	mapRequest tailcfg.MapRequest,
	machine *types.Machine,
	removed []tailcfg.NodeID,
) ([]byte, error) {
	resp := m.baseMapResponse(machine)
	resp.PeersRemoved = removed

	return m.marshalMapResponse(&resp, machine, mapRequest.Compress)
}

func (m Mapper) marshalMapResponse(
	resp *tailcfg.MapResponse,
	machine *types.Machine,
	compression string,
) ([]byte, error) {
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

		now := time.Now().Unix()

		mapResponsePath := path.Join(
			mPath,
			fmt.Sprintf("%d-%s-%d.json", now, m.uid, atomic.LoadUint64(&m.seq)),
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

func (m *Mapper) baseMapResponse(machine *types.Machine) tailcfg.MapResponse {
	now := time.Now()

	resp := tailcfg.MapResponse{
		KeepAlive:   false,
		ControlTime: &now,
	}

	// online, err := m.db.ListOnlineMachines(machine)
	// if err == nil {
	// 	resp.OnlineChange = online
	// }

	return resp
}
