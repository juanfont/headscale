package headscale

import (
	"database/sql/driver"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	v1 "github.com/juanfont/headscale/gen/go/headscale/v1"
	"github.com/rs/zerolog/log"
	"github.com/samber/lo"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gorm.io/gorm"
	"tailscale.com/tailcfg"
	"tailscale.com/types/key"
)

const (
	ErrNodeNotFound                  = Error("node not found")
	ErrNodeRouteIsNotAvailable       = Error("route is not available on node ")
	ErrNodeAddressesInvalid          = Error("failed to parse node addresses")
	ErrNodeNotFoundRegistrationCache = Error(
		"node not found in registration cache",
	)
	ErrCouldNotConvertNodeInterface = Error("failed to convert node interface")
	ErrHostnameTooLong              = Error("Hostname too long")
	ErrDifferentRegisteredUser      = Error(
		"node was previously registered with a different user",
	)
	NodeGivenNameHashLength = 8
	NodeGivenNameTrimSize   = 2
)

const (
	maxHostnameLength = 255
)

// Node is a Headscale client.
type Node struct {
	ID          uint64 `gorm:"primary_key"`
	MachineKey  string `gorm:"type:varchar(64);unique_index"`
	NodeKey     string
	DiscoKey    string
	IPAddresses NodeAddresses

	// Hostname represents the name given by the Tailscale
	// client during registration
	Hostname string

	// Givenname represents either:
	// a DNS normalized version of Hostname
	// a valid name set by the User
	//
	// GivenName is the name used in all DNS related
	// parts of headscale.
	GivenName string `gorm:"type:varchar(63);unique_index"`
	UserID    uint
	User      User `gorm:"foreignKey:UserID"`

	RegisterMethod string

	ForcedTags StringList

	// TODO(kradalby): This seems like irrelevant information?
	AuthKeyID uint
	AuthKey   *PreAuthKey

	LastSeen             *time.Time
	LastSuccessfulUpdate *time.Time
	Expiry               *time.Time

	HostInfo  HostInfo
	Endpoints StringList

	CreatedAt time.Time
	UpdatedAt time.Time
	DeletedAt *time.Time
}

type (
	Nodes  []Node
	NodesP []*Node
)

type NodeAddresses []netip.Addr

func (ma NodeAddresses) ToStringSlice() []string {
	strSlice := make([]string, 0, len(ma))
	for _, addr := range ma {
		strSlice = append(strSlice, addr.String())
	}

	return strSlice
}

func (ma *NodeAddresses) Scan(destination interface{}) error {
	switch value := destination.(type) {
	case string:
		addresses := strings.Split(value, ",")
		*ma = (*ma)[:0]
		for _, addr := range addresses {
			if len(addr) < 1 {
				continue
			}
			parsed, err := netip.ParseAddr(addr)
			if err != nil {
				return err
			}
			*ma = append(*ma, parsed)
		}

		return nil

	default:
		return fmt.Errorf("%w: unexpected data type %T", ErrNodeAddressesInvalid, destination)
	}
}

// Value return json value, implement driver.Valuer interface.
func (ma NodeAddresses) Value() (driver.Value, error) {
	addresses := strings.Join(ma.ToStringSlice(), ",")

	return addresses, nil
}

// isExpired returns whether the node registration has expired.
func (node Node) isExpired() bool {
	// If Expiry is not set, the client has not indicated that
	// it wants an expiry time, it is therefor considered
	// to mean "not expired"
	if node.Expiry == nil || node.Expiry.IsZero() {
		return false
	}

	return time.Now().UTC().After(*node.Expiry)
}

// isOnline returns if the node is connected to Headscale.
// This is really a naive implementation, as we don't really see
// if there is a working connection between the client and the server.
func (node *Node) isOnline() bool {
	if node.LastSeen == nil {
		return false
	}

	if node.isExpired() {
		return false
	}

	return node.LastSeen.After(time.Now().Add(-keepAliveInterval))
}

// isEphemeral returns if the node is registered as an Ephemeral node.
// https://tailscale.com/kb/1111/ephemeral-nodes/
func (node *Node) isEphemeral() bool {
	return node.AuthKey != nil && node.AuthKey.Ephemeral
}

// filterNodesByACL wrapper function to not have devs pass around locks and maps
// related to the application outside of tests.
func (h *Headscale) filterNodesByACL(currentNode *Node, peers Nodes) Nodes {
	return filterNodesByACL(currentNode, peers, &h.aclPeerCacheMapRW, h.aclPeerCacheMap)
}

// filterNodesByACL returns the list of peers authorized to be accessed from a given node.
func filterNodesByACL(
	node *Node,
	nodes Nodes,
	lock *sync.RWMutex,
	aclPeerCacheMap map[string][]string,
) Nodes {
	log.Trace().
		Caller().
		Str("self", node.Hostname).
		Str("input", nodes.String()).
		Msg("Finding peers filtered by ACLs")

	peers := make(map[uint64]Node)
	// Aclfilter peers here. We are itering through nodes in all users and search through the computed aclRules
	// for match between rule SrcIPs and DstPorts. If the rule is a match we allow the node to be viewable.
	nodeIPs := node.IPAddresses.ToStringSlice()

	// TODO(kradalby): Remove this lock, I suspect its not a good idea, and might not be necessary,
	// we only set this at startup atm (reading ACLs) and it might become a bottleneck.
	lock.RLock()

	for _, peer := range nodes {
		if peer.ID == node.ID {
			continue
		}
		peerIPs := peer.IPAddresses.ToStringSlice()

		if dstMap, ok := aclPeerCacheMap["*"]; ok {
			// match source and all destination

			for _, dst := range dstMap {
				if dst == "*" {
					peers[peer.ID] = peer

					continue
				}
			}

			// match source and all destination
			for _, peerIP := range peerIPs {
				for _, dst := range dstMap {
					_, cdr, _ := net.ParseCIDR(dst)
					ip := net.ParseIP(peerIP)
					if dst == peerIP || (cdr != nil && ip != nil && cdr.Contains(ip)) {
						peers[peer.ID] = peer

						continue
					}
				}
			}

			// match all sources and source
			for _, nodeIP := range nodeIPs {
				for _, dst := range dstMap {
					_, cdr, _ := net.ParseCIDR(dst)
					ip := net.ParseIP(nodeIP)
					if dst == nodeIP || (cdr != nil && ip != nil && cdr.Contains(ip)) {
						peers[peer.ID] = peer

						continue
					}
				}
			}
		}

		for _, nodeIP := range nodeIPs {
			if dstMap, ok := aclPeerCacheMap[nodeIP]; ok {
				// match source and all destination
				for _, dst := range dstMap {
					if dst == "*" {
						peers[peer.ID] = peer

						continue
					}
				}

				// match source and destination
				for _, peerIP := range peerIPs {
					for _, dst := range dstMap {
						_, cdr, _ := net.ParseCIDR(dst)
						ip := net.ParseIP(peerIP)
						if dst == peerIP || (cdr != nil && ip != nil && cdr.Contains(ip)) {
							peers[peer.ID] = peer

							continue
						}
					}
				}
			}
		}

		for _, peerIP := range peerIPs {
			if dstMap, ok := aclPeerCacheMap[peerIP]; ok {
				// match source and all destination
				for _, dst := range dstMap {
					if dst == "*" {
						peers[peer.ID] = peer

						continue
					}
				}

				// match return path
				for _, nodeIP := range nodeIPs {
					for _, dst := range dstMap {
						_, cdr, _ := net.ParseCIDR(dst)
						ip := net.ParseIP(nodeIP)
						if dst == nodeIP || (cdr != nil && ip != nil && cdr.Contains(ip)) {
							peers[peer.ID] = peer

							continue
						}
					}
				}
			}
		}
	}

	lock.RUnlock()

	authorizedPeers := make(Nodes, 0, len(peers))
	for _, m := range peers {
		authorizedPeers = append(authorizedPeers, m)
	}
	sort.Slice(
		authorizedPeers,
		func(i, j int) bool { return authorizedPeers[i].ID < authorizedPeers[j].ID },
	)

	log.Trace().
		Caller().
		Str("self", node.Hostname).
		Str("peers", authorizedPeers.String()).
		Msg("Authorized peers")

	return authorizedPeers
}

func (h *Headscale) ListPeers(node *Node) (Nodes, error) {
	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msg("Finding direct peers")

	nodes := Nodes{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where("node_key <> ?",
		node.NodeKey).Find(&nodes).Error; err != nil {
		log.Error().Err(err).Msg("Error accessing db")

		return Nodes{}, err
	}

	sort.Slice(nodes, func(i, j int) bool { return nodes[i].ID < nodes[j].ID })

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Msgf("Found peers: %s", nodes.String())

	return nodes, nil
}

func (h *Headscale) getPeers(node *Node) (Nodes, error) {
	var peers Nodes
	var err error

	// If ACLs rules are defined, filter visible host list with the ACLs
	// else use the classic user scope
	if h.aclPolicy != nil {
		var nodes []Node
		nodes, err = h.ListNodes()
		if err != nil {
			log.Error().Err(err).Msg("Error retrieving list of nodes")

			return Nodes{}, err
		}
		peers = h.filterNodesByACL(node, nodes)
	} else {
		peers, err = h.ListPeers(node)
		if err != nil {
			log.Error().
				Caller().
				Err(err).
				Msg("Cannot fetch peers")

			return Nodes{}, err
		}
	}

	sort.Slice(peers, func(i, j int) bool { return peers[i].ID < peers[j].ID })

	log.Trace().
		Caller().
		Str("self", node.Hostname).
		Str("peers", peers.String()).
		Msg("Peers returned to caller")

	return peers, nil
}

func (h *Headscale) getValidPeers(node *Node) (Nodes, error) {
	validPeers := make(Nodes, 0)

	peers, err := h.getPeers(node)
	if err != nil {
		return Nodes{}, err
	}

	for _, peer := range peers {
		if !peer.isExpired() {
			validPeers = append(validPeers, peer)
		}
	}

	return validPeers, nil
}

func (h *Headscale) ListNodes() ([]Node, error) {
	nodes := []Node{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

func (h *Headscale) ListNodesByGivenName(givenName string) ([]Node, error) {
	nodes := []Node{}
	if err := h.db.Preload("AuthKey").Preload("AuthKey.User").Preload("User").Where("given_name = ?", givenName).Find(&nodes).Error; err != nil {
		return nil, err
	}

	return nodes, nil
}

// GetNode finds a Node by name and user and returns the Node struct.
func (h *Headscale) GetNode(user string, name string) (*Node, error) {
	nodes, err := h.ListNodesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, m := range nodes {
		if m.Hostname == name {
			return &m, nil
		}
	}

	return nil, ErrNodeNotFound
}

// GetNodeByGivenName finds a Node by given name and user and returns the Node struct.
func (h *Headscale) GetNodeByGivenName(user string, givenName string) (*Node, error) {
	nodes, err := h.ListNodesByUser(user)
	if err != nil {
		return nil, err
	}

	for _, node := range nodes {
		if node.GivenName == givenName {
			return &node, nil
		}
	}

	return nil, ErrNodeNotFound
}

// GetNodeByID finds a Node by ID and returns the Node struct.
func (h *Headscale) GetNodeByID(id uint64) (*Node, error) {
	m := Node{}
	if result := h.db.Preload("AuthKey").Preload("User").Find(&Node{ID: id}).First(&m); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetNodeByNodeKey finds a Node by its NodeKey and returns the Node struct.
func (h *Headscale) GetNodeByMachineKey(
	machineKey key.MachinePublic,
) (*Node, error) {
	m := Node{}
	if result := h.db.Preload("AuthKey").Preload("User").First(&m, "machine_key = ?", MachinePublicKeyStripPrefix(machineKey)); result.Error != nil {
		return nil, result.Error
	}

	return &m, nil
}

// GetNodeByNodeKey finds a Node by its current NodeKey.
func (h *Headscale) GetNodeByNodeKey(
	nodeKey key.NodePublic,
) (*Node, error) {
	node := Node{}
	if result := h.db.Preload("AuthKey").Preload("User").First(&node, "node_key = ?",
		NodePublicKeyStripPrefix(nodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &node, nil
}

// GetNodeByAnyKey finds a Node by its MachineKey, its current NodeKey, or the old one, and returns the Node struct.
func (h *Headscale) GetNodeByAnyKey(
	machineKey key.MachinePublic, nodeKey key.NodePublic, oldNodeKey key.NodePublic,
) (*Node, error) {
	node := Node{}
	if result := h.db.Preload("AuthKey").Preload("User").First(&node, "machine_key = ? OR node_key = ? OR node_key = ?",
		MachinePublicKeyStripPrefix(machineKey),
		NodePublicKeyStripPrefix(nodeKey),
		NodePublicKeyStripPrefix(oldNodeKey)); result.Error != nil {
		return nil, result.Error
	}

	return &node, nil
}

// UpdateNodeFromDatabase takes a Node struct pointer (typically already loaded from database
// and updates it with the latest data from the database.
func (h *Headscale) UpdateNodeFromDatabase(node *Node) error {
	if result := h.db.Find(node).First(&node); result.Error != nil {
		return result.Error
	}

	return nil
}

// SetTags takes a Node struct pointer and update the forced tags.
func (h *Headscale) SetTags(node *Node, tags []string) error {
	newTags := []string{}
	for _, tag := range tags {
		if !contains(newTags, tag) {
			newTags = append(newTags, tag)
		}
	}
	node.ForcedTags = newTags
	if err := h.UpdateACLRules(); err != nil && !errors.Is(err, errEmptyPolicy) {
		return err
	}
	h.setLastStateChangeToNow()

	if err := h.db.Save(node).Error; err != nil {
		return fmt.Errorf("failed to update tags for node in the database: %w", err)
	}

	return nil
}

// ExpireNode takes a Node struct and sets the expire field to now.
func (h *Headscale) ExpireNode(node *Node) error {
	now := time.Now()
	node.Expiry = &now

	h.setLastStateChangeToNow()

	if err := h.db.Save(node).Error; err != nil {
		return fmt.Errorf("failed to expire node in the database: %w", err)
	}

	return nil
}

// RenameNode takes a Node struct and a new GivenName for the nodes
// and renames it.
func (h *Headscale) RenameNode(node *Node, newName string) error {
	err := CheckForFQDNRules(
		newName,
	)
	if err != nil {
		log.Error().
			Caller().
			Str("func", "RenameNode").
			Str("node", node.Hostname).
			Str("newName", newName).
			Err(err)

		return err
	}
	node.GivenName = newName

	h.setLastStateChangeToNow()

	if err := h.db.Save(node).Error; err != nil {
		return fmt.Errorf("failed to rename node in the database: %w", err)
	}

	return nil
}

// RefreshNode takes a Node struct and sets the expire field to now.
func (h *Headscale) RefreshNode(node *Node, expiry time.Time) error {
	now := time.Now()

	node.LastSuccessfulUpdate = &now
	node.Expiry = &expiry

	h.setLastStateChangeToNow()

	if err := h.db.Save(node).Error; err != nil {
		return fmt.Errorf(
			"failed to refresh node (update expiration) in the database: %w",
			err,
		)
	}

	return nil
}

// DeleteNode softs deletes a Node from the database.
func (h *Headscale) DeleteNode(node *Node) error {
	err := h.DeleteNodeRoutes(node)
	if err != nil {
		return err
	}

	if err := h.db.Delete(&node).Error; err != nil {
		return err
	}

	return nil
}

func (h *Headscale) TouchNode(node *Node) error {
	return h.db.Updates(Node{
		ID:                   node.ID,
		LastSeen:             node.LastSeen,
		LastSuccessfulUpdate: node.LastSuccessfulUpdate,
	}).Error
}

// HardDeleteNode hard deletes a Node from the database.
func (h *Headscale) HardDeleteNode(node *Node) error {
	err := h.DeleteNodeRoutes(node)
	if err != nil {
		return err
	}

	if err := h.db.Unscoped().Delete(&node).Error; err != nil {
		return err
	}

	return nil
}

// GetHostInfo returns a Hostinfo struct for the node.
func (node *Node) GetHostInfo() tailcfg.Hostinfo {
	return tailcfg.Hostinfo(node.HostInfo)
}

func (h *Headscale) isOutdated(node *Node) bool {
	if err := h.UpdateNodeFromDatabase(node); err != nil {
		// It does not seem meaningful to propagate this error as the end result
		// will have to be that the node has to be considered outdated.
		return true
	}

	// Get the last update from all headscale users to compare with our nodes
	// last update.
	// TODO(kradalby): Only request updates from users where we can talk to nodes
	// This would mostly be for a bit of performance, and can be calculated based on
	// ACLs.
	lastChange := h.getLastStateChange()
	lastUpdate := node.CreatedAt
	if node.LastSuccessfulUpdate != nil {
		lastUpdate = *node.LastSuccessfulUpdate
	}
	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Time("last_successful_update", lastChange).
		Time("last_state_change", lastUpdate).
		Msgf("Checking if %s is missing updates", node.Hostname)

	return lastUpdate.Before(lastChange)
}

func (node Node) String() string {
	return node.Hostname
}

func (nodes Nodes) String() string {
	temp := make([]string, len(nodes))

	for index, node := range nodes {
		temp[index] = node.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

// TODO(kradalby): Remove when we have generics...
func (nodes NodesP) String() string {
	temp := make([]string, len(nodes))

	for index, node := range nodes {
		temp[index] = node.Hostname
	}

	return fmt.Sprintf("[ %s ](%d)", strings.Join(temp, ", "), len(temp))
}

func (h *Headscale) toNodes(
	nodes Nodes,
	baseDomain string,
	dnsConfig *tailcfg.DNSConfig,
) ([]*tailcfg.Node, error) {
	tailNodes := make([]*tailcfg.Node, len(nodes))

	for index, node := range nodes {
		tailNode, err := h.toNode(node, baseDomain, dnsConfig)
		if err != nil {
			return nil, err
		}

		tailNodes[index] = tailNode
	}

	return tailNodes, nil
}

// toNode converts a Node into a Tailscale Node. includeRoutes is false for shared nodes
// as per the expected behaviour in the official SaaS.
func (h *Headscale) toNode(
	node Node,
	baseDomain string,
	dnsConfig *tailcfg.DNSConfig,
) (*tailcfg.Node, error) {
	var nodeKey key.NodePublic
	err := nodeKey.UnmarshalText([]byte(NodePublicKeyEnsurePrefix(node.NodeKey)))
	if err != nil {
		log.Trace().
			Caller().
			Str("node_key", node.NodeKey).
			Msgf("Failed to parse node public key from hex")

		return nil, fmt.Errorf("failed to parse node public key: %w", err)
	}

	var machineKey key.MachinePublic
	// MachineKey is only used in the legacy protocol
	if node.MachineKey != "" {
		err = machineKey.UnmarshalText(
			[]byte(MachinePublicKeyEnsurePrefix(node.MachineKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse node public key: %w", err)
		}
	}

	var discoKey key.DiscoPublic
	if node.DiscoKey != "" {
		err := discoKey.UnmarshalText(
			[]byte(DiscoPublicKeyEnsurePrefix(node.DiscoKey)),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to parse disco public key: %w", err)
		}
	} else {
		discoKey = key.DiscoPublic{}
	}

	addrs := []netip.Prefix{}
	for _, nodeAddress := range node.IPAddresses {
		ip := netip.PrefixFrom(nodeAddress, nodeAddress.BitLen())
		addrs = append(addrs, ip)
	}

	allowedIPs := append(
		[]netip.Prefix{},
		addrs...) // we append the node own IP, as it is required by the clients

	primaryRoutes, err := h.getNodePrimaryRoutes(&node)
	if err != nil {
		return nil, err
	}
	primaryPrefixes := Routes(primaryRoutes).toPrefixes()

	nodeRoutes, err := h.GetNodeRoutes(&node)
	if err != nil {
		return nil, err
	}
	for _, route := range nodeRoutes {
		if route.Enabled && (route.IsPrimary || route.isExitRoute()) {
			allowedIPs = append(allowedIPs, netip.Prefix(route.Prefix))
		}
	}

	var derp string
	if node.HostInfo.NetInfo != nil {
		derp = fmt.Sprintf("127.3.3.40:%d", node.HostInfo.NetInfo.PreferredDERP)
	} else {
		derp = "127.3.3.40:0" // Zero means disconnected or unknown.
	}

	var keyExpiry time.Time
	if node.Expiry != nil {
		keyExpiry = *node.Expiry
	} else {
		keyExpiry = time.Time{}
	}

	var hostname string
	if dnsConfig != nil && dnsConfig.Proxied { // MagicDNS
		hostname = fmt.Sprintf(
			"%s.%s.%s",
			node.GivenName,
			node.User.Name,
			baseDomain,
		)
		if len(hostname) > maxHostnameLength {
			return nil, fmt.Errorf(
				"hostname %q is too long it cannot except 255 ASCII chars: %w",
				hostname,
				ErrHostnameTooLong,
			)
		}
	} else {
		hostname = node.GivenName
	}

	hostInfo := node.GetHostInfo()

	online := node.isOnline()

	tags, _ := getTags(h.aclPolicy, node, h.cfg.OIDC.StripEmaildomain)
	tags = lo.Uniq(append(tags, node.ForcedTags...))

	tailNode := tailcfg.Node{
		ID: tailcfg.NodeID(node.ID), // this is the actual ID
		StableID: tailcfg.StableNodeID(
			strconv.FormatUint(node.ID, Base10),
		), // in headscale, unlike tailcontrol server, IDs are permanent
		Name: hostname,

		User: tailcfg.UserID(node.UserID),

		Key:       nodeKey,
		KeyExpiry: keyExpiry,

		Machine:    machineKey,
		DiscoKey:   discoKey,
		Addresses:  addrs,
		AllowedIPs: allowedIPs,
		Endpoints:  node.Endpoints,
		DERP:       derp,
		Hostinfo:   hostInfo.View(),
		Created:    node.CreatedAt,

		Tags: tags,

		PrimaryRoutes: primaryPrefixes,

		LastSeen:          node.LastSeen,
		Online:            &online,
		KeepAlive:         true,
		MachineAuthorized: !node.isExpired(),

		Capabilities: []string{
			tailcfg.CapabilityFileSharing,
			tailcfg.CapabilityAdmin,
			tailcfg.CapabilitySSH,
		},
	}

	return &tailNode, nil
}

func (node *Node) toProto() *v1.Node {
	nodeProto := &v1.Node{
		Id:         node.ID,
		MachineKey: node.MachineKey,

		NodeKey:     node.NodeKey,
		DiscoKey:    node.DiscoKey,
		IpAddresses: node.IPAddresses.ToStringSlice(),
		Name:        node.Hostname,
		GivenName:   node.GivenName,
		User:        node.User.toProto(),
		ForcedTags:  node.ForcedTags,
		Online:      node.isOnline(),

		// TODO(kradalby): Implement register method enum converter
		// RegisterMethod: ,

		CreatedAt: timestamppb.New(node.CreatedAt),
	}

	if node.AuthKey != nil {
		nodeProto.PreAuthKey = node.AuthKey.toProto()
	}

	if node.LastSeen != nil {
		nodeProto.LastSeen = timestamppb.New(*node.LastSeen)
	}

	if node.LastSuccessfulUpdate != nil {
		nodeProto.LastSuccessfulUpdate = timestamppb.New(
			*node.LastSuccessfulUpdate,
		)
	}

	if node.Expiry != nil {
		nodeProto.Expiry = timestamppb.New(*node.Expiry)
	}

	return nodeProto
}

// getTags will return the tags of the current node.
// Invalid tags are tags added by a user on a node, and that user doesn't have authority to add this tag.
// Valid tags are tags added by a user that is allowed in the ACL policy to add this tag.
func getTags(
	aclPolicy *ACLPolicy,
	node Node,
	stripEmailDomain bool,
) ([]string, []string) {
	validTags := make([]string, 0)
	invalidTags := make([]string, 0)
	if aclPolicy == nil {
		return validTags, invalidTags
	}
	validTagMap := make(map[string]bool)
	invalidTagMap := make(map[string]bool)
	for _, tag := range node.HostInfo.RequestTags {
		owners, err := expandTagOwners(*aclPolicy, tag, stripEmailDomain)
		if errors.Is(err, errInvalidTag) {
			invalidTagMap[tag] = true

			continue
		}
		var found bool
		for _, owner := range owners {
			if node.User.Name == owner {
				found = true
			}
		}
		if found {
			validTagMap[tag] = true
		} else {
			invalidTagMap[tag] = true
		}
	}
	for tag := range invalidTagMap {
		invalidTags = append(invalidTags, tag)
	}
	for tag := range validTagMap {
		validTags = append(validTags, tag)
	}

	return validTags, invalidTags
}

func (h *Headscale) RegisterNodeFromAuthCallback(
	nodeKeyStr string,
	userName string,
	nodeExpiry *time.Time,
	registrationMethod string,
) (*Node, error) {
	nodeKey := key.NodePublic{}
	err := nodeKey.UnmarshalText([]byte(nodeKeyStr))
	if err != nil {
		return nil, err
	}

	log.Debug().
		Str("nodeKey", nodeKey.ShortString()).
		Str("userName", userName).
		Str("registrationMethod", registrationMethod).
		Str("expiresAt", fmt.Sprintf("%v", nodeExpiry)).
		Msg("Registering node from API/CLI or auth callback")

	if nodeInterface, ok := h.registrationCache.Get(NodePublicKeyStripPrefix(nodeKey)); ok {
		if registrationNode, ok := nodeInterface.(Node); ok {
			user, err := h.GetUser(userName)
			if err != nil {
				return nil, fmt.Errorf(
					"failed to find user in register node from auth callback, %w",
					err,
				)
			}

			// Registration of expired node with different user
			if registrationNode.ID != 0 &&
				registrationNode.UserID != user.ID {
				return nil, ErrDifferentRegisteredUser
			}

			registrationNode.UserID = user.ID
			registrationNode.RegisterMethod = registrationMethod

			if nodeExpiry != nil {
				registrationNode.Expiry = nodeExpiry
			}

			node, err := h.RegisterNode(
				registrationNode,
			)

			if err == nil {
				h.registrationCache.Delete(nodeKeyStr)
			}

			return node, err
		} else {
			return nil, ErrCouldNotConvertNodeInterface
		}
	}

	return nil, ErrNodeNotFoundRegistrationCache
}

// RegisterNode is executed from the CLI to register a new Node using its MachineKey.
func (h *Headscale) RegisterNode(node Node,
) (*Node, error) {
	log.Debug().
		Str("node", node.Hostname).
		Str("machine_key", node.MachineKey).
		Str("node_key", node.NodeKey).
		Str("user", node.User.Name).
		Msg("Registering node")

	// If the node exists and we had already IPs for it, we just save it
	// so we store the node.Expire and node.Nodekey that has been set when
	// adding it to the registrationCache
	if len(node.IPAddresses) > 0 {
		if err := h.db.Save(&node).Error; err != nil {
			return nil, fmt.Errorf("failed register existing node in the database: %w", err)
		}

		log.Trace().
			Caller().
			Str("node", node.Hostname).
			Str("machine_key", node.MachineKey).
			Str("node_key", node.NodeKey).
			Str("user", node.User.Name).
			Msg("Node authorized again")

		return &node, nil
	}

	h.ipAllocationMutex.Lock()
	defer h.ipAllocationMutex.Unlock()

	ips, err := h.getAvailableIPs()
	if err != nil {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not find IP for the new node")

		return nil, err
	}

	node.IPAddresses = ips

	if err := h.db.Save(&node).Error; err != nil {
		return nil, fmt.Errorf("failed register(save) node in the database: %w", err)
	}

	log.Trace().
		Caller().
		Str("node", node.Hostname).
		Str("ip", strings.Join(ips.ToStringSlice(), ",")).
		Msg("Node registered with the database")

	return &node, nil
}

// GetAdvertisedRoutes returns the routes that are be advertised by the given node.
func (h *Headscale) GetAdvertisedRoutes(node *Node) ([]netip.Prefix, error) {
	routes := []Route{}

	err := h.db.
		Preload("Node").
		Where("node_id = ? AND advertised = ?", node.ID, true).Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get advertised routes for node")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

// GetEnabledRoutes returns the routes that are enabled for the node.
func (h *Headscale) GetEnabledRoutes(node *Node) ([]netip.Prefix, error) {
	routes := []Route{}

	err := h.db.
		Preload("Node").
		Where("node_id = ? AND advertised = ? AND enabled = ?", node.ID, true, true).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get enabled routes for node")

		return nil, err
	}

	prefixes := []netip.Prefix{}
	for _, route := range routes {
		prefixes = append(prefixes, netip.Prefix(route.Prefix))
	}

	return prefixes, nil
}

func (h *Headscale) IsRoutesEnabled(node *Node, routeStr string) bool {
	route, err := netip.ParsePrefix(routeStr)
	if err != nil {
		return false
	}

	enabledRoutes, err := h.GetEnabledRoutes(node)
	if err != nil {
		log.Error().Err(err).Msg("Could not get enabled routes")

		return false
	}

	for _, enabledRoute := range enabledRoutes {
		if route == enabledRoute {
			return true
		}
	}

	return false
}

// enableRoutes enables new routes based on a list of new routes.
func (h *Headscale) enableRoutes(node *Node, routeStrs ...string) error {
	newRoutes := make([]netip.Prefix, len(routeStrs))
	for index, routeStr := range routeStrs {
		route, err := netip.ParsePrefix(routeStr)
		if err != nil {
			return err
		}

		newRoutes[index] = route
	}

	advertisedRoutes, err := h.GetAdvertisedRoutes(node)
	if err != nil {
		return err
	}

	for _, newRoute := range newRoutes {
		if !contains(advertisedRoutes, newRoute) {
			return fmt.Errorf(
				"route (%s) is not available on node %s: %w",
				node.Hostname,
				newRoute, ErrNodeRouteIsNotAvailable,
			)
		}
	}

	// Separate loop so we don't leave things in a half-updated state
	for _, prefix := range newRoutes {
		route := Route{}
		err := h.db.Preload("Node").
			Where("node_id = ? AND prefix = ?", node.ID, IPPrefix(prefix)).
			First(&route).Error
		if err == nil {
			route.Enabled = true

			// Mark already as primary if there is only this node offering this subnet
			// (and is not an exit route)
			if !route.isExitRoute() {
				route.IsPrimary = h.isUniquePrefix(route)
			}

			err = h.db.Save(&route).Error
			if err != nil {
				return fmt.Errorf("failed to enable route: %w", err)
			}
		} else {
			return fmt.Errorf("failed to find route: %w", err)
		}
	}

	h.setLastStateChangeToNow()

	return nil
}

// EnableAutoApprovedRoutes enables any routes advertised by a node that match the ACL autoApprovers policy.
func (h *Headscale) EnableAutoApprovedRoutes(node *Node) error {
	if len(node.IPAddresses) == 0 {
		return nil // This node has no IPAddresses, so can't possibly match any autoApprovers ACLs
	}

	routes := []Route{}
	err := h.db.
		Preload("Node").
		Where("node_id = ? AND advertised = true AND enabled = false", node.ID).
		Find(&routes).Error
	if err != nil && !errors.Is(err, gorm.ErrRecordNotFound) {
		log.Error().
			Caller().
			Err(err).
			Str("node", node.Hostname).
			Msg("Could not get advertised routes for node")

		return err
	}

	approvedRoutes := []Route{}

	for _, advertisedRoute := range routes {
		routeApprovers, err := h.aclPolicy.AutoApprovers.GetRouteApprovers(
			netip.Prefix(advertisedRoute.Prefix),
		)
		if err != nil {
			log.Err(err).
				Str("advertisedRoute", advertisedRoute.String()).
				Uint64("nodeId", node.ID).
				Msg("Failed to resolve autoApprovers for advertised route")

			return err
		}

		for _, approvedAlias := range routeApprovers {
			if approvedAlias == node.User.Name {
				approvedRoutes = append(approvedRoutes, advertisedRoute)
			} else {
				approvedIps, err := expandAlias([]Node{*node}, *h.aclPolicy, approvedAlias, h.cfg.OIDC.StripEmaildomain)
				if err != nil {
					log.Err(err).
						Str("alias", approvedAlias).
						Msg("Failed to expand alias when processing autoApprovers policy")

					return err
				}

				// approvedIPs should contain all of node's IPs if it matches the rule, so check for first
				if contains(approvedIps, node.IPAddresses[0].String()) {
					approvedRoutes = append(approvedRoutes, advertisedRoute)
				}
			}
		}
	}

	for i, approvedRoute := range approvedRoutes {
		approvedRoutes[i].Enabled = true
		err = h.db.Save(&approvedRoutes[i]).Error
		if err != nil {
			log.Err(err).
				Str("approvedRoute", approvedRoute.String()).
				Uint64("nodeId", node.ID).
				Msg("Failed to enable approved route")

			return err
		}
	}

	return nil
}

func (h *Headscale) generateGivenName(suppliedName string, randomSuffix bool) (string, error) {
	normalizedHostname, err := NormalizeToFQDNRules(
		suppliedName,
		h.cfg.OIDC.StripEmaildomain,
	)
	if err != nil {
		return "", err
	}

	if randomSuffix {
		// Trim if a hostname will be longer than 63 chars after adding the hash.
		trimmedHostnameLength := labelHostnameLength - NodeGivenNameHashLength - NodeGivenNameTrimSize
		if len(normalizedHostname) > trimmedHostnameLength {
			normalizedHostname = normalizedHostname[:trimmedHostnameLength]
		}

		suffix, err := GenerateRandomStringDNSSafe(NodeGivenNameHashLength)
		if err != nil {
			return "", err
		}

		normalizedHostname += "-" + suffix
	}

	return normalizedHostname, nil
}

func (h *Headscale) GenerateGivenName(machineKey string, suppliedName string) (string, error) {
	givenName, err := h.generateGivenName(suppliedName, false)
	if err != nil {
		return "", err
	}

	// Tailscale rules (may differ) https://tailscale.com/kb/1098/machine-names/
	nodes, err := h.ListNodesByGivenName(givenName)
	if err != nil {
		return "", err
	}

	for _, node := range nodes {
		if node.MachineKey != machineKey && node.GivenName == givenName {
			postfixedName, err := h.generateGivenName(suppliedName, true)
			if err != nil {
				return "", err
			}

			givenName = postfixedName
		}
	}

	return givenName, nil
}

func (nodes Nodes) FilterByIP(ip netip.Addr) Nodes {
	found := make(Nodes, 0)

	for _, node := range nodes {
		for _, mIP := range node.IPAddresses {
			if ip == mIP {
				found = append(found, node)
			}
		}
	}

	return found
}
